//! Handler for `opke encrypt` subcommand.

use base64::prelude::*;
use rand::{rngs::OsRng, RngCore};
use std::io::{self, IsTerminal, Read, Write};
use std::time::Instant;
use zeroize::Zeroizing;

use crate::core::{
    derive_key_and_split, encrypt_cascade, get_profile, validate_kdf_params, MAX_SECRET_BYTES,
    NONCE_LEN, SALT_LEN,
};
use crate::envelope::create_envelope;
use crate::error::OpkeError;
use crate::qr::{generate_qr_image_with_options, print_terminal_qr_stderr};
use crate::security::{
    get_available_memory_kib, prompt_passphrase, prompt_secret, read_secure_file,
    scrub_env_passphrase, write_secure_file_with_options, MemoryLockGuard,
};

use super::args::EncryptArgs;
use super::reject_sensitive_arg;

pub fn execute(mut args: EncryptArgs) -> Result<(), OpkeError> {
    // 0. Prohibit passing plaintext secrets or passphrases via CLI args
    reject_sensitive_arg(
        &mut args.secret,
        "secrets",
        "Please use interactive prompt, stdin pipe, or provide a file via '-i / --input-file'.",
    )?;
    reject_sensitive_arg(
        &mut args.passphrase,
        "passphrases",
        "Please use interactive prompt or set the 'OPKE_PASSPHRASE' environment variable.",
    )?;

    if args.v2 {
        eprintln!("[!] 警告: '--v2' は非推奨の旧バージョン互換フラグです。本番環境での使用は推奨されません。");
    }

    // 1. Resolve and validate KDF parameters
    let profile = match get_profile(&args.profile) {
        Some(p) => p,
        None => {
            // Sanitize profile argument to prevent ANSI and Unicode Bidi injection
            let sanitized: String = args
                .profile
                .chars()
                .filter(|c| {
                    !c.is_control()
                        && !matches!(
                            c,
                            '\u{200E}'
                                | '\u{200F}'
                                | '\u{061C}'
                                | '\u{202A}'..='\u{202E}'
                                | '\u{2066}'..='\u{2069}'
                        )
                })
                .collect();
            return Err(OpkeError::Validation(format!(
                "Unknown profile: '{}'. Choose from 'production' (or 'standard'), 'moderate', or 'fast'.",
                sanitized
            )));
        }
    };

    let m_kib = args.mem.unwrap_or(profile.m_kib);
    let t = args.time.unwrap_or(profile.t);
    let p = args.threads.unwrap_or(profile.p);

    validate_kdf_params(m_kib, t, p)?;

    // Check system RAM availability to prevent OOM freezes (with 10% safety margin)
    if let Some(avail_kib) = get_available_memory_kib() {
        let required_kib = (m_kib as u64).saturating_add((m_kib as u64) / 10);
        if required_kib > avail_kib && !args.force {
            return Err(OpkeError::ResourceLimit(format!(
                "Selected parameters require ~{} KiB ({:.2} GiB) RAM (including runtime overhead), but only ~{} KiB ({:.2} GiB) is available.\nEncryption aborted to prevent system freeze / OOM. Use '--profile moderate' or '--force' to override.",
                required_kib, (required_kib as f64) / 1024.0 / 1024.0,
                avail_kib, (avail_kib as f64) / 1024.0 / 1024.0
            )));
        }
    }

    // 2. Resolve secret plaintext
    let secret_bytes: Zeroizing<Vec<u8>> = if let Some(path) = args.input_file {
        read_secure_file(path, MAX_SECRET_BYTES)?
    } else if !io::stdin().is_terminal() {
        let mut take = io::stdin().take((MAX_SECRET_BYTES + 1) as u64);
        // Collect boxed 8KB chunks so vector reallocation moves pointers only,
        // eliminating shallow copy leaks of unzeroized plaintext in previous heap chunks.
        let mut chunks: Vec<Box<Zeroizing<[u8; 8192]>>> = Vec::new();
        let mut total_len = 0usize;
        loop {
            let mut chunk = Box::new(Zeroizing::new([0u8; 8192]));
            let n = take.read(&mut **chunk)?;
            if n == 0 {
                break;
            }
            total_len += n;
            chunks.push(chunk);
            if total_len > MAX_SECRET_BYTES {
                return Err(OpkeError::Validation(format!(
                    "Secret input exceeds maximum allowed size ({} bytes).",
                    MAX_SECRET_BYTES
                )));
            }
        }
        if total_len == 0 {
            return Err(OpkeError::Validation("Secret input is empty.".into()));
        }
        let mut buf = Zeroizing::new(Vec::with_capacity(total_len));
        let mut remaining = total_len;
        for c in chunks {
            let to_copy = remaining.min(8192);
            buf.extend_from_slice(&c[..to_copy]);
            remaining -= to_copy;
        }
        buf
    } else {
        prompt_secret(args.multiline, MAX_SECRET_BYTES)?
    };

    if secret_bytes.is_empty() {
        return Err(OpkeError::Validation("Secret cannot be empty.".into()));
    }

    // Lock plaintext secret into physical RAM to prevent paging to disk during heavy Argon2id
    let _lock_secret = MemoryLockGuard::try_lock(&secret_bytes);

    // 3. Resolve passphrase
    let passphrase: Zeroizing<String> = if let Some(env_pass) = scrub_env_passphrase()? {
        env_pass
    } else {
        prompt_passphrase(true)?
    };

    eprintln!(
        "[*] Deriving keys with Argon2id (m={} KiB ({:.2} GiB), t={}, p={})...",
        m_kib,
        (m_kib as f64) / 1024.0 / 1024.0,
        t,
        p
    );

    let t0 = Instant::now();
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let (key_chacha, key_aes) = derive_key_and_split(passphrase.as_bytes(), &salt, m_kib, t, p)?;

    // Lock derived subkeys at caller stack frame in physical RAM
    let _lock_chacha = MemoryLockGuard::try_lock(&*key_chacha);
    let _lock_aes = MemoryLockGuard::try_lock(&*key_aes);

    // Immediately drop passphrase after key derivation
    drop(passphrase);

    let kdf_elapsed = t0.elapsed();
    eprintln!(
        "[*] Key derivation completed in {:.2}s.",
        kdf_elapsed.as_secs_f64()
    );

    // 4. Perform Cascade AEAD Encryption with Nonce Preparation & AAD Commitment
    let target_version = if args.v2 { 2 } else { 3 };
    let mut nonce_chacha = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_chacha);
    let mut nonce_aes = [0u8; NONCE_LEN];
    loop {
        OsRng.fill_bytes(&mut nonce_aes);
        if nonce_aes != nonce_chacha {
            break;
        }
    }

    let b64_nc = BASE64_STANDARD.encode(nonce_chacha);
    let b64_na = BASE64_STANDARD.encode(nonce_aes);

    let aad = if target_version == 3 {
        Some(
            format!(
                "opke:v=3:kdf=argon2id:m={}:t={}:p={}:c=chacha20-poly1305+aes-256-gcm:nc={}:na={}",
                m_kib, t, p, b64_nc, b64_na
            )
            .into_bytes(),
        )
    } else {
        None
    };

    let (final_ciphertext, tag_aes, n_chacha, n_aes) = encrypt_cascade(
        secret_bytes.as_slice(),
        &key_chacha,
        &key_aes,
        Some(nonce_chacha),
        Some(nonce_aes),
        aad.as_deref(),
    )?;

    // Immediately drop lock guards, subkeys, and secret plaintext after cascade encryption
    drop(_lock_secret);
    drop(secret_bytes);
    drop(_lock_chacha);
    drop(_lock_aes);
    drop(key_chacha);
    drop(key_aes);

    // 5. Build Envelope
    let envelope = create_envelope(
        &salt,
        m_kib,
        t,
        p,
        &n_chacha,
        &n_aes,
        &tag_aes,
        &final_ciphertext,
        Some(target_version),
    )?;

    let paper_output = envelope.to_paper_format()?;
    let raw_b64 = envelope.to_base64_payload()?;

    let allow_overwrite = args.force || args.overwrite;

    // 6. Save or Output Envelope
    if let Some(ref out_path) = args.output {
        if out_path == "-" {
            // Write to stdout using write_all to avoid BrokenPipe panic
            let mut stdout = io::stdout();
            if args.raw {
                stdout
                    .write_all(raw_b64.as_bytes())
                    .map_err(OpkeError::Io)?;
                stdout.write_all(b"\n").map_err(OpkeError::Io)?;
            } else {
                stdout
                    .write_all(paper_output.as_bytes())
                    .map_err(OpkeError::Io)?;
            }
            stdout.flush().map_err(OpkeError::Io)?;
        } else {
            // Prevent silent overwrite without --force or --overwrite
            let p_out = std::path::Path::new(out_path);
            if p_out.exists() && !allow_overwrite {
                if io::stdin().is_terminal() {
                    eprintln!(
                        "[!] 警告: 出力先ファイル '{}' は既に存在します。",
                        p_out.display()
                    );
                    eprint!("上書きしますか？ (y/N): ");
                    let _ = io::stderr().flush();
                    let mut ans = String::new();
                    let _ = io::stdin().read_line(&mut ans);
                    if !ans.trim().eq_ignore_ascii_case("y") {
                        return Err(OpkeError::Validation(
                            "既存ファイルの上書きがキャンセルされました。上書きを強制するには '--force' または '--overwrite' を指定してください。".into(),
                        ));
                    }
                } else {
                    return Err(OpkeError::Validation(format!(
                        "出力先ファイル '{}' は既に存在します。上書きするには '--force' または '--overwrite' を指定してください。",
                        p_out.display()
                    )));
                }
            }

            let content_to_write = if args.raw {
                format!("{}\n", raw_b64)
            } else {
                paper_output.clone()
            };
            write_secure_file_with_options(out_path, content_to_write.as_bytes(), args.force)?;
            eprintln!("[+] Encrypted envelope written to: {}", out_path);
        }
    } else {
        // Write to stdout using write_all to avoid BrokenPipe panic
        let mut stdout = io::stdout();
        if args.raw {
            stdout
                .write_all(raw_b64.as_bytes())
                .map_err(OpkeError::Io)?;
            stdout.write_all(b"\n").map_err(OpkeError::Io)?;
        } else {
            stdout
                .write_all(paper_output.as_bytes())
                .map_err(OpkeError::Io)?;
        }
        stdout.flush().map_err(OpkeError::Io)?;
    }

    // 7. QR Code generation if requested (propagating force)
    if let Some(ref qr_path) = args.qr {
        let p_qr = std::path::Path::new(qr_path);
        if p_qr.exists() && !allow_overwrite {
            if io::stdin().is_terminal() {
                eprintln!(
                    "[!] 警告: QRコード保存先ファイル '{}' は既に存在します。",
                    p_qr.display()
                );
                eprint!("上書きしますか？ (y/N): ");
                let _ = io::stderr().flush();
                let mut ans = String::new();
                let _ = io::stdin().read_line(&mut ans);
                if !ans.trim().eq_ignore_ascii_case("y") {
                    return Err(OpkeError::Validation(
                        "既存QRコードファイルの上書きがキャンセルされました。上書きを強制するには '--force' または '--overwrite' を指定してください。".into(),
                    ));
                }
            } else {
                return Err(OpkeError::Validation(format!(
                    "QRコード保存先ファイル '{}' は既に存在します。上書きするには '--force' または '--overwrite' を指定してください。",
                    p_qr.display()
                )));
            }
        }
        generate_qr_image_with_options(&raw_b64, qr_path, args.force)?;
        eprintln!("[+] QR Code image saved to: {}", qr_path);
    }

    if args.qr_term {
        eprintln!("\n[*] Scan QR code directly from terminal:");
        print_terminal_qr_stderr(&raw_b64)?;
    }

    Ok(())
}
