//! Handler for `opke encrypt` subcommand.

use std::io::{self, IsTerminal, Read, Write};
use std::time::Instant;
use base64::prelude::*;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::core::{
    derive_key_and_split, encrypt_cascade, get_profile, MAX_SECRET_BYTES,
    MIN_M_KIB, MIN_P, MIN_T, MAX_M_KIB, MAX_P, MAX_T, NONCE_LEN, SALT_LEN,
};
use crate::envelope::create_envelope;
use crate::error::OpkeError;
use crate::qr::{generate_qr_image_with_options, print_terminal_qr_stderr};
use crate::security::{
    get_available_memory_kib, prompt_passphrase, prompt_secret, read_secure_file,
    scrub_cmdline_targets, scrub_env_passphrase, write_secure_file_with_options,
};

use super::args::EncryptArgs;

pub fn execute(args: EncryptArgs) -> Result<(), OpkeError> {
    // 0. Prohibit passing plaintext secrets or passphrases via CLI args (VULN-13)
    if let Some(ref sec) = args.secret {
        scrub_cmdline_targets(&[sec]);
        return Err(OpkeError::Validation(
            "Passing secrets as command-line arguments is strictly prohibited for security.\nPlease use interactive prompt, stdin pipe, or provide a file via '-i / --input-file'.".into(),
        ));
    }
    if let Some(ref pass) = args.passphrase {
        scrub_cmdline_targets(&[pass]);
        return Err(OpkeError::Validation(
            "Passing passphrases as command-line arguments is strictly prohibited for security.\nPlease use interactive prompt or set the 'OPKE_PASSPHRASE' environment variable.".into(),
        ));
    }

    // 1. Resolve and validate KDF parameters
    let profile = match get_profile(&args.profile) {
        Some(p) => p,
        None => {
            return Err(OpkeError::Validation(format!(
                "Unknown profile: '{}'. Choose from 'production', 'moderate', or 'fast'.",
                args.profile
            )));
        }
    };

    let m_kib = args.mem.unwrap_or(profile.m_kib);
    let t = args.time.unwrap_or(profile.t);
    let p = args.threads.unwrap_or(profile.p);

    if !(MIN_M_KIB..=MAX_M_KIB).contains(&m_kib) {
        return Err(OpkeError::Validation(format!(
            "Invalid memory cost: {} KiB (range: {}-{})",
            m_kib, MIN_M_KIB, MAX_M_KIB
        )));
    }
    if !(MIN_P..=MAX_P).contains(&p) {
        return Err(OpkeError::Validation(format!(
            "Invalid parallelism: {} (range: {}-{})",
            p, MIN_P, MAX_P
        )));
    }
    if !(MIN_T..=MAX_T).contains(&t) {
        return Err(OpkeError::Validation(format!(
            "Invalid time cost: {} (range: {}-{})",
            t, MIN_T, MAX_T
        )));
    }
    if m_kib < 8 * p {
        return Err(OpkeError::Validation(format!(
            "Invalid memory cost: {} KiB (Argon2 requires m >= 8 * p = {} KiB)",
            m_kib,
            8 * p
        )));
    }

    // Check system RAM availability to prevent OOM freezes
    if let Some(avail_kib) = get_available_memory_kib() {
        if (m_kib as u64) > avail_kib && !args.force {
            return Err(OpkeError::ResourceLimit(format!(
                "Selected parameters require {} KiB ({:.2} GiB) RAM, but only ~{} KiB ({:.2} GiB) is available.\nEncryption aborted to prevent system freeze / OOM. Use '--profile moderate' or '--force' to override.",
                m_kib, (m_kib as f64) / 1024.0 / 1024.0,
                avail_kib, (avail_kib as f64) / 1024.0 / 1024.0
            )));
        }
    }

    // 2. Resolve secret plaintext
    let secret_bytes: Zeroizing<Vec<u8>> = if let Some(path) = args.input_file {
        read_secure_file(path, MAX_SECRET_BYTES)?
    } else if !io::stdin().is_terminal() {
        let mut take = io::stdin().take((MAX_SECRET_BYTES + 1) as u64);
        let mut buf = Zeroizing::new(Vec::with_capacity(65536));
        take.read_to_end(&mut buf)?;
        if buf.is_empty() {
            return Err(OpkeError::Validation("Secret input is empty.".into()));
        }
        if buf.len() > MAX_SECRET_BYTES {
            return Err(OpkeError::Validation(format!(
                "Secret input exceeds maximum allowed size ({} bytes).",
                MAX_SECRET_BYTES
            )));
        }
        buf
    } else {
        prompt_secret(args.multiline, MAX_SECRET_BYTES)?
    };

    if secret_bytes.is_empty() {
        return Err(OpkeError::Validation("Secret cannot be empty.".into()));
    }

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

    let (key_chacha, key_aes) = derive_key_and_split(
        passphrase.as_bytes(),
        &salt,
        m_kib,
        t,
        p,
    )?;

    // Immediately drop passphrase after key derivation (VULN-36, VULN-68)
    drop(passphrase);

    let kdf_elapsed = t0.elapsed();
    eprintln!("[*] Key derivation completed in {:.2}s.", kdf_elapsed.as_secs_f64());

    // 4. Perform Cascade AEAD Encryption with Nonce Preparation & AAD Commitment (VULN-41)
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
        Some(format!(
            "opke:v=3:kdf=argon2id:m={}:t={}:p={}:c=chacha20-poly1305+aes-256-gcm:nc={}:na={}",
            m_kib, t, p, b64_nc, b64_na
        ).into_bytes())
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

    // Immediately drop subkeys after cascade encryption (VULN-69)
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

    // 6. Save or Output Envelope
    if let Some(ref out_path) = args.output {
        if out_path == "-" {
            // Write to stdout (VULN-61)
            if args.raw {
                println!("{}", raw_b64);
            } else {
                print!("{}", paper_output);
            }
        } else {
            // Prevent silent overwrite without --force (VULN-47)
            let p_out = std::path::Path::new(out_path);
            if p_out.exists() && !args.force {
                if io::stdin().is_terminal() {
                    eprintln!("[!] 警告: 出力先ファイル '{}' は既に存在します。", p_out.display());
                    eprint!("上書きしますか？ (y/N): ");
                    let _ = io::stderr().flush();
                    let mut ans = String::new();
                    let _ = io::stdin().read_line(&mut ans);
                    if !ans.trim().eq_ignore_ascii_case("y") {
                        return Err(OpkeError::Validation(
                            "既存ファイルの上書きがキャンセルされました。上書きを強制するには '--force' を指定してください。".into(),
                        ));
                    }
                } else {
                    return Err(OpkeError::Validation(format!(
                        "出力先ファイル '{}' は既に存在します。上書きするには '--force' を指定してください。",
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
        if args.raw {
            println!("{}", raw_b64);
        } else {
            print!("{}", paper_output);
        }
    }

    // 7. QR Code generation if requested (propagating force, VULN-32)
    if let Some(ref qr_path) = args.qr {
        generate_qr_image_with_options(&raw_b64, qr_path, args.force)?;
        eprintln!("[+] QR Code image saved to: {}", qr_path);
    }

    if args.qr_term {
        eprintln!("\n[*] Scan QR code directly from terminal:");
        print_terminal_qr_stderr(&raw_b64)?;
    }

    Ok(())
}
