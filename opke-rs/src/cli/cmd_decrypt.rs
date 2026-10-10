//! Handler for `opke decrypt` subcommand.

use std::io::{self, IsTerminal, Read, Write};
use std::time::Instant;
use zeroize::Zeroizing;

use crate::core::{
    decrypt_cascade, derive_key_and_split, MAX_M_KIB, MAX_P, MAX_T, MIN_M_KIB, MIN_P, MIN_T,
};
use crate::envelope::{deserialize_envelope, MAX_ENVELOPE_CHARS};
use crate::error::OpkeError;
use crate::security::{
    get_available_memory_kib, prompt_passphrase, read_secure_file, scrub_env_passphrase,
    write_secure_file_with_options, MemoryLockGuard,
};

use super::args::DecryptArgs;
use super::reject_sensitive_arg;

const DEFAULT_MAX_MEM_KIB: u64 = 8 * 1024 * 1024; // 8 GiB default memory limit

fn read_stdin_envelope() -> Result<String, OpkeError> {
    let mut take = io::stdin().take((MAX_ENVELOPE_CHARS + 1) as u64);
    let mut buf = String::new();
    take.read_to_string(&mut buf)?;
    if buf.len() > MAX_ENVELOPE_CHARS {
        return Err(OpkeError::Validation(format!(
            "Envelope input exceeds maximum allowed size ({} chars).",
            MAX_ENVELOPE_CHARS
        )));
    }
    Ok(buf)
}

fn output_plaintext_to_stdout(plaintext: &[u8], force: bool) -> Result<(), OpkeError> {
    if io::stdout().is_terminal() {
        // Refuse binary control characters / ANSI escape sequences unless force
        let has_control = plaintext
            .iter()
            .any(|&b| (b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r') || b == 0x7f);
        if has_control {
            if !force {
                return Err(OpkeError::Validation(
                    "Output contains binary control characters or ANSI escape sequences.\nDirect terminal output was blocked to prevent terminal escape injection attacks.\nUse '--output <file>' to save safely, or '--force' to display anyway.".into()
                ));
            }
            eprintln!("[!] Warning: Output contains binary control characters. Terminal output may be corrupted. Use --output <file> to save safely.");
        }
        let mut stdout = io::stdout();
        stdout.write_all(plaintext).map_err(OpkeError::Io)?;
        // Ensure trailing newline on terminal
        if !plaintext.is_empty() && !plaintext.ends_with(b"\n") {
            stdout.write_all(b"\n").map_err(OpkeError::Io)?;
        }
        stdout.flush().map_err(OpkeError::Io)?;
    } else {
        let mut stdout = io::stdout();
        stdout.write_all(plaintext).map_err(OpkeError::Io)?;
        stdout.flush().map_err(OpkeError::Io)?;
    }
    Ok(())
}

pub fn execute(mut args: DecryptArgs) -> Result<(), OpkeError> {
    // 0. Prohibit passing passphrases via CLI args
    reject_sensitive_arg(
        &mut args.passphrase,
        "passphrases",
        "Please use interactive prompt or set the 'OPKE_PASSPHRASE' environment variable.",
    )?;

    // Validate limit options upfront
    if let Some(max_m) = args.max_mem {
        if max_m < MIN_M_KIB as i64 || max_m > MAX_M_KIB as i64 {
            return Err(OpkeError::Validation(format!(
                "Invalid --max-mem: {} KiB (range: {}-{})",
                max_m, MIN_M_KIB, MAX_M_KIB
            )));
        }
    }
    if let Some(max_t) = args.max_time {
        if max_t < MIN_T as i64 || max_t > MAX_T as i64 {
            return Err(OpkeError::Validation(format!(
                "Invalid --max-time: {} (range: {}-{})",
                max_t, MIN_T, MAX_T
            )));
        }
    }
    if let Some(max_p) = args.max_threads {
        if max_p < MIN_P as i64 || max_p > MAX_P as i64 {
            return Err(OpkeError::Validation(format!(
                "Invalid --max-threads: {} (range: {}-{})",
                max_p, MIN_P, MAX_P
            )));
        }
    }

    // 1. Read input envelope (bounded stdin read for VULN-15, "-" handling for VULN-61)
    let raw_input: String = if let Some(ref inp) = args.input {
        if inp == "-" {
            read_stdin_envelope()?
        } else {
            inp.clone()
        }
    } else if let Some(ref path) = args.input_file {
        if path == "-" {
            read_stdin_envelope()?
        } else {
            let bytes = read_secure_file(path, MAX_ENVELOPE_CHARS)?;
            String::from_utf8(bytes.to_vec()).map_err(|e| {
                OpkeError::Validation(format!("Envelope file is not valid UTF-8: {}", e))
            })?
        }
    } else if !io::stdin().is_terminal() {
        read_stdin_envelope()?
    } else {
        eprintln!("[*] Paste your OPKE envelope (or PEM block), then press Ctrl+Z (Windows) or Ctrl+D (Unix) then Enter:");
        read_stdin_envelope()?
    };

    if raw_input.trim().is_empty() {
        return Err(OpkeError::Validation("Envelope input is empty.".into()));
    }

    // 2. Parse and validate envelope
    let envelope = deserialize_envelope(&raw_input)?;

    // Prevent envelope downgrade attacks. Legacy v2 requires explicit --allow-v2
    if envelope.v == 2 && !args.allow_v2 {
        return Err(OpkeError::Validation(
            "Envelope format is legacy v2. Use '--allow-v2' to permit decrypting legacy v2 envelopes.".into(),
        ));
    }

    // 3. Check memory and execution constraints before prompting for passphrase
    let m_kib = envelope.kdf.m_kib;
    let t = envelope.kdf.t;
    let p = envelope.kdf.p;

    // Enforce default memory limit if --max-mem not specified
    let effective_max_m = args.max_mem.unwrap_or(DEFAULT_MAX_MEM_KIB as i64);
    if (m_kib as i64) > effective_max_m && !args.force {
        return Err(OpkeError::ResourceLimit(format!(
            "Envelope memory requirement ({} KiB) exceeds max memory limit ({} KiB).\nUse '--max-mem' or '--force' to override.",
            m_kib, effective_max_m
        )));
    }

    if let Some(max_t) = args.max_time {
        if (t as i64) > max_t {
            return Err(OpkeError::ResourceLimit(format!(
                "Envelope time requirement ({} iterations) exceeds specified --max-time limit ({}).",
                t, max_t
            )));
        }
    }
    if let Some(max_p) = args.max_threads {
        if (p as i64) > max_p {
            return Err(OpkeError::ResourceLimit(format!(
                "Envelope parallelism requirement ({} threads) exceeds specified --max-threads limit ({}).",
                p, max_p
            )));
        }
    }

    if let Some(avail_kib) = get_available_memory_kib() {
        if (m_kib as u64) > avail_kib && !args.force {
            return Err(OpkeError::ResourceLimit(format!(
                "Envelope requires {} KiB ({:.2} GiB) RAM, but only ~{} KiB ({:.2} GiB) is available.\nDecryption aborted to prevent system freeze / OOM. Use '--force' to override.",
                m_kib, (m_kib as f64) / 1024.0 / 1024.0,
                avail_kib, (avail_kib as f64) / 1024.0 / 1024.0
            )));
        }
    }

    // 4. Read passphrase
    let passphrase: Zeroizing<String> = if let Some(env_pass) = scrub_env_passphrase()? {
        env_pass
    } else {
        prompt_passphrase(false)?
    };

    let decoded = envelope.get_decoded_bytes()?;

    eprintln!(
        "[*] Deriving keys with Argon2id (m={} KiB ({:.2} GiB), t={}, p={})...",
        m_kib,
        (m_kib as f64) / 1024.0 / 1024.0,
        t,
        p
    );

    let t0 = Instant::now();
    let (key_chacha, key_aes) =
        derive_key_and_split(passphrase.as_bytes(), &decoded.salt, m_kib, t, p)?;

    // Lock subkeys at caller stack frame in physical RAM
    let _lock_chacha = MemoryLockGuard::try_lock(&*key_chacha);
    let _lock_aes = MemoryLockGuard::try_lock(&*key_aes);

    // Immediately drop passphrase
    drop(passphrase);

    let kdf_elapsed = t0.elapsed();
    eprintln!(
        "[*] Key derivation completed in {:.2}s.",
        kdf_elapsed.as_secs_f64()
    );

    // 5. Decrypt and Authenticate Cascade (AAD binding, unified nonce order)
    let aad = envelope.compute_aad();
    let aad_ref = if aad.is_empty() {
        None
    } else {
        Some(aad.as_slice())
    };

    let plaintext = decrypt_cascade(
        &decoded.final_ciphertext,
        &decoded.tag_aes,
        &decoded.nonce_chacha,
        &decoded.nonce_aes,
        &key_chacha,
        &key_aes,
        aad_ref,
    )?;

    // Lock decrypted plaintext into physical RAM
    let _lock_plain = MemoryLockGuard::try_lock(&plaintext);

    // Immediately drop lock guards and subkeys
    drop(_lock_chacha);
    drop(_lock_aes);
    drop(key_chacha);
    drop(key_aes);

    // 6. Output plaintext
    let allow_overwrite = args.force || args.overwrite;
    if let Some(ref out_path) = args.output {
        if out_path == "-" {
            output_plaintext_to_stdout(plaintext.as_slice(), args.force)?;
        } else {
            if std::path::Path::new(out_path).exists() && !allow_overwrite {
                if io::stdin().is_terminal() {
                    eprint!(
                        "[?] Output file '{}' already exists. Overwrite? (y/N): ",
                        out_path
                    );
                    io::stderr().flush()?;
                    let mut line = String::new();
                    io::stdin().read_line(&mut line)?;
                    if !line.trim().eq_ignore_ascii_case("y") {
                        return Err(OpkeError::Validation(
                            "Aborted: file already exists.".into(),
                        ));
                    }
                } else {
                    return Err(OpkeError::Validation(format!(
                        "Output file '{}' already exists. Use '--force' or '--overwrite' to overwrite.",
                        out_path
                    )));
                }
            }
            write_secure_file_with_options(out_path, plaintext.as_slice(), args.force)?;
            eprintln!("[+] Decrypted plaintext written to: {}", out_path);
        }
    } else {
        output_plaintext_to_stdout(plaintext.as_slice(), args.force)?;
    }

    Ok(())
}
