//! Handler for `opke encrypt` subcommand.

use std::io::{self, IsTerminal, Read};
use std::time::Instant;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::core::{
    derive_key_and_split, encrypt_cascade, get_profile, MAX_SECRET_BYTES,
    MIN_M_KIB, MIN_P, MIN_T, MAX_M_KIB, MAX_P, MAX_T, PROFILE_PRODUCTION, SALT_LEN,
};
use crate::envelope::create_envelope;
use crate::error::OpkeError;
use crate::qr::{generate_qr_image, print_terminal_qr_stderr};
use crate::security::{
    get_available_memory_kib, prompt_passphrase, prompt_secret, read_secure_file,
    scrub_env_passphrase, write_secure_file,
};

use super::args::EncryptArgs;

pub fn execute(args: EncryptArgs) -> Result<(), OpkeError> {
    // 1. Resolve and validate KDF parameters
    let profile = get_profile(&args.profile).unwrap_or(PROFILE_PRODUCTION);
    let m_kib = args.mem.unwrap_or(profile.m_kib);
    let t = args.time.unwrap_or(profile.t);
    let p = args.threads.unwrap_or(profile.p);

    if m_kib < MIN_M_KIB || m_kib > MAX_M_KIB {
        return Err(OpkeError::Validation(format!(
            "Invalid memory cost: {} KiB (range: {}-{})",
            m_kib, MIN_M_KIB, MAX_M_KIB
        )));
    }
    if p < MIN_P || p > MAX_P {
        return Err(OpkeError::Validation(format!(
            "Invalid parallelism: {} (range: {}-{})",
            p, MIN_P, MAX_P
        )));
    }
    if t < MIN_T || t > MAX_T {
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
    let secret_bytes: Zeroizing<Vec<u8>> = if let Some(sec) = args.secret {
        eprintln!(
            "[!] SECURITY WARNING: Passing secret as command-line argument exposes it to process tables and shell history!"
        );
        Zeroizing::new(sec.into_bytes())
    } else if let Some(path) = args.input_file {
        read_secure_file(path, MAX_SECRET_BYTES)?
    } else if !io::stdin().is_terminal() {
        let mut buf = Zeroizing::new(Vec::new());
        io::stdin().read_to_end(&mut buf)?;
        if buf.is_empty() {
            return Err(OpkeError::Validation("Secret input is empty.".into()));
        }
        buf
    } else {
        prompt_secret(args.multiline, MAX_SECRET_BYTES)?
    };

    if secret_bytes.is_empty() {
        return Err(OpkeError::Validation("Secret cannot be empty.".into()));
    }

    // 3. Resolve passphrase
    let passphrase: Zeroizing<String> = if let Some(pass) = args.passphrase {
        eprintln!(
            "[!] SECURITY WARNING: Passing passphrase as command-line argument exposes it to process tables and shell history!"
        );
        Zeroizing::new(pass)
    } else if let Some(env_pass) = scrub_env_passphrase()? {
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

    let kdf_elapsed = t0.elapsed();
    eprintln!("[*] Key derivation completed in {:.2}s.", kdf_elapsed.as_secs_f64());

    // 4. Perform Cascade AEAD Encryption
    let (final_ciphertext, tag_aes, nonce_chacha, nonce_aes) = encrypt_cascade(
        secret_bytes.as_slice(),
        &key_chacha,
        &key_aes,
        None,
        None,
    )?;

    // 5. Build Envelope (version 3)
    let envelope = create_envelope(
        &salt,
        m_kib,
        t,
        p,
        &nonce_chacha,
        &nonce_aes,
        &tag_aes,
        &final_ciphertext,
        Some(3),
    )?;

    let paper_output = envelope.to_paper_format()?;
    let raw_b64 = envelope.to_base64_payload()?;

    // 6. Save or Output Envelope
    if let Some(ref out_path) = args.output {
        let content_to_write = if args.raw {
            format!("{}\n", raw_b64)
        } else {
            paper_output.clone()
        };
        write_secure_file(out_path, content_to_write.as_bytes())?;
        eprintln!("[+] Encrypted envelope written to: {}", out_path);
    } else {
        if args.raw {
            println!("{}", raw_b64);
        } else {
            print!("{}", paper_output);
        }
    }

    // 7. QR Code generation if requested
    if let Some(ref qr_path) = args.qr {
        generate_qr_image(&raw_b64, qr_path)?;
        eprintln!("[+] QR Code image saved to: {}", qr_path);
    }

    if args.qr_term {
        eprintln!("\n[*] Scan QR code directly from terminal:");
        print_terminal_qr_stderr(&raw_b64)?;
    }

    Ok(())
}
