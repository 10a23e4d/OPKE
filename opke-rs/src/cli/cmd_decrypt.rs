//! Handler for `opke decrypt` subcommand.

use std::io::{self, IsTerminal, Read, Write};
use std::time::Instant;
use zeroize::Zeroizing;

use crate::core::{decrypt_cascade, derive_key_and_split};
use crate::envelope::{deserialize_envelope, MAX_ENVELOPE_CHARS};
use crate::error::OpkeError;
use crate::security::{
    get_available_memory_kib, prompt_passphrase, read_secure_file, scrub_env_passphrase,
    write_secure_file,
};

use super::args::DecryptArgs;

pub fn execute(args: DecryptArgs) -> Result<(), OpkeError> {
    // 1. Read input envelope
    let raw_input: String = if let Some(inp) = args.input {
        inp
    } else if let Some(path) = args.input_file {
        let bytes = read_secure_file(path, MAX_ENVELOPE_CHARS)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| OpkeError::Validation(format!("Envelope file is not valid UTF-8: {}", e)))?
    } else if !io::stdin().is_terminal() {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        eprintln!("[*] Paste your OPKE envelope (or PEM block), then press Ctrl+Z (Windows) or Ctrl+D (Unix) then Enter:");
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf
    };

    if raw_input.trim().is_empty() {
        return Err(OpkeError::Validation("Envelope input is empty.".into()));
    }

    // 2. Parse and validate envelope
    let envelope = deserialize_envelope(&raw_input)?;

    // 3. Check memory and execution constraints before prompting for passphrase
    let m_kib = envelope.kdf.m_kib;
    let t = envelope.kdf.t;
    let p = envelope.kdf.p;

    if let Some(max_m) = args.max_mem {
        if m_kib > max_m {
            return Err(OpkeError::ResourceLimit(format!(
                "Envelope memory requirement ({} KiB) exceeds specified --max-mem limit ({} KiB).",
                m_kib, max_m
            )));
        }
    }
    if let Some(max_t) = args.max_time {
        if t > max_t {
            return Err(OpkeError::ResourceLimit(format!(
                "Envelope time requirement ({} iterations) exceeds specified --max-time limit ({}).",
                t, max_t
            )));
        }
    }
    if let Some(max_p) = args.max_threads {
        if p > max_p {
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
    let passphrase: Zeroizing<String> = if let Some(pass) = args.passphrase {
        eprintln!(
            "[!] SECURITY WARNING: Passing passphrase as command-line argument exposes it to process tables and shell history!"
        );
        Zeroizing::new(pass)
    } else if let Some(env_pass) = scrub_env_passphrase()? {
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
    let (key_chacha, key_aes) = derive_key_and_split(
        passphrase.as_bytes(),
        &decoded.salt,
        m_kib,
        t,
        p,
    )?;

    let kdf_elapsed = t0.elapsed();
    eprintln!("[*] Key derivation completed in {:.2}s.", kdf_elapsed.as_secs_f64());

    // 5. Decrypt and Authenticate Cascade
    let plaintext = decrypt_cascade(
        &decoded.final_ciphertext,
        &decoded.tag_aes,
        &decoded.nonce_aes,
        &decoded.nonce_chacha,
        &key_chacha,
        &key_aes,
    )?;

    // 6. Output plaintext
    if let Some(ref out_path) = args.output {
        write_secure_file(out_path, plaintext.as_slice())?;
        eprintln!("[+] Decrypted plaintext written to: {}", out_path);
    } else {
        io::stdout().write_all(plaintext.as_slice())?;
        io::stdout().flush()?;
    }

    Ok(())
}
