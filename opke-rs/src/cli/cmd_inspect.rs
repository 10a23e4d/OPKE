//! Handler for `opke inspect` subcommand.

use std::io::{self, IsTerminal, Read};

use crate::envelope::{deserialize_envelope, MAX_ENVELOPE_CHARS};
use crate::error::OpkeError;
use crate::security::read_secure_file;

use super::args::InspectArgs;

fn read_stdin_envelope() -> Result<String, OpkeError> {
    if io::stdin().is_terminal() {
        eprintln!("[*] Paste your OPKE envelope (or PEM block), then press Ctrl+Z (Windows) or Ctrl+D (Unix) then Enter:");
    }
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

pub fn execute(args: InspectArgs) -> Result<(), OpkeError> {
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
    } else {
        read_stdin_envelope()?
    };

    if raw_input.trim().is_empty() {
        return Err(OpkeError::Validation("Envelope input is empty.".into()));
    }

    let envelope = deserialize_envelope(&raw_input)?;
    let decoded = envelope.get_decoded_bytes()?;

    println!("============================================================");
    println!("             OPKE Envelope Inspection Metadata              ");
    println!("============================================================");
    println!("Envelope Version : v{}", envelope.v);
    println!("------------------------------------------------------------");
    println!("KDF Algorithm    : {}", envelope.kdf.name);
    println!(
        "Memory Cost (m)  : {} KiB ({:.2} GiB)",
        envelope.kdf.m_kib,
        (envelope.kdf.m_kib as f64) / 1024.0 / 1024.0
    );
    println!("Time Cost (t)    : {} iterations", envelope.kdf.t);
    println!("Parallelism (p)  : {} threads", envelope.kdf.p);
    println!("Salt (16B Base64): {}", envelope.kdf.salt);
    println!("------------------------------------------------------------");
    println!("Cipher Layers    : {}", envelope.cipher.layers.join(" -> "));
    println!("ChaCha20 Nonce   : {}", envelope.cipher.nonce_chacha);
    println!("AES-256 Nonce    : {}", envelope.cipher.nonce_aes);
    println!("AES-256 Tag      : {}", envelope.cipher.tag_aes);
    println!("------------------------------------------------------------");
    println!(
        "Ciphertext Size  : {} bytes",
        decoded.final_ciphertext.len()
    );
    println!("============================================================");

    Ok(())
}
