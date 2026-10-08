//! Passphrase and secret interactive prompts.

use std::io::{self, Read};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::core::MAX_PASSPHRASE_BYTES;
use crate::error::OpkeError;

/// Safely prompts for a passphrase without echoing characters to terminal.
pub fn prompt_passphrase(confirm: bool) -> Result<Zeroizing<String>, OpkeError> {
    eprint!("Enter passphrase: ");
    let p1 = rpassword::read_password()
        .map_err(|e| OpkeError::Validation(format!("Failed to read passphrase: {}", e)))?;

    if p1.is_empty() {
        return Err(OpkeError::Validation("Passphrase cannot be empty.".into()));
    }
    if p1.len() > MAX_PASSPHRASE_BYTES {
        return Err(OpkeError::Validation(format!(
            "Passphrase exceeds maximum allowed length ({} bytes).",
            MAX_PASSPHRASE_BYTES
        )));
    }

    if confirm {
        eprint!("Confirm passphrase: ");
        let p2 = rpassword::read_password()
            .map_err(|e| OpkeError::Validation(format!("Failed to read confirmation: {}", e)))?;

        if !bool::from(p1.as_bytes().ct_eq(p2.as_bytes())) {
            return Err(OpkeError::Validation("Passphrases do not match.".into()));
        }
    }

    Ok(Zeroizing::new(p1))
}

/// Prompts for secret plaintext (interactive hidden entry or multiline / piped input).
pub fn prompt_secret(multiline: bool, max_bytes: usize) -> Result<Zeroizing<Vec<u8>>, OpkeError> {
    if multiline {
        eprintln!(
            "[*] Multi-line secret entry:\n[*] Paste/type secret, then press Ctrl+Z (Windows) or Ctrl+D (Unix) then Enter:"
        );
        let mut buf = Zeroizing::new(Vec::new());
        let mut stdin = io::stdin().lock();
        let mut chunk = [0u8; 8192];
        loop {
            let n = stdin.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > max_bytes {
                return Err(OpkeError::Validation(format!(
                    "Secret input exceeds maximum allowed size ({} bytes).",
                    max_bytes
                )));
            }
        }
        if buf.is_empty() {
            return Err(OpkeError::Validation("Secret cannot be empty.".into()));
        }
        Ok(buf)
    } else {
        eprint!("Enter secret plaintext (hidden): ");
        let s = rpassword::read_password()
            .map_err(|e| OpkeError::Validation(format!("Failed to read secret: {}", e)))?;

        if s.is_empty() {
            return Err(OpkeError::Validation("Secret cannot be empty.".into()));
        }
        if s.len() > max_bytes {
            return Err(OpkeError::Validation(format!(
                "Secret exceeds maximum allowed size ({} bytes).",
                max_bytes
            )));
        }
        Ok(Zeroizing::new(s.into_bytes()))
    }
}
