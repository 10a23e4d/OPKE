//! Passphrase and secret interactive prompts with guaranteed zeroization on success or error.

use std::io::{self, Read};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::core::MAX_PASSPHRASE_BYTES;
use crate::error::OpkeError;

/// Safely prompts for a passphrase without echoing characters to terminal.
/// Both initial and confirmation entries are zeroized upon drop even if errors or mismatches occur.
pub fn prompt_passphrase(confirm: bool) -> Result<Zeroizing<String>, OpkeError> {
    eprint!("Enter passphrase: ");
    let p1 = Zeroizing::new(
        rpassword::read_password()
            .map_err(|e| OpkeError::Validation(format!("Failed to read passphrase: {}", e)))?,
    );

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
        let p2 =
            Zeroizing::new(rpassword::read_password().map_err(|e| {
                OpkeError::Validation(format!("Failed to read confirmation: {}", e))
            })?);

        if !bool::from(p1.as_bytes().ct_eq(p2.as_bytes())) {
            return Err(OpkeError::Validation("Passphrases do not match.".into()));
        }
    }

    Ok(p1)
}

/// Prompts for secret plaintext (interactive hidden entry or multiline / piped input).
/// Uses pre-allocated zeroized buffers and zeroizes all temporary stack buffers on completion or error.
pub fn prompt_secret(multiline: bool, max_bytes: usize) -> Result<Zeroizing<Vec<u8>>, OpkeError> {
    if multiline {
        eprintln!(
            "[*] Multi-line secret entry:\n[*] Paste/type secret, then press Ctrl+Z (Windows) or Ctrl+D (Unix) then Enter:"
        );
        // VULN-80, VULN-126: Collect boxed 8KB chunks so vector reallocation moves pointers only,
        // eliminating shallow copy leaks of unzeroized plaintext in previous heap chunks.
        let mut chunks: Vec<Box<Zeroizing<[u8; 8192]>>> = Vec::new();
        let mut total_len = 0usize;
        let mut stdin = io::stdin().lock();
        loop {
            // VULN-158: Check size limit upfront before accumulating more chunks
            if total_len >= max_bytes {
                return Err(OpkeError::Validation(format!(
                    "Secret input exceeds maximum allowed size ({} bytes).",
                    max_bytes
                )));
            }
            let mut chunk = Box::new(Zeroizing::new([0u8; 8192]));
            let n = stdin.read(&mut **chunk)?;
            if n == 0 {
                break;
            }
            total_len += n;
            chunks.push(chunk);
            if total_len > max_bytes {
                return Err(OpkeError::Validation(format!(
                    "Secret input exceeds maximum allowed size ({} bytes).",
                    max_bytes
                )));
            }
        }
        if total_len == 0 {
            return Err(OpkeError::Validation("Secret cannot be empty.".into()));
        }
        let mut buf = Zeroizing::new(Vec::with_capacity(total_len));
        let mut remaining = total_len;
        for c in chunks {
            let to_copy = remaining.min(8192);
            buf.extend_from_slice(&c[..to_copy]);
            remaining -= to_copy;
        }
        Ok(buf)
    } else {
        eprint!("Enter secret plaintext (hidden): ");
        let mut s = Zeroizing::new(
            rpassword::read_password()
                .map_err(|e| OpkeError::Validation(format!("Failed to read secret: {}", e)))?,
        );

        if s.is_empty() {
            return Err(OpkeError::Validation("Secret cannot be empty.".into()));
        }
        if s.len() > max_bytes {
            return Err(OpkeError::Validation(format!(
                "Secret exceeds maximum allowed size ({} bytes).",
                max_bytes
            )));
        }
        // VULN-46: Avoid extra heap cloning by converting underlying String to Vec in-place
        let vec = std::mem::take(&mut *s).into_bytes();
        let bytes = Zeroizing::new(vec);
        Ok(bytes)
    }
}
