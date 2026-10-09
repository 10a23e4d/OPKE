use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::OpkeError;
use crate::security::memory::lock_memory;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 64;
pub const SUBKEY_LEN: usize = 32;

pub const MIN_M_KIB: u32 = 8;
pub const MAX_M_KIB: u32 = 67_108_864; // 64 GiB max limit
pub const MIN_T: u32 = 1;
pub const MAX_T: u32 = 1000;
pub const MIN_P: u32 = 1;
pub const MAX_P: u32 = 256;
pub const MAX_PASSPHRASE_BYTES: usize = 4096;

/// Derives a 64-byte key using Argon2id (v0x13) and splits it into two 32-byte keys.
/// Normalizes passphrase to Unicode NFC if valid UTF-8 (VULN-55) and locks derived keys in RAM (VULN-54).
///
/// Returns `(Key_ChaCha, Key_AES)`, both zeroized on drop.
#[allow(clippy::type_complexity)]
pub fn derive_key_and_split(
    passphrase: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), OpkeError> {
    if passphrase.is_empty() {
        return Err(OpkeError::Validation("Passphrase cannot be empty.".into()));
    }
    if passphrase.len() > MAX_PASSPHRASE_BYTES {
        return Err(OpkeError::Validation(format!(
            "Passphrase exceeds maximum allowed length ({} bytes).",
            MAX_PASSPHRASE_BYTES
        )));
    }
    if salt.len() != SALT_LEN {
        return Err(OpkeError::Validation(format!(
            "Salt must be exactly {} bytes, got {}",
            SALT_LEN,
            salt.len()
        )));
    }
    if !(MIN_P..=MAX_P).contains(&p) {
        return Err(OpkeError::Validation(format!(
            "Parallelism must be between {} and {}, got {}",
            MIN_P, MAX_P, p
        )));
    }
    if !(MIN_T..=MAX_T).contains(&t) {
        return Err(OpkeError::Validation(format!(
            "Time cost must be between {} and {}, got {}",
            MIN_T, MAX_T, t
        )));
    }
    if !(MIN_M_KIB..=MAX_M_KIB).contains(&m_kib) {
        return Err(OpkeError::Validation(format!(
            "Memory cost must be between {} KiB and {} KiB, got {} KiB",
            MIN_M_KIB, MAX_M_KIB, m_kib
        )));
    }
    if m_kib < 8 * p {
        return Err(OpkeError::Validation(format!(
            "Memory cost too low: {} KiB (Argon2 requires m_kib >= 8 * p = {} KiB)",
            m_kib,
            8 * p
        )));
    }

    // Unicode NFC Normalization (VULN-55)
    let norm_pass: Zeroizing<Vec<u8>> = if let Ok(s) = std::str::from_utf8(passphrase) {
        let nfc_string: String = s.nfc().collect();
        Zeroizing::new(nfc_string.into_bytes())
    } else {
        Zeroizing::new(passphrase.to_vec())
    };
    let _ = lock_memory(norm_pass.as_ptr(), norm_pass.len());

    let params = Params::new(m_kib, t, p, Some(KEY_LEN)).map_err(|e| {
        OpkeError::Crypto(format!("Failed to initialize Argon2 params: {}", e))
    })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out_key = Zeroizing::new([0u8; KEY_LEN]);
    let _ = lock_memory(out_key.as_ptr(), KEY_LEN);

    argon2
        .hash_password_into(&norm_pass, salt, &mut *out_key)
        .map_err(|e| OpkeError::Crypto(format!("Argon2id derivation failed: {}", e)))?;

    let mut key_chacha = Zeroizing::new([0u8; SUBKEY_LEN]);
    let mut key_aes = Zeroizing::new([0u8; SUBKEY_LEN]);
    let _ = lock_memory(key_chacha.as_ptr(), SUBKEY_LEN);
    let _ = lock_memory(key_aes.as_ptr(), SUBKEY_LEN);

    key_chacha.copy_from_slice(&out_key[..SUBKEY_LEN]);
    key_aes.copy_from_slice(&out_key[SUBKEY_LEN..]);

    // Ensure subkeys are not degenerate identical
    if bool::from(key_chacha.as_slice().ct_eq(key_aes.as_slice())) {
        return Err(OpkeError::Crypto(
            "Argon2id derived degenerate identical subkeys.".into(),
        ));
    }

    Ok((key_chacha, key_aes))
}
