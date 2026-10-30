use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::OpkeError;
use crate::security::memory::MemoryLockGuard;

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

/// Returns architecture-aware maximum allowed Argon2 memory parameter in KiB.
pub const fn max_arch_m_kib() -> u32 {
    if usize::BITS <= 32 {
        let limit = u32::MAX / 1024;
        if limit < MAX_M_KIB {
            limit
        } else {
            MAX_M_KIB
        }
    } else {
        MAX_M_KIB
    }
}

/// Pure predicate checking Argon2id KDF parameter bounds without heap allocations.
/// Serves as the single source of truth for `validate_kdf_params` and Kani formal verification.
pub const fn is_valid_kdf_params(m_kib: u32, t: u32, p: u32) -> bool {
    let max_arch_kib = max_arch_m_kib();
    if m_kib < MIN_M_KIB || m_kib > max_arch_kib {
        return false;
    }
    if p < MIN_P || p > MAX_P {
        return false;
    }
    if t < MIN_T || t > MAX_T {
        return false;
    }
    match 8u32.checked_mul(p) {
        Some(min_m) => m_kib >= min_m,
        None => false,
    }
}

/// Extracts two 32-byte subkeys from a 64-byte master key and verifies in constant time
/// that the derived subkeys are non-identical.
pub fn extract_distinct_subkeys(
    master_key: &[u8; KEY_LEN],
    key_chacha: &mut [u8; SUBKEY_LEN],
    key_aes: &mut [u8; SUBKEY_LEN],
) -> bool {
    key_chacha.copy_from_slice(&master_key[..SUBKEY_LEN]);
    key_aes.copy_from_slice(&master_key[SUBKEY_LEN..]);
    !bool::from(key_chacha.as_slice().ct_eq(key_aes.as_slice()))
}

/// Validates Argon2id KDF parameters against strict system and algorithm bounds.
/// Only returns `Ok(())` when `is_valid_kdf_params(m_kib, t, p)` holds.
pub fn validate_kdf_params(m_kib: u32, t: u32, p: u32) -> Result<(), OpkeError> {
    if is_valid_kdf_params(m_kib, t, p) {
        return Ok(());
    }
    let max_arch_kib = max_arch_m_kib();
    if m_kib < MIN_M_KIB || m_kib > max_arch_kib {
        return Err(OpkeError::Validation(format!(
            "Invalid memory cost: {} KiB (range: {}-{})",
            m_kib, MIN_M_KIB, max_arch_kib
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
    Err(OpkeError::Validation(format!(
        "Invalid memory cost: {} KiB (Argon2 requires m >= 8 * p = {} KiB)",
        m_kib,
        8u64 * (p as u64)
    )))
}

/// Derives a 64-byte key using Argon2id (v0x13) and splits it into two 32-byte keys.
/// Normalizes passphrase to Unicode NFC if valid UTF-8 and locks derived keys in RAM.
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
    validate_kdf_params(m_kib, t, p)?;

    // Unicode NFC Normalization (VULN-55, VULN-84, VULN-136)
    let norm_pass: Zeroizing<Vec<u8>> = if let Ok(s) = std::str::from_utf8(passphrase) {
        let mut nfc_buf = Zeroizing::new(Vec::with_capacity(s.len().saturating_mul(2)));
        for ch in s.nfc() {
            let mut b = [0u8; 4];
            let encoded = ch.encode_utf8(&mut b);
            nfc_buf.extend_from_slice(encoded.as_bytes());
        }
        nfc_buf
    } else {
        Zeroizing::new(passphrase.to_vec())
    };
    let _lock_norm_pass = MemoryLockGuard::try_lock(&norm_pass);

    let params = Params::new(m_kib, t, p, Some(KEY_LEN))
        .map_err(|e| OpkeError::Crypto(format!("Failed to initialize Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out_key = Zeroizing::new([0u8; KEY_LEN]);

    argon2
        .hash_password_into(&norm_pass, salt, &mut *out_key)
        .map_err(|e| OpkeError::Crypto(format!("Argon2id derivation failed: {}", e)))?;

    let _lock_out_key = MemoryLockGuard::try_lock(&*out_key);

    let mut key_chacha = Zeroizing::new([0u8; SUBKEY_LEN]);
    let mut key_aes = Zeroizing::new([0u8; SUBKEY_LEN]);

    // Ensure subkeys are extracted and not degenerate identical
    if !extract_distinct_subkeys(&out_key, &mut key_chacha, &mut key_aes) {
        return Err(OpkeError::Crypto(
            "Argon2id derived degenerate identical subkeys.".into(),
        ));
    }

    Ok((key_chacha, key_aes))
}
