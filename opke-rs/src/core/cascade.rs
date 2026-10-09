//! Dual-layer AEAD cascade encryption:
//! Layer 1: ChaCha20-Poly1305
//! Layer 2: AES-256-GCM

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key as AesKey, Nonce as AesNonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::OpkeError;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const SUBKEY_LEN: usize = 32;
pub const MIN_CIPHERTEXT_BYTES: usize = 17; // 1-byte plaintext + 16-byte Poly1305 tag
pub const MAX_SECRET_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_SECRET_BYTES + TAG_LEN;

/// Encrypts plaintext using dual AEAD cascade (ChaCha20-Poly1305 + AES-256-GCM) with optional AAD.
///
/// Returns `(final_ciphertext, tag_aes, nonce_chacha, nonce_aes)`.
#[allow(clippy::type_complexity)]
pub fn encrypt_cascade(
    plaintext: &[u8],
    key_chacha: &[u8; SUBKEY_LEN],
    key_aes: &[u8; SUBKEY_LEN],
    nonce_chacha: Option<[u8; NONCE_LEN]>,
    nonce_aes: Option<[u8; NONCE_LEN]>,
    aad: Option<&[u8]>,
) -> Result<(Vec<u8>, [u8; TAG_LEN], [u8; NONCE_LEN], [u8; NONCE_LEN]), OpkeError> {
    if plaintext.is_empty() {
        return Err(OpkeError::Validation("Plaintext cannot be empty.".into()));
    }
    if plaintext.len() > MAX_SECRET_BYTES {
        return Err(OpkeError::Validation(format!(
            "Plaintext exceeds maximum allowed size ({} bytes).",
            MAX_SECRET_BYTES
        )));
    }
    if bool::from(key_chacha.as_slice().ct_eq(key_aes.as_slice())) {
        return Err(OpkeError::Validation(
            "Key_ChaCha and Key_AES must be independent and distinct.".into(),
        ));
    }

    let n_chacha = match nonce_chacha {
        Some(n) => n,
        None => {
            let mut n = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut n);
            n
        }
    };

    let n_aes = match nonce_aes {
        Some(n) => {
            if bool::from(n.as_slice().ct_eq(n_chacha.as_slice())) {
                return Err(OpkeError::Validation(
                    "Nonce_ChaCha and Nonce_AES must be distinct.".into(),
                ));
            }
            n
        }
        None => {
            let mut n = [0u8; NONCE_LEN];
            loop {
                OsRng.fill_bytes(&mut n);
                if !bool::from(n.as_slice().ct_eq(n_chacha.as_slice())) {
                    break;
                }
            }
            n
        }
    };

    let aad_bytes = aad.unwrap_or(b"");

    // Layer 1: ChaCha20-Poly1305
    let chacha_key = ChaChaKey::from_slice(key_chacha);
    let chacha_cipher = ChaCha20Poly1305::new(chacha_key);
    let chacha_nonce = ChaChaNonce::from_slice(&n_chacha);

    let l1_blob = Zeroizing::new(
        chacha_cipher
            .encrypt(
                chacha_nonce,
                Payload {
                    msg: plaintext,
                    aad: aad_bytes,
                },
            )
            .map_err(|e| {
                OpkeError::Crypto(format!(
                    "Layer 1 (ChaCha20-Poly1305) encryption failed: {}",
                    e
                ))
            })?,
    );

    // Layer 2: AES-256-GCM
    let aes_key = AesKey::<Aes256Gcm>::from_slice(key_aes);
    let aes_cipher = Aes256Gcm::new(aes_key);
    let aes_nonce = AesNonce::from_slice(&n_aes);

    let mut l2_blob = aes_cipher
        .encrypt(
            aes_nonce,
            Payload {
                msg: l1_blob.as_slice(),
                aad: aad_bytes,
            },
        )
        .map_err(|e| {
            OpkeError::Crypto(format!("Layer 2 (AES-256-GCM) encryption failed: {}", e))
        })?;

    if l2_blob.len() < TAG_LEN {
        return Err(OpkeError::Crypto(
            "Layer 2 encryption output too short.".into(),
        ));
    }

    let ciphertext_len = l2_blob.len() - TAG_LEN;
    let mut tag_aes = [0u8; TAG_LEN];
    tag_aes.copy_from_slice(&l2_blob[ciphertext_len..]);
    l2_blob.truncate(ciphertext_len);

    Ok((l2_blob, tag_aes, n_chacha, n_aes))
}

/// Decrypts ciphertext through inverse dual AEAD cascade (Layer 2 AES-256-GCM then Layer 1 ChaCha20-Poly1305).
/// Order of nonces matches encrypt_cascade (nonce_chacha then nonce_aes) (VULN-59).
/// Returns zeroized plaintext buffer.
pub fn decrypt_cascade(
    final_ciphertext: &[u8],
    tag_aes: &[u8; TAG_LEN],
    nonce_chacha: &[u8; NONCE_LEN],
    nonce_aes: &[u8; NONCE_LEN],
    key_chacha: &[u8; SUBKEY_LEN],
    key_aes: &[u8; SUBKEY_LEN],
    aad: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, OpkeError> {
    if final_ciphertext.len() < MIN_CIPHERTEXT_BYTES {
        return Err(OpkeError::Validation(format!(
            "Ciphertext too short: must be at least {} bytes, got {}",
            MIN_CIPHERTEXT_BYTES,
            final_ciphertext.len()
        )));
    }
    if final_ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(OpkeError::Validation(format!(
            "Ciphertext exceeds maximum allowed size ({} bytes).",
            MAX_CIPHERTEXT_BYTES
        )));
    }
    if bool::from(nonce_chacha.as_slice().ct_eq(nonce_aes.as_slice())) {
        return Err(OpkeError::Validation(
            "Nonce_ChaCha and Nonce_AES must be distinct.".into(),
        ));
    }
    if bool::from(key_chacha.as_slice().ct_eq(key_aes.as_slice())) {
        return Err(OpkeError::Validation(
            "Key_ChaCha and Key_AES must be independent and distinct.".into(),
        ));
    }

    let aad_bytes = aad.unwrap_or(b"");

    // Layer 2: AES-256-GCM Decryption
    let aes_key = AesKey::<Aes256Gcm>::from_slice(key_aes);
    let aes_cipher = Aes256Gcm::new(aes_key);
    let aes_nonce = AesNonce::from_slice(nonce_aes);

    let mut l2_payload = Vec::with_capacity(final_ciphertext.len() + TAG_LEN);
    l2_payload.extend_from_slice(final_ciphertext);
    l2_payload.extend_from_slice(tag_aes);

    // Uniform authentication failure message to eliminate multi-layer oracle (VULN-42)
    let l1_blob = Zeroizing::new(
        aes_cipher
            .decrypt(aes_nonce, Payload { msg: l2_payload.as_slice(), aad: aad_bytes })
            .map_err(|_| {
                OpkeError::Authentication(
                    "Decryption failed: authentication failed. Invalid passphrase or corrupted data.".into(),
                )
            })?,
    );

    if l1_blob.len() < MIN_CIPHERTEXT_BYTES {
        return Err(OpkeError::Authentication(
            "Decryption failed: authentication failed. Invalid passphrase or corrupted data."
                .into(),
        ));
    }

    // Layer 1: ChaCha20-Poly1305 Decryption
    let chacha_key = ChaChaKey::from_slice(key_chacha);
    let chacha_cipher = ChaCha20Poly1305::new(chacha_key);
    let chacha_nonce = ChaChaNonce::from_slice(nonce_chacha);

    let plaintext = Zeroizing::new(
        chacha_cipher
            .decrypt(chacha_nonce, Payload { msg: l1_blob.as_slice(), aad: aad_bytes })
            .map_err(|_| {
                OpkeError::Authentication(
                    "Decryption failed: authentication failed. Invalid passphrase or corrupted data.".into(),
                )
            })?,
    );

    if plaintext.is_empty() {
        return Err(OpkeError::Authentication(
            "Decryption failed: Plaintext is empty.".into(),
        ));
    }

    Ok(plaintext)
}
