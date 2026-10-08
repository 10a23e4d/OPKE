//! OPKE Envelope serialization, deserialization, and strict validation.

pub mod model;
pub mod pem;

pub use model::{CipherParams, KdfParams, OPKEEnvelope};
pub use pem::{strip_pem, to_paper_format, PEM_FOOTER, PEM_HEADER};

use base64::prelude::*;
use subtle::ConstantTimeEq;

use crate::core::{
    MAX_CIPHERTEXT_BYTES, MAX_M_KIB, MAX_P, MAX_T, MIN_M_KIB, MIN_P, MIN_T, NONCE_LEN, SALT_LEN,
    TAG_LEN,
};
use crate::error::OpkeError;

pub const CURRENT_VERSION: u32 = 3;
pub const MAX_ENVELOPE_CHARS: usize = 160 * 1024 * 1024; // 160 MiB

#[derive(Debug, Clone)]
pub struct DecodedEnvelopeBytes {
    pub salt: [u8; SALT_LEN],
    pub nonce_chacha: [u8; NONCE_LEN],
    pub nonce_aes: [u8; NONCE_LEN],
    pub tag_aes: [u8; TAG_LEN],
    pub final_ciphertext: Vec<u8>,
}

impl OPKEEnvelope {
    /// Serializes envelope to a compact JSON string without whitespace.
    pub fn to_compact_json(&self) -> Result<String, OpkeError> {
        serde_json::to_string(self).map_err(|e| OpkeError::Envelope(e.to_string()))
    }

    /// Serializes envelope to a single-line Base64 payload.
    pub fn to_base64_payload(&self) -> Result<String, OpkeError> {
        let json_str = self.to_compact_json()?;
        Ok(BASE64_STANDARD.encode(json_str.as_bytes()))
    }

    /// Serializes envelope into paper-friendly PEM-formatted wrapped text.
    pub fn to_paper_format(&self) -> Result<String, OpkeError> {
        let b64 = self.to_base64_payload()?;
        pem::to_paper_format(&b64, 64)
    }

    /// Decodes and validates all Base64-encoded cryptographic fields.
    pub fn get_decoded_bytes(&self) -> Result<DecodedEnvelopeBytes, OpkeError> {
        let salt_vec = BASE64_STANDARD
            .decode(&self.kdf.salt)
            .map_err(|e| OpkeError::Envelope(format!("Invalid Base64 salt: {}", e)))?;
        if salt_vec.len() != SALT_LEN {
            return Err(OpkeError::Envelope(format!(
                "Salt length must be {} bytes, got {}",
                SALT_LEN,
                salt_vec.len()
            )));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_vec);

        let nc_vec = BASE64_STANDARD
            .decode(&self.cipher.nonce_chacha)
            .map_err(|e| OpkeError::Envelope(format!("Invalid Base64 nonce_chacha: {}", e)))?;
        if nc_vec.len() != NONCE_LEN {
            return Err(OpkeError::Envelope(format!(
                "Nonce_ChaCha length must be {} bytes, got {}",
                NONCE_LEN,
                nc_vec.len()
            )));
        }
        let mut nonce_chacha = [0u8; NONCE_LEN];
        nonce_chacha.copy_from_slice(&nc_vec);

        let na_vec = BASE64_STANDARD
            .decode(&self.cipher.nonce_aes)
            .map_err(|e| OpkeError::Envelope(format!("Invalid Base64 nonce_aes: {}", e)))?;
        if na_vec.len() != NONCE_LEN {
            return Err(OpkeError::Envelope(format!(
                "Nonce_AES length must be {} bytes, got {}",
                NONCE_LEN,
                na_vec.len()
            )));
        }
        let mut nonce_aes = [0u8; NONCE_LEN];
        nonce_aes.copy_from_slice(&na_vec);

        if nonce_chacha.ct_eq(&nonce_aes).into() {
            return Err(OpkeError::Envelope(
                "Nonce_ChaCha and Nonce_AES must be distinct.".into(),
            ));
        }

        let tag_vec = BASE64_STANDARD
            .decode(&self.cipher.tag_aes)
            .map_err(|e| OpkeError::Envelope(format!("Invalid Base64 tag_aes: {}", e)))?;
        if tag_vec.len() != TAG_LEN {
            return Err(OpkeError::Envelope(format!(
                "Tag_AES length must be {} bytes, got {}",
                TAG_LEN,
                tag_vec.len()
            )));
        }
        let mut tag_aes = [0u8; TAG_LEN];
        tag_aes.copy_from_slice(&tag_vec);

        let final_ciphertext = BASE64_STANDARD
            .decode(&self.data)
            .map_err(|e| OpkeError::Envelope(format!("Invalid Base64 ciphertext data: {}", e)))?;
        if final_ciphertext.is_empty() {
            return Err(OpkeError::Envelope("Ciphertext data cannot be empty.".into()));
        }
        if final_ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(OpkeError::Envelope(format!(
                "Ciphertext data exceeds maximum allowed size ({} bytes).",
                MAX_CIPHERTEXT_BYTES
            )));
        }

        Ok(DecodedEnvelopeBytes {
            salt,
            nonce_chacha,
            nonce_aes,
            tag_aes,
            final_ciphertext,
        })
    }
}

/// Creates a strongly validated OPKEEnvelope instance from raw cryptographic components.
pub fn create_envelope(
    salt: &[u8; SALT_LEN],
    m_kib: u32,
    t: u32,
    p: u32,
    nonce_chacha: &[u8; NONCE_LEN],
    nonce_aes: &[u8; NONCE_LEN],
    tag_aes: &[u8; TAG_LEN],
    final_ciphertext: &[u8],
    version: Option<u32>,
) -> Result<OPKEEnvelope, OpkeError> {
    if m_kib < MIN_M_KIB || m_kib > MAX_M_KIB {
        return Err(OpkeError::Validation(format!(
            "Invalid or out-of-range m_kib: {} (range: {}-{})",
            m_kib, MIN_M_KIB, MAX_M_KIB
        )));
    }
    if t < MIN_T || t > MAX_T {
        return Err(OpkeError::Validation(format!(
            "Invalid or out-of-range t: {} (range: {}-{})",
            t, MIN_T, MAX_T
        )));
    }
    if p < MIN_P || p > MAX_P {
        return Err(OpkeError::Validation(format!(
            "Invalid or out-of-range p: {} (range: {}-{})",
            p, MIN_P, MAX_P
        )));
    }
    if m_kib < 8 * p {
        return Err(OpkeError::Validation(format!(
            "Memory cost too low: {} KiB (must be >= 8 * p = {} KiB)",
            m_kib,
            8 * p
        )));
    }
    if nonce_chacha.ct_eq(nonce_aes).into() {
        return Err(OpkeError::Validation(
            "Nonce_ChaCha and Nonce_AES must be distinct.".into(),
        ));
    }
    if final_ciphertext.is_empty() {
        return Err(OpkeError::Validation(
            "Ciphertext data cannot be empty.".into(),
        ));
    }
    if final_ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(OpkeError::Validation(format!(
            "Ciphertext data exceeds maximum allowed size ({} bytes).",
            MAX_CIPHERTEXT_BYTES
        )));
    }

    Ok(OPKEEnvelope {
        v: version.unwrap_or(CURRENT_VERSION),
        kdf: KdfParams {
            name: "argon2id".to_string(),
            m_kib,
            t,
            p,
            salt: BASE64_STANDARD.encode(salt),
        },
        cipher: CipherParams {
            layers: vec!["chacha20-poly1305".to_string(), "aes-256-gcm".to_string()],
            nonce_chacha: BASE64_STANDARD.encode(nonce_chacha),
            nonce_aes: BASE64_STANDARD.encode(nonce_aes),
            tag_aes: BASE64_STANDARD.encode(tag_aes),
        },
        data: BASE64_STANDARD.encode(final_ciphertext),
    })
}

/// Serializes an OPKEEnvelope to string (either paper PEM format or compact Base64).
pub fn serialize_envelope(envelope: &OPKEEnvelope, paper_format: bool) -> Result<String, OpkeError> {
    if paper_format {
        envelope.to_paper_format()
    } else {
        envelope.to_base64_payload()
    }
}

/// Deserializes and strictly validates an envelope from string input.
/// Supports PEM-wrapped Base64, raw Base64, and compact/raw JSON.
/// Supports both version 2 and version 3 envelopes for seamless backward compatibility.
pub fn deserialize_envelope(raw_input: &str) -> Result<OPKEEnvelope, OpkeError> {
    if raw_input.len() > MAX_ENVELOPE_CHARS {
        return Err(OpkeError::Envelope(format!(
            "Envelope input exceeds maximum allowed size ({} chars).",
            MAX_ENVELOPE_CHARS
        )));
    }

    let text = raw_input.trim();
    if text.is_empty() {
        return Err(OpkeError::Envelope("Input is empty.".into()));
    }

    // 1. Strip PEM header/footer if present
    let unpemed = pem::strip_pem(text)?;
    let cleaned: String = unpemed.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Err(OpkeError::Envelope("Envelope payload is empty.".into()));
    }

    // 2. Determine if payload is JSON or Base64-encoded JSON
    let json_str = if cleaned.starts_with('{') && cleaned.ends_with('}') {
        cleaned
    } else {
        let decoded = BASE64_STANDARD
            .decode(&cleaned)
            .map_err(|e| OpkeError::Envelope(format!("Failed to decode Base64 envelope payload: {}", e)))?;
        String::from_utf8(decoded)
            .map_err(|e| OpkeError::Envelope(format!("Envelope payload is not valid UTF-8: {}", e)))?
    };

    // 3. Parse JSON into OPKEEnvelope with strict field verification
    let envelope: OPKEEnvelope = serde_json::from_str(&json_str)
        .map_err(|e| OpkeError::Envelope(format!("Invalid envelope schema: {}", e)))?;

    // 4. Validate version (accepts v2 for backward compatibility and v3)
    if envelope.v != 2 && envelope.v != 3 {
        return Err(OpkeError::Envelope(format!(
            "Unsupported envelope version: {}. Expected version 2 or 3.",
            envelope.v
        )));
    }

    // 5. Validate KDF fields
    if envelope.kdf.name != "argon2id" {
        return Err(OpkeError::Envelope(format!(
            "Unsupported KDF algorithm: {}. Expected 'argon2id'.",
            envelope.kdf.name
        )));
    }
    if envelope.kdf.m_kib < MIN_M_KIB || envelope.kdf.m_kib > MAX_M_KIB {
        return Err(OpkeError::Envelope(format!(
            "Invalid or out-of-range m_kib: {} (range: {}-{})",
            envelope.kdf.m_kib, MIN_M_KIB, MAX_M_KIB
        )));
    }
    if envelope.kdf.t < MIN_T || envelope.kdf.t > MAX_T {
        return Err(OpkeError::Envelope(format!(
            "Invalid or out-of-range t: {} (range: {}-{})",
            envelope.kdf.t, MIN_T, MAX_T
        )));
    }
    if envelope.kdf.p < MIN_P || envelope.kdf.p > MAX_P {
        return Err(OpkeError::Envelope(format!(
            "Invalid or out-of-range p: {} (range: {}-{})",
            envelope.kdf.p, MIN_P, MAX_P
        )));
    }
    if envelope.kdf.m_kib < 8 * envelope.kdf.p {
        return Err(OpkeError::Envelope(format!(
            "Invalid or out-of-range m_kib: {} (Argon2 requires m_kib >= 8 * p = {})",
            envelope.kdf.m_kib,
            8 * envelope.kdf.p
        )));
    }

    // 6. Validate Cipher layers
    let expected_layers = vec!["chacha20-poly1305".to_string(), "aes-256-gcm".to_string()];
    if envelope.cipher.layers != expected_layers {
        return Err(OpkeError::Envelope(format!(
            "Unsupported cipher layers: {:?}. Expected {:?}",
            envelope.cipher.layers, expected_layers
        )));
    }

    // 7. Validate decoded cryptographic fields and bounds
    let _ = envelope.get_decoded_bytes()?;

    Ok(envelope)
}
