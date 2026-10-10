//! Envelope data models for OPKE v2 and v3.

use serde::{Deserialize, Serialize};

use crate::core::validate_kdf_params;
use crate::error::OpkeError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    pub name: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String, // Base64 16 bytes
}

impl KdfParams {
    pub fn validate(&self) -> Result<(), OpkeError> {
        validate_kdf_params(self.m_kib, self.t, self.p)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CipherParams {
    pub layers: Vec<String>,
    pub nonce_chacha: String, // Base64 12 bytes
    pub nonce_aes: String,    // Base64 12 bytes
    pub tag_aes: String,      // Base64 16 bytes
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OPKEEnvelope {
    pub v: u32,
    pub kdf: KdfParams,
    pub cipher: CipherParams,
    pub data: String, // Base64 ciphertext
}
