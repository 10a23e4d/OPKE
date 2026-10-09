//! Core cryptographic primitives for OPKE v3.0.

pub mod cascade;
pub mod kdf;
pub mod profiles;

pub use cascade::{
    decrypt_cascade, encrypt_cascade, MAX_CIPHERTEXT_BYTES, MAX_SECRET_BYTES, MIN_CIPHERTEXT_BYTES,
    NONCE_LEN, SUBKEY_LEN, TAG_LEN,
};
pub use kdf::{
    derive_key_and_split, KEY_LEN, MAX_M_KIB, MAX_P, MAX_PASSPHRASE_BYTES, MAX_T, MIN_M_KIB, MIN_P,
    MIN_T, SALT_LEN,
};
pub use profiles::{
    get_profile, KdfProfile, PROFILE_FAST, PROFILE_MODERATE, PROFILE_PRODUCTION, PROFILE_STANDARD,
    PROFILE_TEST,
};
