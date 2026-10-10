//! OPKE v3.1 (Offline Paper-Key Encryptor) Core Library.

pub mod cli;
pub mod core;
pub mod envelope;
pub mod error;
pub mod qr;
pub mod security;

pub use error::OpkeError;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
