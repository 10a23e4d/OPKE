//! Error types for OPKE v3.0.

use std::fmt;

#[derive(Debug)]
pub enum OpkeError {
    Crypto(String),
    Authentication(String),
    Envelope(String),
    Validation(String),
    ResourceLimit(String),
    Io(std::io::Error),
}

impl fmt::Display for OpkeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpkeError::Crypto(msg) => write!(f, "Cryptographic error: {}", msg),
            OpkeError::Authentication(msg) => write!(f, "Authentication error: {}", msg),
            OpkeError::Envelope(msg) => write!(f, "Envelope error: {}", msg),
            OpkeError::Validation(msg) => write!(f, "Validation error: {}", msg),
            OpkeError::ResourceLimit(msg) => write!(f, "Resource limit error: {}", msg),
            OpkeError::Io(err) => write!(f, "I/O error: {}", err),
        }
    }
}

impl std::error::Error for OpkeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OpkeError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for OpkeError {
    fn from(err: std::io::Error) -> Self {
        OpkeError::Io(err)
    }
}

impl From<serde_json::Error> for OpkeError {
    fn from(err: serde_json::Error) -> Self {
        OpkeError::Envelope(err.to_string())
    }
}

impl From<base64::DecodeError> for OpkeError {
    fn from(err: base64::DecodeError) -> Self {
        OpkeError::Envelope(format!("Base64 decoding failed: {}", err))
    }
}
