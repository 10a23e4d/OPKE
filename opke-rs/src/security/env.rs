//! Environment variable security utilities.

use zeroize::Zeroizing;

use crate::core::MAX_PASSPHRASE_BYTES;
use crate::error::OpkeError;

/// Retrieves and immediately scrubs `OPKE_PASSPHRASE` from environment.
pub fn scrub_env_passphrase() -> Result<Option<Zeroizing<String>>, OpkeError> {
    if let Ok(val) = std::env::var("OPKE_PASSPHRASE") {
        std::env::remove_var("OPKE_PASSPHRASE");
        if val.is_empty() {
            return Err(OpkeError::Validation(
                "Passphrase cannot be empty (OPKE_PASSPHRASE is empty).".into(),
            ));
        }
        if val.len() > MAX_PASSPHRASE_BYTES {
            return Err(OpkeError::Validation(format!(
                "Passphrase exceeds maximum allowed length ({} bytes).",
                MAX_PASSPHRASE_BYTES
            )));
        }
        return Ok(Some(Zeroizing::new(val)));
    }
    Ok(None)
}
