//! Command-line interface and wizard modules.

pub mod args;
pub mod cmd_benchmark;
pub mod cmd_decrypt;
pub mod cmd_encrypt;
pub mod cmd_inspect;
pub mod wizard;

pub use args::{Cli, Commands};

use crate::error::OpkeError;
use crate::security::scrub_cmdline_targets;
use zeroize::Zeroize;

/// Rejects and scrubs sensitive arguments passed via CLI flags.
pub fn reject_sensitive_arg(
    arg: &mut Option<String>,
    kind: &str,
    guidance: &str,
) -> Result<(), OpkeError> {
    if let Some(mut val) = arg.take() {
        scrub_cmdline_targets(&[&val]);
        val.zeroize();
        return Err(OpkeError::Validation(format!(
            "Passing {} as command-line arguments is strictly prohibited for security.\n{}",
            kind, guidance
        )));
    }
    Ok(())
}
