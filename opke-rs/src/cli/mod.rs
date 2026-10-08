//! Command-line interface and wizard modules.

pub mod args;
pub mod cmd_benchmark;
pub mod cmd_decrypt;
pub mod cmd_encrypt;
pub mod cmd_inspect;
pub mod wizard;

pub use args::{Cli, Commands};
