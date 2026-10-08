//! Security utilities: memory inspection, secure file I/O, prompt handling, and env scrubbing.

pub mod env;
pub mod file;
pub mod memory;
pub mod prompt;

pub use env::scrub_env_passphrase;
pub use file::{read_secure_file, write_secure_file};
pub use memory::get_available_memory_kib;
pub use prompt::{prompt_passphrase, prompt_secret};
