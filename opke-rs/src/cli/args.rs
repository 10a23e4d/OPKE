//! CLI argument definitions using Clap.

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "opke",
    version = crate::VERSION,
    about = "OPKE (Offline Paper-Key Encryptor) v3.0 - Offline Paper Cold Storage Key Encryptor",
    long_about = "OPKE is an ultra-secure offline tool for encrypting VeraCrypt passwords, password manager emergency kits, and master keys using high-cost Argon2id KDF and dual AEAD cascade encryption (ChaCha20-Poly1305 + AES-256-GCM)."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt secret plaintext into paper key envelope and QR code
    Encrypt(EncryptArgs),
    /// Decrypt paper key envelope to retrieve secret plaintext
    Decrypt(DecryptArgs),
    /// Inspect envelope metadata without prompting for passphrase
    Inspect(InspectArgs),
    /// Benchmark Argon2id KDF on your system
    Benchmark(BenchmarkArgs),
}

#[derive(Args, Debug)]
pub struct EncryptArgs {
    /// Secret plaintext to encrypt (Rejected for security: use interactive prompt, pipe, or -i)
    pub secret: Option<String>,

    /// Read secret plaintext from a file
    #[arg(short = 'i', long = "input-file")]
    pub input_file: Option<String>,

    /// Passphrase to derive encryption keys (Rejected for security: use interactive prompt or OPKE_PASSPHRASE)
    #[arg(short = 'p', long = "passphrase")]
    pub passphrase: Option<String>,

    /// Output file path for encrypted envelope
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Predefined KDF profile: 'production' (8 GiB, 64 iters), 'moderate' (1 GiB, 16 iters), 'fast' (64 MiB, 2 iters)
    #[arg(long = "profile", default_value = "production")]
    pub profile: String,

    /// Override Argon2id memory cost in KiB
    #[arg(long = "mem")]
    pub mem: Option<u32>,

    /// Override Argon2id time cost (iterations)
    #[arg(long = "time")]
    pub time: Option<u32>,

    /// Override Argon2id parallelism (threads)
    #[arg(long = "threads")]
    pub threads: Option<u32>,

    /// Path to save QR code image (.png or .svg)
    #[arg(long = "qr")]
    pub qr: Option<String>,

    /// Display QR code directly in terminal using Unicode half-blocks
    #[arg(long = "qr-term")]
    pub qr_term: bool,

    /// Output single-line raw Base64 instead of PEM format
    #[arg(long = "raw")]
    pub raw: bool,

    /// Interactive multi-line secret entry mode
    #[arg(long = "multiline")]
    pub multiline: bool,

    /// Bypass available memory check and force execution
    #[arg(long = "force")]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct DecryptArgs {
    /// Encrypted envelope string or Base64 payload
    pub input: Option<String>,

    /// Read encrypted envelope from a file
    #[arg(short = 'i', long = "input-file")]
    pub input_file: Option<String>,

    /// Passphrase to decrypt envelope (Rejected for security: use interactive prompt or OPKE_PASSPHRASE)
    #[arg(short = 'p', long = "passphrase")]
    pub passphrase: Option<String>,

    /// Output file path for decrypted secret plaintext
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Maximum allowed memory cost in KiB (DoS protection)
    #[arg(long = "max-mem", allow_hyphen_values = true)]
    pub max_mem: Option<i64>,

    /// Maximum allowed time cost (iterations) (DoS protection)
    #[arg(long = "max-time", allow_hyphen_values = true)]
    pub max_time: Option<i64>,

    /// Maximum allowed parallelism (threads) (DoS protection)
    #[arg(long = "max-threads", allow_hyphen_values = true)]
    pub max_threads: Option<i64>,

    /// Bypass available memory check and force execution
    #[arg(long = "force")]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Encrypted envelope string or Base64 payload
    pub input: Option<String>,

    /// Read encrypted envelope from a file
    #[arg(short = 'i', long = "input-file")]
    pub input_file: Option<String>,
}

#[derive(Args, Debug)]
pub struct BenchmarkArgs {
    /// Predefined KDF profile to benchmark: 'production', 'moderate', or 'fast'
    #[arg(long = "profile", default_value = "production")]
    pub profile: String,

    /// Override Argon2id memory cost in KiB
    #[arg(long = "mem")]
    pub mem: Option<u32>,

    /// Override Argon2id time cost (iterations)
    #[arg(long = "time")]
    pub time: Option<u32>,

    /// Override Argon2id parallelism (threads)
    #[arg(long = "threads")]
    pub threads: Option<u32>,

    /// Bypass available memory check and force execution
    #[arg(long = "force")]
    pub force: bool,
}
