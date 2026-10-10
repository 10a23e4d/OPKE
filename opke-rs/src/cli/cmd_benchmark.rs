//! Handler for `opke benchmark` subcommand.

use std::time::Instant;

use crate::core::{derive_key_and_split, get_profile, validate_kdf_params};
use crate::error::OpkeError;
use crate::security::get_available_memory_kib;

use super::args::BenchmarkArgs;

pub fn execute(args: BenchmarkArgs) -> Result<(), OpkeError> {
    let profile = match get_profile(&args.profile) {
        Some(p) => p,
        None => {
            return Err(OpkeError::Validation(format!(
                "Unknown profile: '{}'. Choose from 'production', 'moderate', or 'fast'.",
                args.profile
            )));
        }
    };

    let m_kib = args.mem.unwrap_or(profile.m_kib);
    let t = args.time.unwrap_or(profile.t);
    let p = args.threads.unwrap_or(profile.p);

    validate_kdf_params(m_kib, t, p)?;

    // Check available RAM to prevent system freeze / OOM DoS
    if let Some(avail_kib) = get_available_memory_kib() {
        if (m_kib as u64) > avail_kib && !args.force {
            let m_gib = (m_kib as f64) / 1024.0 / 1024.0;
            let avail_gib = (avail_kib as f64) / 1024.0 / 1024.0;
            return Err(OpkeError::ResourceLimit(format!(
                "Benchmark requires {} KiB ({:.2} GiB) RAM, but only ~{} KiB ({:.2} GiB) is available.\nBenchmark aborted to prevent system freeze / OOM. Use --force to override.",
                m_kib, m_gib, avail_kib, avail_gib
            )));
        }
    }

    println!("============================================================");
    println!("             OPKE Argon2id KDF Benchmark                    ");
    println!("============================================================");
    println!("Profile          : {}", profile.name);
    println!(
        "Memory (m)       : {} KiB ({:.2} GiB)",
        m_kib,
        (m_kib as f64) / 1024.0 / 1024.0
    );
    println!("Iterations (t)   : {}", t);
    println!("Threads (p)      : {}", p);
    println!("------------------------------------------------------------");
    println!("[*] Starting benchmark on current hardware...");

    let test_passphrase = b"BenchmarkPassphrase123!";
    let test_salt = [99u8; 16];

    let t0 = Instant::now();
    let (key_chacha, key_aes) = derive_key_and_split(test_passphrase, &test_salt, m_kib, t, p)?;
    let elapsed = t0.elapsed();

    assert_ne!(key_chacha.as_slice(), key_aes.as_slice());

    println!("[+] Benchmark completed successfully!");
    println!(
        "    Elapsed Time : {:.2} seconds ({:.1} ms)",
        elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1000.0
    );
    println!("============================================================");

    Ok(())
}
