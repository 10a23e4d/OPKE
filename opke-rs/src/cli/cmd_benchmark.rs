//! Handler for `opke benchmark` subcommand.

use std::time::Instant;

use crate::core::{
    derive_key_and_split, get_profile, MAX_M_KIB, MAX_P, MAX_T, MIN_M_KIB, MIN_P, MIN_T,
};
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

    if m_kib < MIN_M_KIB {
        return Err(OpkeError::Validation(format!(
            "Invalid memory cost: {} KiB (must be at least {} KiB)",
            m_kib, MIN_M_KIB
        )));
    }
    if m_kib > MAX_M_KIB {
        return Err(OpkeError::Validation(format!(
            "Invalid memory cost: {} KiB (exceeds maximum allowed {} KiB)",
            m_kib, MAX_M_KIB
        )));
    }
    if !(MIN_P..=MAX_P).contains(&p) {
        return Err(OpkeError::Validation(format!(
            "Invalid parallelism: {} (must be between {} and {})",
            p, MIN_P, MAX_P
        )));
    }
    if m_kib < 8 * p {
        return Err(OpkeError::Validation(format!(
            "Invalid memory cost: {} KiB (Argon2 requires m >= 8 * p = {} KiB)",
            m_kib,
            8 * p
        )));
    }
    if !(MIN_T..=MAX_T).contains(&t) {
        return Err(OpkeError::Validation(format!(
            "Invalid time cost: {} (must be between {} and {})",
            t, MIN_T, MAX_T
        )));
    }

    // Check available RAM to prevent system freeze / OOM (VULN-14)
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
