//! Memory inspection utilities to prevent system freeze / OOM DoS attacks.

use sysinfo::System;

/// Returns available physical system RAM in KiB, if determinable.
pub fn get_available_memory_kib() -> Option<u64> {
    let mut sys = System::new();
    sys.refresh_memory();
    let avail_bytes = sys.available_memory();
    if avail_bytes > 0 {
        Some(avail_bytes / 1024)
    } else {
        None
    }
}
