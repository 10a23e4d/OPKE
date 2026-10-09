//! Memory inspection utilities to prevent system freeze / OOM DoS attacks.
//! Supports container cgroup v1 and v2 limits alongside host physical RAM detection.

use sysinfo::System;

/// Returns available physical or container memory in KiB, taking into account cgroups (Docker / Kubernetes).
pub fn get_available_memory_kib() -> Option<u64> {
    #[allow(unused_mut)]
    let mut cgroup_kib: Option<u64> = None;

    #[cfg(target_os = "linux")]
    {
        // 1. Check Linux cgroups v2 (Docker / K8s / systemd)
        if let Ok(val) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
            let trimmed = val.trim();
            if let Ok(limit_bytes) = trimmed.parse::<u64>() {
                let curr_bytes = std::fs::read_to_string("/sys/fs/cgroup/memory.current")
                    .ok()
                    .and_then(|c| c.trim().parse::<u64>().ok())
                    .unwrap_or(0);
                cgroup_kib = Some(limit_bytes.saturating_sub(curr_bytes) / 1024);
            }
        }

        // 2. Check Linux cgroups v1 if cgroups v2 is not active
        if cgroup_kib.is_none() {
            if let Ok(val) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes") {
                let trimmed = val.trim();
                if let Ok(lim) = trimmed.parse::<u64>() {
                    // Filter out unbounded / default maximum values (e.g. 9223372036854771712)
                    if lim < (1u64 << 60) {
                        let curr = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes")
                            .ok()
                            .and_then(|u| u.trim().parse::<u64>().ok())
                            .unwrap_or(0);
                        cgroup_kib = Some(lim.saturating_sub(curr) / 1024);
                    }
                }
            }
        }
    }

    let mut sys = System::new();
    sys.refresh_memory();
    let host_avail_kib = {
        let avail_bytes = sys.available_memory();
        if avail_bytes > 0 {
            Some(avail_bytes / 1024)
        } else {
            None
        }
    };

    match (cgroup_kib, host_avail_kib) {
        (Some(cg), Some(host)) => Some(cg.min(host)),
        (Some(cg), None) => Some(cg),
        (None, Some(host)) => Some(host),
        (None, None) => None,
    }
}
