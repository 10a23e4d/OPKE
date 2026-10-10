//! Memory inspection utilities to prevent system freeze / OOM DoS attacks.
//! Supports container cgroup v1 and v2 limits alongside host physical RAM detection.

use crate::error::OpkeError;
use sysinfo::{MemoryRefreshKind, RefreshKind, System};

#[cfg(windows)]
extern "system" {
    fn VirtualLock(lpAddress: *const std::ffi::c_void, dwSize: usize) -> i32;
    fn VirtualUnlock(lpAddress: *const std::ffi::c_void, dwSize: usize) -> i32;
    fn GetCurrentProcess() -> *mut std::ffi::c_void;
    fn GetProcessWorkingSetSize(
        hProcess: *mut std::ffi::c_void,
        lpMinimumWorkingSetSize: *mut usize,
        lpMaximumWorkingSetSize: *mut usize,
    ) -> i32;
    fn SetProcessWorkingSetSize(
        hProcess: *mut std::ffi::c_void,
        dwMinimumWorkingSetSize: usize,
        dwMaximumWorkingSetSize: usize,
    ) -> i32;
    fn QueryInformationJobObject(
        hJob: *mut std::ffi::c_void,
        JobObjectInformationClass: i32,
        lpJobObjectInformation: *mut std::ffi::c_void,
        cbJobObjectInformationLength: u32,
        lpReturnLength: *mut u32,
    ) -> i32;
}

#[cfg(windows)]
#[repr(C)]
struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    per_process_user_time_limit: i64,
    per_job_user_time_limit: i64,
    limit_flags: u32,
    minimum_working_set_size: usize,
    maximum_working_set_size: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

#[cfg(windows)]
#[repr(C)]
struct IO_COUNTERS {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

#[cfg(windows)]
#[repr(C)]
struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    io_info: IO_COUNTERS,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

/// Locks memory page(s) into physical RAM to prevent swapping/paging out to disk (VULN-54).
/// Returns true if successfully locked by OS.
pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
    if len == 0 || ptr.is_null() {
        return true;
    }
    #[cfg(miri)]
    {
        true
    }
    #[cfg(all(not(miri), windows))]
    unsafe {
        let res = VirtualLock(ptr as *const _, len);
        if res != 0 {
            return true;
        }
        // If quota exceeded, attempt to expand process working set size and retry
        let proc = GetCurrentProcess();
        let mut min_ws = 0usize;
        let mut max_ws = 0usize;
        if GetProcessWorkingSetSize(proc, &mut min_ws, &mut max_ws) != 0 {
            let new_min = min_ws.saturating_add(len);
            let new_max = max_ws.saturating_add(len.saturating_mul(2));
            let _ = SetProcessWorkingSetSize(proc, new_min, new_max);
            return VirtualLock(ptr as *const _, len) != 0;
        }
        false
    }
    #[cfg(all(not(miri), unix))]
    unsafe {
        libc::mlock(ptr as *const _, len) == 0
    }
}

/// Unlocks memory page(s) previously locked into physical RAM.
pub fn unlock_memory(ptr: *const u8, len: usize) {
    if len == 0 || ptr.is_null() {
        return;
    }
    #[cfg(miri)]
    {}
    #[cfg(all(not(miri), windows))]
    unsafe {
        let _ = VirtualUnlock(ptr as *const _, len);
    }
    #[cfg(all(not(miri), unix))]
    unsafe {
        let _ = libc::munlock(ptr as *const _, len);
    }
}

/// RAII Guard that locks a sensitive buffer into RAM on creation and unlocks it on drop.
pub struct MemoryLockGuard<'a> {
    ptr: *const u8,
    len: usize,
    locked: bool,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> MemoryLockGuard<'a> {
    pub fn new(slice: &'a [u8]) -> Result<Self, OpkeError> {
        let locked = lock_memory(slice.as_ptr(), slice.len());
        if !locked && !slice.is_empty() {
            return Err(OpkeError::ResourceLimit(
                "Failed to lock sensitive memory into RAM (VirtualLock/mlock). Memory could be swapped to disk.".into()
            ));
        }
        Ok(Self {
            ptr: slice.as_ptr(),
            len: slice.len(),
            locked,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn try_lock(slice: &'a [u8]) -> Self {
        let locked = lock_memory(slice.as_ptr(), slice.len());
        Self {
            ptr: slice.as_ptr(),
            len: slice.len(),
            locked,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<'a> Drop for MemoryLockGuard<'a> {
    fn drop(&mut self) {
        if self.locked {
            unlock_memory(self.ptr, self.len);
        }
    }
}

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
            if let Ok(val) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
            {
                let trimmed = val.trim();
                if let Ok(lim) = trimmed.parse::<u64>() {
                    // Filter out unbounded / default maximum values (e.g. 9223372036854771712)
                    if lim < (1u64 << 60) {
                        let curr =
                            std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes")
                                .ok()
                                .and_then(|u| u.trim().parse::<u64>().ok())
                                .unwrap_or(0);
                        cgroup_kib = Some(lim.saturating_sub(curr) / 1024);
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // Check Windows Job Object memory limits (VULN-43)
        let mut job_info = std::mem::MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::zeroed();
        let mut ret_len = 0u32;
        let ok = unsafe {
            QueryInformationJobObject(
                std::ptr::null_mut(),
                9, // JobObjectExtendedLimitInformation
                job_info.as_mut_ptr() as *mut _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                &mut ret_len,
            )
        };
        if ok != 0 {
            let info = unsafe { job_info.assume_init() };
            let flags = info.basic_limit_information.limit_flags;
            let mut job_lim = 0usize;
            if (flags & 0x00000100) != 0 && info.process_memory_limit > 0 {
                job_lim = info
                    .process_memory_limit
                    .saturating_sub(info.peak_process_memory_used);
            }
            if (flags & 0x00000200) != 0 && info.job_memory_limit > 0 {
                let job_used = info.peak_job_memory_used.max(info.peak_process_memory_used);
                let avail = info.job_memory_limit.saturating_sub(job_used);
                if job_lim == 0 || avail < job_lim {
                    job_lim = avail;
                }
            }
            if job_lim > 0 {
                cgroup_kib = Some((job_lim / 1024) as u64);
            }
        }
    }

    // Lightweight system memory refresh (VULN-71)
    let sys = System::new_with_specifics(
        RefreshKind::nothing().with_memory(MemoryRefreshKind::everything()),
    );
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
