//! Environment variable security utilities.

use zeroize::Zeroizing;

use crate::core::MAX_PASSPHRASE_BYTES;
use crate::error::OpkeError;

#[cfg(windows)]
extern "system" {
    fn GetEnvironmentStringsW() -> *mut u16;
    fn FreeEnvironmentStringsW(penv: *mut u16) -> i32;
}

/// Retrieves and immediately scrubs `OPKE_PASSPHRASE` from environment, libc, and procfs/PEB memory.
pub fn scrub_env_passphrase() -> Result<Option<Zeroizing<String>>, OpkeError> {
    if let Ok(raw_val) = std::env::var("OPKE_PASSPHRASE") {
        // VULN-37: Wrap in Zeroizing immediately so any early return drops and zeroes the buffer
        let val = Zeroizing::new(raw_val);
        std::env::remove_var("OPKE_PASSPHRASE");

        #[cfg(target_os = "linux")]
        {
            unsafe {
                libc::unsetenv(b"OPKE_PASSPHRASE\0".as_ptr() as *const libc::c_char);
            }

            // Wipe from /proc/self/environ physical memory region via /proc/self/stat
            if let Ok(content) = std::fs::read_to_string("/proc/self/stat") {
                if let Some(idx) = content.rfind(')') {
                    let fields: Vec<&str> = content[idx + 2..].split_whitespace().collect();
                    if fields.len() > 48 {
                        if let (Ok(env_start), Ok(env_end)) =
                            (fields[47].parse::<usize>(), fields[48].parse::<usize>())
                        {
                            if env_end > env_start {
                                let len = env_end - env_start;
                                let slice = unsafe {
                                    std::slice::from_raw_parts_mut(env_start as *mut u8, len)
                                };
                                let targets = [
                                    format!("OPKE_PASSPHRASE={}", &*val).into_bytes(),
                                    val.as_bytes().to_vec(),
                                ];
                                for needle in &targets {
                                    if needle.is_empty() {
                                        continue;
                                    }
                                    let mut pos = 0;
                                    while pos + needle.len() <= slice.len() {
                                        if &slice[pos..pos + needle.len()] == needle.as_slice() {
                                            for b in &mut slice[pos..pos + needle.len()] {
                                                *b = b'X';
                                            }
                                            pos += needle.len();
                                        } else {
                                            pos += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            // VULN-35: Wipe OPKE_PASSPHRASE from Windows PEB Environment block
            unsafe {
                let env_ptr = GetEnvironmentStringsW();
                if !env_ptr.is_null() {
                    let mut curr = env_ptr;
                    while *curr != 0 {
                        let mut len = 0usize;
                        while *curr.add(len) != 0 {
                            len += 1;
                        }
                        let slice = std::slice::from_raw_parts_mut(curr, len);
                        let targets = [format!("OPKE_PASSPHRASE={}", *val), (*val).clone()];
                        for target in &targets {
                            if target.is_empty() {
                                continue;
                            }
                            let needle: Vec<u16> = target.encode_utf16().collect();
                            let mut pos = 0;
                            while pos + needle.len() <= slice.len() {
                                if &slice[pos..pos + needle.len()] == needle.as_slice() {
                                    for ch in &mut slice[pos..pos + needle.len()] {
                                        *ch = 'X' as u16;
                                    }
                                    pos += needle.len();
                                } else {
                                    pos += 1;
                                }
                            }
                        }
                        curr = curr.add(len + 1);
                    }
                    FreeEnvironmentStringsW(env_ptr);
                }
            }
        }

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
        return Ok(Some(val));
    }
    Ok(None)
}
