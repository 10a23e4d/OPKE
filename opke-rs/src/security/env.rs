//! Environment variable security utilities.

use zeroize::Zeroizing;

use crate::core::MAX_PASSPHRASE_BYTES;
use crate::error::OpkeError;

/// Retrieves and immediately scrubs `OPKE_PASSPHRASE` from environment, libc, and procfs memory.
pub fn scrub_env_passphrase() -> Result<Option<Zeroizing<String>>, OpkeError> {
    if let Ok(val) = std::env::var("OPKE_PASSPHRASE") {
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
                        if let (Ok(env_start), Ok(env_end)) = (fields[47].parse::<usize>(), fields[48].parse::<usize>()) {
                            if env_end > env_start {
                                let len = env_end - env_start;
                                let slice = unsafe { std::slice::from_raw_parts_mut(env_start as *mut u8, len) };
                                let targets = [
                                    format!("OPKE_PASSPHRASE={}", val).into_bytes(),
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
        return Ok(Some(Zeroizing::new(val)));
    }
    Ok(None)
}
