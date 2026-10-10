//! Process memory and command line scrubbing utilities.

#[cfg(windows)]
use zeroize::Zeroizing;

#[cfg(windows)]
extern "system" {
    fn GetCommandLineW() -> *mut u16;
}

/// Scrubs sensitive target strings from native process command line memory (Linux procfs and Windows PEB).
pub fn scrub_cmdline_targets(targets: &[&str]) {
    if targets.is_empty() {
        return;
    }

    #[cfg(target_os = "linux")]
    {
        // Linux: wipe target strings from /proc/self/cmdline via arg_start..arg_end
        if let Ok(content) = std::fs::read_to_string("/proc/self/stat") {
            if let Some(idx) = content.rfind(')') {
                let fields: Vec<&str> = content[idx + 2..].split_whitespace().collect();
                if fields.len() > 46 {
                    if let (Ok(arg_start), Ok(arg_end)) =
                        (fields[45].parse::<usize>(), fields[46].parse::<usize>())
                    {
                        if arg_end > arg_start {
                            let len = arg_end - arg_start;
                            let slice = unsafe {
                                std::slice::from_raw_parts_mut(arg_start as *mut u8, len)
                            };
                            for t in targets {
                                if t.is_empty() {
                                    continue;
                                }
                                let needle = t.as_bytes();
                                let mut pos = 0;
                                while pos + needle.len() <= slice.len() {
                                    if &slice[pos..pos + needle.len()] == needle {
                                        for b in &mut slice[pos..pos + needle.len()] {
                                            *b = 0;
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

        unsafe {
            let proc_name = b"opke\0";
            libc::prctl(15, proc_name.as_ptr() as usize, 0, 0, 0); // PR_SET_NAME
        }
    }

    #[cfg(windows)]
    {
        // Windows: GetCommandLineW() returns the mutable CommandLine.Buffer in PEB ProcessParameters
        let cmd_ptr = unsafe { GetCommandLineW() };
        if !cmd_ptr.is_null() {
            let mut len = 0usize;
            unsafe {
                while *cmd_ptr.add(len) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts_mut(cmd_ptr, len);
                for t in targets {
                    if t.is_empty() {
                        continue;
                    }
                    let needle: Zeroizing<Vec<u16>> = Zeroizing::new(t.encode_utf16().collect());
                    let mut pos = 0;
                    while pos + needle.len() <= slice.len() {
                        if &slice[pos..pos + needle.len()] == needle.as_slice() {
                            for ch in &mut slice[pos..pos + needle.len()] {
                                *ch = 0;
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
