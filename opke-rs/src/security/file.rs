//! Secure file operations preventing symlink attacks, hardlink attacks, TOCTOU races,
//! permission leakage, and incomplete file residue.

use std::fs::OpenOptions;
#[cfg(windows)]
use std::io::{self, IsTerminal};
use std::io::{Read, Seek, Write};
use std::path::Path;
use zeroize::Zeroizing;

use crate::error::OpkeError;

#[cfg(windows)]
#[allow(non_snake_case)]
#[repr(C)]
struct BY_HANDLE_FILE_INFORMATION {
    dwFileAttributes: u32,
    ftCreationTime: [u32; 2],
    ftLastAccessTime: [u32; 2],
    ftLastWriteTime: [u32; 2],
    dwVolumeSerialNumber: u32,
    nFileSizeHigh: u32,
    nFileSizeLow: u32,
    nNumberOfLinks: u32,
    nFileIndexHigh: u32,
    nFileIndexLow: u32,
}

#[cfg(windows)]
extern "system" {
    fn GetFileInformationByHandle(
        hFile: *mut std::ffi::c_void,
        lpFileInformation: *mut BY_HANDLE_FILE_INFORMATION,
    ) -> i32;
    fn LocalFree(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    fn LockFile(
        hFile: *mut std::ffi::c_void,
        dwFileOffsetLow: u32,
        dwFileOffsetHigh: u32,
        nNumberOfBytesToLockLow: u32,
        nNumberOfBytesToLockHigh: u32,
    ) -> i32;
    fn UnlockFile(
        hFile: *mut std::ffi::c_void,
        dwFileOffsetLow: u32,
        dwFileOffsetHigh: u32,
        nNumberOfBytesToLockLow: u32,
        nNumberOfBytesToLockHigh: u32,
    ) -> i32;
    fn GetCurrentProcess() -> *mut std::ffi::c_void;
    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
}

#[cfg(windows)]
#[link(name = "advapi32")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        StringSecurityDescriptor: *const u16,
        StringSDRevision: u32,
        SecurityDescriptor: *mut *mut std::ffi::c_void,
        SecurityDescriptorSize: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        pSecurityDescriptor: *mut std::ffi::c_void,
        lpbDaclPresent: *mut i32,
        pDacl: *mut *mut std::ffi::c_void,
        lpbDaclDefaulted: *mut i32,
    ) -> i32;
    fn GetSecurityInfo(
        handle: *mut std::ffi::c_void,
        ObjectType: i32,
        SecurityInfo: u32,
        ppsidOwner: *mut *mut std::ffi::c_void,
        ppsidGroup: *mut *mut std::ffi::c_void,
        ppDacl: *mut *mut std::ffi::c_void,
        ppSacl: *mut *mut std::ffi::c_void,
        ppSecurityDescriptor: *mut *mut std::ffi::c_void,
    ) -> u32;
    fn SetSecurityInfo(
        handle: *mut std::ffi::c_void,
        ObjectType: i32,
        SecurityInfo: u32,
        psidOwner: *mut std::ffi::c_void,
        psidGroup: *mut std::ffi::c_void,
        pDacl: *mut std::ffi::c_void,
        pSacl: *mut std::ffi::c_void,
    ) -> u32;
    fn OpenProcessToken(
        ProcessHandle: *mut std::ffi::c_void,
        DesiredAccess: u32,
        TokenHandle: *mut *mut std::ffi::c_void,
    ) -> i32;
    fn GetTokenInformation(
        TokenHandle: *mut std::ffi::c_void,
        TokenInformationClass: i32,
        TokenInformation: *mut std::ffi::c_void,
        TokenInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
    fn EqualSid(pSid1: *mut std::ffi::c_void, pSid2: *mut std::ffi::c_void) -> i32;
    fn CheckTokenMembership(
        TokenHandle: *mut std::ffi::c_void,
        SidToCheck: *mut std::ffi::c_void,
        IsMember: *mut i32,
    ) -> i32;
}

/// Validates file path against NTFS Alternate Data Streams (ADS) and Windows reserved device names (VULN-39, VULN-40).
fn validate_file_path(p: &Path) -> Result<(), OpkeError> {
    let s = p.to_string_lossy();
    if s.is_empty() {
        return Err(OpkeError::Validation("Invalid file path.".into()));
    }

    // 1. Check for NTFS Alternate Data Streams (ADS: filename:stream)
    // Allow standard Windows drive specifier (e.g., C:\ or D:/)
    let rest_path =
        if s.len() >= 2 && s.as_bytes()[1] == b':' && s.as_bytes()[0].is_ascii_alphabetic() {
            &s[2..]
        } else {
            &s[..]
        };
    if rest_path.contains(':') {
        return Err(OpkeError::Validation(format!(
            "NTFS Alternate Data Streams (ADS) are prohibited for security: {}",
            p.display()
        )));
    }

    // 2. Check for Windows reserved device names (CON, NUL, AUX, PRN, COM1-9, LPT1-9)
    if let Some(file_name) = p.file_name().and_then(|f| f.to_str()) {
        let stem = std::path::Path::new(file_name)
            .file_stem()
            .and_then(|st| st.to_str())
            .unwrap_or(file_name)
            .to_ascii_uppercase();

        let reserved = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        if reserved.contains(&stem.as_str()) {
            return Err(OpkeError::Validation(format!(
                "Windows reserved device names are prohibited for security: {}",
                p.display()
            )));
        }
    }

    Ok(())
}

/// Reads a regular file into a zeroized byte buffer, strictly refusing symlinks, FIFOs, and non-regular files.
pub fn read_secure_file(
    path: impl AsRef<Path>,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, OpkeError> {
    let p = path.as_ref();
    validate_file_path(p)?;

    if !p.exists() {
        return Err(OpkeError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", p.display()),
        )));
    }

    // Pre-check for symlinks and non-regular files to fail fast
    let sym_meta = std::fs::symlink_metadata(p)?;
    if sym_meta.file_type().is_symlink() {
        return Err(OpkeError::Validation(format!(
            "Refusing to read symlink for security: {}",
            p.display()
        )));
    }
    if !sym_meta.is_file() {
        return Err(OpkeError::Validation(format!(
            "Refusing to read non-regular file for security: {}",
            p.display()
        )));
    }

    let file_len = sym_meta.len() as usize;
    if file_len > max_bytes {
        return Err(OpkeError::Validation(format!(
            "File '{}' exceeds maximum allowed size ({} bytes).",
            p.display(),
            max_bytes
        )));
    }

    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0x00000001 | 0x00000002 | 0x00000004); // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    }

    let mut file = options.open(p)?;

    // Verify metadata on the opened file descriptor to prevent TOCTOU race
    let fd_meta = file.metadata()?;
    if !fd_meta.is_file() {
        return Err(OpkeError::Validation(format!(
            "Refusing to read non-regular file for security: {}",
            p.display()
        )));
    }

    // Fully preallocate buffer with exact file length to eliminate reallocation plaintext leak (VULN-28)
    let mut buf = Zeroizing::new(Vec::with_capacity(file_len));
    let mut chunk = Zeroizing::new([0u8; 65536]);

    loop {
        let n = file.read(&mut *chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > max_bytes {
            return Err(OpkeError::Validation(format!(
                "File '{}' exceeds maximum allowed size ({} bytes).",
                p.display(),
                max_bytes
            )));
        }
    }

    Ok(buf)
}

/// Safely writes data to a file with owner-only permissions (0600 on Unix, restricted DACL on Windows).
/// Refuses symlinks, hardlinks, and files owned by other users.
pub fn write_secure_file(path: impl AsRef<Path>, data: &[u8]) -> Result<(), OpkeError> {
    write_secure_file_with_options(path, data, false)
}

/// Safely writes data with an explicit `--force` override for environments where ACLs cannot be set.
pub fn write_secure_file_with_options(
    path: impl AsRef<Path>,
    data: &[u8],
    force: bool,
) -> Result<(), OpkeError> {
    let p = path.as_ref();
    let _ = force;
    validate_file_path(p)?;

    let existed_before = std::fs::symlink_metadata(p).is_ok();

    if existed_before {
        let sym_meta = std::fs::symlink_metadata(p)?;
        if sym_meta.file_type().is_symlink() {
            return Err(OpkeError::Validation(format!(
                "Refusing to write to symlink for security: {}",
                p.display()
            )));
        }
        if !sym_meta.is_file() {
            return Err(OpkeError::Validation(format!(
                "Refusing to write to non-regular file for security: {}",
                p.display()
            )));
        }
    }

    let mut options = OpenOptions::new();
    options.write(true);
    if existed_before {
        options.create(true);
    } else {
        // VULN-57: Use CREATE_NEW for new files to prevent TOCTOU race
        options.create_new(true);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        options.mode(0o600);
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // GENERIC_READ (0x80000000) | GENERIC_WRITE (0x40000000) | WRITE_DAC (0x00040000)
        options.access_mode(0x80000000 | 0x40000000 | 0x00040000);
        options.share_mode(0x00000001 | 0x00000002 | 0x00000004); // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    }

    let mut file = options.open(p)?;

    // Validate the opened file descriptor directly
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(OpkeError::Validation(format!(
            "Refusing to write to non-regular file for security: {}",
            p.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            return Err(OpkeError::Validation(format!(
                "Refusing to write to hardlink target for security: {}",
                p.display()
            )));
        }

        let current_uid = unsafe { libc::getuid() };
        if meta.uid() != current_uid {
            return Err(OpkeError::Validation(format!(
                "Refusing to write to file owned by another user (UID {} != {}): {}",
                meta.uid(),
                current_uid,
                p.display()
            )));
        }

        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = file.set_permissions(perms);

        // VULN-62: Advisory/mandatory file lock on Unix
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_EX);
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let handle = file.as_raw_handle();
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        let ok = unsafe { GetFileInformationByHandle(handle as *mut _, info.as_mut_ptr()) };
        if ok != 0 {
            let info = unsafe { info.assume_init() };
            if info.nNumberOfLinks > 1 {
                return Err(OpkeError::Validation(format!(
                    "Refusing to write to hardlink target for security: {}",
                    p.display()
                )));
            }
        }

        if existed_before {
            // VULN-67: Verify owner SID of existing file matches current process user SID
            let mut owner_sid: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut file_sd: *mut std::ffi::c_void = std::ptr::null_mut();
            let ret = unsafe {
                GetSecurityInfo(
                    handle as *mut _,
                    1,          // SE_FILE_OBJECT
                    0x00000001, // OWNER_SECURITY_INFORMATION
                    &mut owner_sid,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut file_sd,
                )
            };
            if ret == 0 && !owner_sid.is_null() {
                let mut token_handle: *mut std::ffi::c_void = std::ptr::null_mut();
                let token_ok = unsafe {
                    OpenProcessToken(GetCurrentProcess(), 0x0008, &mut token_handle)
                    // TOKEN_QUERY
                };
                if token_ok != 0 && !token_handle.is_null() {
                    let mut token_user_buf = [0u8; 256];
                    let mut ret_len = 0u32;
                    let info_ok = unsafe {
                        GetTokenInformation(
                            token_handle,
                            1, // TokenUser
                            token_user_buf.as_mut_ptr() as *mut _,
                            token_user_buf.len() as u32,
                            &mut ret_len,
                        )
                    };
                    unsafe {
                        CloseHandle(token_handle);
                    }
                    if info_ok != 0 {
                        let token_user_sid = unsafe {
                            std::ptr::read_unaligned(
                                token_user_buf.as_ptr() as *const *mut std::ffi::c_void
                            )
                        };
                        let mut is_authorized_owner = false;
                        let same = unsafe { EqualSid(owner_sid, token_user_sid) };
                        if same != 0 {
                            is_authorized_owner = true;
                        } else {
                            // On environments running as Administrator (such as CI runners),
                            // newly created files are owned by BUILTIN\Administrators.
                            // Verify whether the current process token is a member of the owner SID.
                            let mut is_member = 0i32;
                            let mem_ok = unsafe {
                                CheckTokenMembership(
                                    std::ptr::null_mut(),
                                    owner_sid,
                                    &mut is_member,
                                )
                            };
                            if mem_ok != 0 && is_member != 0 {
                                is_authorized_owner = true;
                            }
                        }

                        if !is_authorized_owner {
                            unsafe {
                                LocalFree(file_sd);
                            }
                            return Err(OpkeError::Validation(format!(
                                "Refusing to write to file owned by another user (Windows SID mismatch): {}",
                                p.display()
                            )));
                        }
                    }
                }
                unsafe {
                    LocalFree(file_sd);
                }
            }
        }

        // Apply owner-only DACL using handle-based SetSecurityInfo to prevent TOCTOU symlink race (VULN-34)
        let sddl: Vec<u16> = "D:P(A;;FA;;;OW)\0".encode_utf16().collect();
        let mut sd = std::ptr::null_mut();
        let mut sd_size = 0u32;
        let conv_ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut sd,
                &mut sd_size,
            )
        };

        let mut acl_applied = false;
        if conv_ok != 0 && !sd.is_null() {
            let mut dacl_present = 0i32;
            let mut dacl = std::ptr::null_mut();
            let mut dacl_defaulted = 0i32;
            let get_ok = unsafe {
                GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
            };
            if get_ok != 0 && dacl_present != 0 {
                let set_res = unsafe {
                    SetSecurityInfo(
                        handle as *mut _,
                        1,                       // SE_FILE_OBJECT
                        0x00000004 | 0x80000000, // DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        dacl,
                        std::ptr::null_mut(),
                    )
                };
                if set_res == 0 {
                    acl_applied = true;
                }
            }
            unsafe {
                LocalFree(sd);
            }
        }

        if !acl_applied {
            // Filesystem (FAT32/exFAT/network share) does not support NTFS DACL
            if io::stdin().is_terminal() {
                eprintln!("[!] 警告: 保存先ファイルシステムがWindowsアクセス制御（ACL）に対応していません。");
                eprintln!("[!] 他のユーザーがこのPCにログインしている場合、ファイルが閲覧される可能性があります。");
                eprint!("続行しますか？ (y/N): ");
                let _ = io::stderr().flush();
                let mut ans = String::new();
                let _ = io::stdin().read_line(&mut ans);
                if !ans.trim().eq_ignore_ascii_case("y") {
                    return Err(OpkeError::Validation(
                        "セキュリティ保護設定（ACL）の適用に失敗したため、書き込みを中止しました。"
                            .into(),
                    ));
                }
            } else if force {
                eprintln!("[!] 警告: 保存先ファイルシステムがWindowsアクセス制御（ACL）に対応していません。--force が指定されているため続行します。");
            } else {
                return Err(OpkeError::Validation(
                    "保存先ファイルシステムがWindowsアクセス制御（ACL）に対応していません。非対話実行で続行するには '--force' を指定してください。".into(),
                ));
            }
        }

        // VULN-62: Mandatory file locking on Windows
        unsafe {
            LockFile(handle as *mut _, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF);
        }
    }

    // Write data and truncate afterwards to protect existing file on write error (VULN-29)
    file.rewind()?;
    let write_result = (|| -> Result<(), OpkeError> {
        file.write_all(data)?;
        file.set_len(data.len() as u64)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        unsafe {
            UnlockFile(file.as_raw_handle() as *mut _, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
        }
    }

    // Close the file handle explicitly before cleanup to eliminate ERROR_SHARING_VIOLATION on Windows (VULN-30)
    drop(file);

    if let Err(e) = write_result {
        if !existed_before {
            let _ = std::fs::remove_file(p);
        }
        return Err(e);
    }

    Ok(())
}
