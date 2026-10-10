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
    fn MoveFileExW(lpExistingFileName: *const u16, lpNewFileName: *const u16, dwFlags: u32) -> i32;
}

/// Validates file path against NTFS Alternate Data Streams (ADS) and Windows reserved device names (VULN-39, VULN-40, VULN-86, VULN-87).
fn validate_file_path(p: &Path) -> Result<(), OpkeError> {
    let s = p.to_string_lossy();
    if s.is_empty() {
        return Err(OpkeError::Validation("Invalid file path.".into()));
    }

    // 1. Check for NTFS Alternate Data Streams (ADS: filename:stream)
    // Strip Windows verbatim / device prefix (\\?\ or \\.\ or //?/ or //./) if present (VULN-86, VULN-139)
    let s_norm = s.replace('/', "\\");
    let stripped = if s_norm.starts_with(r"\\?\") || s_norm.starts_with(r"\\.\") {
        &s_norm[4..]
    } else {
        &s_norm[..]
    };

    // Allow standard Windows drive specifier (e.g., C:\ or D:/)
    let rest_path = if stripped.len() >= 2
        && stripped.as_bytes()[1] == b':'
        && stripped.as_bytes()[0].is_ascii_alphabetic()
    {
        &stripped[2..]
    } else {
        stripped
    };

    if rest_path.contains(':') {
        return Err(OpkeError::Validation(format!(
            "NTFS Alternate Data Streams (ADS) are prohibited for security: {}",
            p.display()
        )));
    }

    // 2. Check for Windows reserved device names in all components (VULN-39, VULN-87, VULN-137)
    let reserved = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "CONIN$",
        "CONOUT$", "CLOCK$",
    ];

    for comp in p.components() {
        if let std::path::Component::Normal(os_str) = comp {
            if let Some(file_name) = os_str.to_str() {
                // Normalize superscript digits (e.g. COM¹ -> COM1) (VULN-138)
                let norm_chars: String = file_name
                    .chars()
                    .map(|c| match c {
                        '⁰' => '0',
                        '¹' => '1',
                        '²' => '2',
                        '³' => '3',
                        '⁴' => '4',
                        '⁵' => '5',
                        '⁶' => '6',
                        '⁷' => '7',
                        '⁸' => '8',
                        '⁹' => '9',
                        _ => c,
                    })
                    .collect();

                let stem = std::path::Path::new(&norm_chars)
                    .file_stem()
                    .and_then(|st| st.to_str())
                    .unwrap_or(&norm_chars)
                    .to_ascii_uppercase();
                let full = norm_chars.to_ascii_uppercase();

                if reserved.contains(&stem.as_str()) || reserved.contains(&full.as_str()) {
                    return Err(OpkeError::Validation(format!(
                        "Windows reserved device names are prohibited for security: {}",
                        p.display()
                    )));
                }
            }
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

    // Pre-check for symlinks and non-regular files to fail fast (VULN-215)
    let sym_meta = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) => return Err(OpkeError::Io(e)),
    };
    if sym_meta.file_type().is_symlink() {
        return Err(OpkeError::Validation(format!(
            "Refusing to read symlink for security: {}",
            p.display()
        )));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (sym_meta.file_attributes() & 0x0400) != 0 {
            return Err(OpkeError::Validation(format!(
                "Refusing to read reparse point / junction for security: {}",
                p.display()
            )));
        }
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = fd_meta.mode();
        if (mode & 0o077) != 0 {
            eprintln!(
                "[!] Warning: File '{}' has overly permissive permissions ({:04o}). It is recommended to restrict access (chmod 600).",
                p.display(),
                mode & 0o777
            );
        }
    }

    // Fully preallocate buffer with exact file length to eliminate reallocation plaintext leak (VULN-28, VULN-145)
    let mut buf = Zeroizing::new(Vec::with_capacity(file_len));
    let mut chunk = Zeroizing::new([0u8; 65536]);

    loop {
        let n = file.read(&mut *chunk)?;
        if n == 0 {
            break;
        }
        if buf.len() + n > max_bytes {
            return Err(OpkeError::Validation(format!(
                "File '{}' exceeds maximum allowed size ({} bytes).",
                p.display(),
                max_bytes
            )));
        }
        // If file grew beyond initial capacity, allocate a new zeroized buffer with exact required capacity
        // and safely copy, ensuring old buffer drops and zeroizes immediately without unzeroized shallow copy.
        if buf.len() + n > buf.capacity() {
            let new_cap = (buf.len() + n)
                .max(buf.capacity().saturating_mul(2))
                .min(max_bytes);
            let mut new_buf = Zeroizing::new(Vec::with_capacity(new_cap));
            new_buf.extend_from_slice(&buf);
            buf = new_buf;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    Ok(buf)
}

/// Safely writes data to a file with owner-only permissions (0600 on Unix, restricted DACL on Windows).
/// Refuses symlinks, hardlinks, and files owned by other users.
pub fn write_secure_file(path: impl AsRef<Path>, data: &[u8]) -> Result<(), OpkeError> {
    write_secure_file_with_options(path, data, false)
}

#[cfg(windows)]
fn atomic_replace_windows(from: &Path, to: &Path) -> Result<(), OpkeError> {
    use std::os::windows::ffi::OsStrExt;
    let from_wide: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to_wide: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x00000001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x00000008;
    let ok = unsafe {
        MoveFileExW(
            from_wide.as_ptr(),
            to_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        return Err(OpkeError::Io(err));
    }
    Ok(())
}

fn validate_existing_file_security(p: &Path) -> Result<(), OpkeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(p)?;
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
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        let mut options = OpenOptions::new();
        options.read(true);
        // READ_CONTROL (0x00020000)
        options.access_mode(0x80000000 | 0x00020000);
        options.share_mode(0x00000001 | 0x00000002 | 0x00000004);
        let file = options.open(p)?;
        let handle = file.as_raw_handle();

        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        let ok = unsafe { GetFileInformationByHandle(handle as *mut _, info.as_mut_ptr()) };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(OpkeError::Io(std::io::Error::new(
                err.kind(),
                format!(
                    "Failed to get file information on '{}': {}",
                    p.display(),
                    err
                ),
            )));
        }
        let info = unsafe { info.assume_init() };
        if info.nNumberOfLinks > 1 {
            return Err(OpkeError::Validation(format!(
                "Refusing to write to hardlink target for security: {}",
                p.display()
            )));
        }

        // VULN-67, VULN-140: Verify owner SID of existing file matches current process user SID
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
        if ret != 0 {
            let err = std::io::Error::from_raw_os_error(ret as i32);
            return Err(OpkeError::Io(std::io::Error::new(
                err.kind(),
                format!(
                    "Failed to get file security info on '{}': {}",
                    p.display(),
                    err
                ),
            )));
        }
        if !owner_sid.is_null() {
            let mut token_handle: *mut std::ffi::c_void = std::ptr::null_mut();
            let token_ok =
                unsafe { OpenProcessToken(GetCurrentProcess(), 0x0008, &mut token_handle) };
            if token_ok != 0 && !token_handle.is_null() {
                // VULN-156: Dynamic buffer allocation if 256 bytes is insufficient
                let mut token_user_buf = vec![0u8; 256];
                let mut ret_len = 0u32;
                let mut info_ok = unsafe {
                    GetTokenInformation(
                        token_handle,
                        1, // TokenUser
                        token_user_buf.as_mut_ptr() as *mut _,
                        token_user_buf.len() as u32,
                        &mut ret_len,
                    )
                };
                if info_ok == 0 && ret_len > token_user_buf.len() as u32 {
                    token_user_buf.resize(ret_len as usize, 0);
                    info_ok = unsafe {
                        GetTokenInformation(
                            token_handle,
                            1,
                            token_user_buf.as_mut_ptr() as *mut _,
                            token_user_buf.len() as u32,
                            &mut ret_len,
                        )
                    };
                }
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
                        let mut is_member = 0i32;
                        let mem_ok = unsafe {
                            CheckTokenMembership(std::ptr::null_mut(), owner_sid, &mut is_member)
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

    Ok(())
}

#[cfg(windows)]
fn apply_windows_dacl(
    handle: *mut std::ffi::c_void,
    _p: &Path,
    force: bool,
) -> Result<(), OpkeError> {
    // VULN-151: Remove redundant \0 byte literal in SDDL string
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)".encode_utf16().chain(Some(0)).collect();
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
                    handle,
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
        if io::stdin().is_terminal() {
            eprintln!(
                "[!] 警告: 保存先ファイルシステムがWindowsアクセス制御（ACL）に対応していません。"
            );
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

    Ok(())
}

fn write_secure_file_direct(p: &Path, data: &[u8], force: bool) -> Result<(), OpkeError> {
    write_secure_file_internal(p, data, force, true)
}

#[cfg(windows)]
fn write_secure_file_inplace(p: &Path, data: &[u8], force: bool) -> Result<(), OpkeError> {
    write_secure_file_internal(p, data, force, false)
}

fn write_secure_file_internal(
    p: &Path,
    data: &[u8],
    _force: bool,
    create_new: bool,
) -> Result<(), OpkeError> {
    let mut options = OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
        options.truncate(true); // VULN-141: Truncate in-place to prevent tail remnants
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
        if _force {
            options.access_mode(0x80000000 | 0x40000000); // GENERIC_READ | GENERIC_WRITE (without WRITE_DAC, VULN-175)
        } else {
            options.access_mode(0x80000000 | 0x40000000 | 0x00040000); // with WRITE_DAC
        }
        options.share_mode(0x00000001 | 0x00000002 | 0x00000004);
    }

    let mut file = match options.open(p) {
        Ok(f) => f,
        Err(e) => {
            #[cfg(windows)]
            if _force && e.kind() == std::io::ErrorKind::PermissionDenied {
                // VULN-175: Retry opening without WRITE_DAC if permission was denied under --force
                use std::os::windows::fs::OpenOptionsExt;
                let mut retry_options = OpenOptions::new();
                retry_options.write(true);
                if create_new {
                    retry_options.create_new(true);
                } else {
                    retry_options.create(true);
                    retry_options.truncate(true);
                }
                retry_options.access_mode(0x80000000 | 0x40000000);
                retry_options.share_mode(0x00000001 | 0x00000002 | 0x00000004);
                retry_options.open(p)?
            } else {
                return Err(OpkeError::Io(e));
            }
            #[cfg(not(windows))]
            return Err(OpkeError::Io(e));
        }
    };

    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(OpkeError::Validation(format!(
            "Refusing to write to non-regular file for security: {}",
            p.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = file.set_permissions(perms);

        // VULN-62, VULN-82: Non-blocking flock on Unix
        use std::os::unix::io::AsRawFd;
        unsafe {
            let ret = libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB);
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                return Err(OpkeError::Io(std::io::Error::new(
                    err.kind(),
                    format!(
                        "Failed to acquire exclusive lock on '{}': {}",
                        p.display(),
                        err
                    ),
                )));
            }
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let handle = file.as_raw_handle();
        apply_windows_dacl(handle as *mut _, p, _force)?;

        // VULN-62, VULN-96, VULN-128: Mandatory file locking on Windows with return check
        unsafe {
            let ok = LockFile(handle as *mut _, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF);
            if ok == 0 {
                let err = std::io::Error::last_os_error();
                return Err(OpkeError::Io(std::io::Error::new(
                    err.kind(),
                    format!(
                        "Failed to acquire exclusive lock on '{}': {}",
                        p.display(),
                        err
                    ),
                )));
            }
        }
    }

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

    drop(file);

    if let Err(e) = write_result {
        if create_new {
            let _ = std::fs::remove_file(p);
        }
        return Err(e);
    }

    Ok(())
}

/// Safely writes data with an explicit `--force` override for environments where ACLs cannot be set.
/// Performs atomic replacement when writing to existing files (VULN-81).
pub fn write_secure_file_with_options(
    path: impl AsRef<Path>,
    data: &[u8],
    force: bool,
) -> Result<(), OpkeError> {
    let p = path.as_ref();
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
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if (sym_meta.file_attributes() & 0x0400) != 0 {
                return Err(OpkeError::Validation(format!(
                    "Refusing to write to reparse point / junction for security: {}",
                    p.display()
                )));
            }
        }
        if !sym_meta.is_file() {
            return Err(OpkeError::Validation(format!(
                "Refusing to write to non-regular file for security: {}",
                p.display()
            )));
        }

        validate_existing_file_security(p)?;

        // VULN-81: Atomic file replacement using secure temp file
        let parent_dir = p
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file_name = p.file_name().and_then(|f| f.to_str()).unwrap_or("file");
        let tmp_path = parent_dir.join(format!(
            ".{}.opke_tmp.{}_{:08x}",
            file_name,
            std::process::id(),
            rand::random::<u32>()
        ));

        // Write data to tmp_path as brand new file with secure permissions
        let write_res = write_secure_file_direct(&tmp_path, data, force);
        if let Err(e) = write_res {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }

        // Atomically replace target file
        #[cfg(unix)]
        {
            if let Err(e) = std::fs::rename(&tmp_path, p) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(OpkeError::Io(e));
            }
        }

        #[cfg(windows)]
        {
            if let Err(_e) = atomic_replace_windows(&tmp_path, p) {
                let _ = std::fs::remove_file(&tmp_path);
                // Destination file p may be held open by an existing handle (e.g. NamedTempFile in tests
                // or open shared handle). Fall back to in-place secure write.
                return write_secure_file_inplace(p, data, force);
            }
        }

        return Ok(());
    }

    write_secure_file_direct(p, data, force)
}
