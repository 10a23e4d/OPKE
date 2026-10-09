//! Secure file operations preventing symlink attacks, hardlink attacks, TOCTOU races,
//! permission leakage, and incomplete file residue.

use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Read, Seek, Write};
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
    fn SetNamedSecurityInfoW(
        pObjectName: *const u16,
        ObjectType: i32,
        SecurityInfo: u32,
        psidOwner: *mut std::ffi::c_void,
        psidGroup: *mut std::ffi::c_void,
        pDacl: *mut std::ffi::c_void,
        pSacl: *mut std::ffi::c_void,
    ) -> u32;
}

/// Reads a regular file into a zeroized byte buffer, strictly refusing symlinks, FIFOs, and non-regular files.
pub fn read_secure_file(path: impl AsRef<Path>, max_bytes: usize) -> Result<Zeroizing<Vec<u8>>, OpkeError> {
    let p = path.as_ref();
    if p.as_os_str().is_empty() {
        return Err(OpkeError::Validation("Invalid file path.".into()));
    }
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

    let mut file = options.open(p)?;

    // Verify metadata on the opened file descriptor to prevent TOCTOU race
    let fd_meta = file.metadata()?;
    if !fd_meta.is_file() {
        return Err(OpkeError::Validation(format!(
            "Refusing to read non-regular file for security: {}",
            p.display()
        )));
    }

    let mut buf = Zeroizing::new(Vec::with_capacity(file_len.min(65536)));
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
    if p.as_os_str().is_empty() {
        return Err(OpkeError::Validation("Invalid file path.".into()));
    }

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

    // Notice: truncate(true) is omitted to avoid truncating existing target before validations
    let mut options = OpenOptions::new();
    options.write(true).create(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        options.mode(0o600);
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

        // Apply owner-only DACL (D:P(A;;FA;;;OW) -> Protected DACL, Full Access to Owner)
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
                use std::os::windows::ffi::OsStrExt;
                let p_wide: Vec<u16> = p.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
                let set_res = unsafe {
                    SetNamedSecurityInfoW(
                        p_wide.as_ptr(),
                        1, // SE_FILE_OBJECT
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
                        "セキュリティ保護設定（ACL）の適用に失敗したため、書き込みを中止しました。".into(),
                    ));
                }
            } else if force {
                eprintln!("[!] 警告: 保存先ファイルシステムがWindowsアクセス制御（ACL）に対応していませんが、--force が指定されているため続行します。");
            } else {
                return Err(OpkeError::Validation(
                    "保存先ファイルシステムがWindowsアクセス制御（ACL）に対応していません。非対話実行で続行するには '--force' を指定してください。".into(),
                ));
            }
        }
    }

    // Safely truncate existing target now that validations have succeeded
    file.set_len(0)?;
    file.rewind()?;

    // RAII guard to unlink incomplete file if an error or panic occurs during writing
    struct CleanupGuard<'a> {
        path: &'a Path,
        should_cleanup: bool,
    }
    impl<'a> Drop for CleanupGuard<'a> {
        fn drop(&mut self) {
            if self.should_cleanup {
                let _ = std::fs::remove_file(self.path);
            }
        }
    }

    let mut guard = CleanupGuard {
        path: p,
        should_cleanup: !existed_before,
    };

    file.write_all(data)?;
    file.flush()?;
    file.sync_all()?;

    // Successfully written; do not remove file
    guard.should_cleanup = false;

    Ok(())
}
