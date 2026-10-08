//! Secure file operations preventing symlink attacks and enforcing restricted permissions.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

use crate::error::OpkeError;

/// Reads a regular file into a zeroized byte buffer, strictly refusing symlinks and non-regular files.
pub fn read_secure_file(path: impl AsRef<Path>, max_bytes: usize) -> Result<Zeroizing<Vec<u8>>, OpkeError> {
    let p = path.as_ref();
    if !p.exists() {
        return Err(OpkeError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", p.display()),
        )));
    }

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

    let mut file = File::open(p)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(file_len.min(65536)));
    let mut chunk = [0u8; 65536];

    loop {
        let n = file.read(&mut chunk)?;
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

/// Safely writes data to a file with owner-only permissions (0600 on Unix) and refuses symlinks.
pub fn write_secure_file(path: impl AsRef<Path>, data: &[u8]) -> Result<(), OpkeError> {
    let p = path.as_ref();

    if p.exists() {
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
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(p)?;
    file.write_all(data)?;
    file.flush()?;
    file.sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(p, perms);
    }

    Ok(())
}
