"""Security utilities for OPKE: memory wiping, secure input handling, and secure file operations."""

import ctypes
import getpass
import hmac
import os
import stat
import sys
from typing import Union


MAX_SECRET_BYTES = 64 * 1024 * 1024  # 64 MiB sanity limit for secrets
MAX_PASSPHRASE_BYTES = 4096           # 4 KiB sanity limit for passphrases


def zero_memory(buf: Union[bytearray, memoryview, list, None]) -> None:
    """Overwrites mutable memory buffers with zeros to prevent key leakage.

    Uses native memset via ctypes when possible for zero heap allocation
    and fast in-place memory erasure.

    Args:
        buf: A mutable buffer (bytearray, memoryview, or list of ints) to be zeroed.

    Raises:
        TypeError: If an immutable, read-only, or unsupported object is passed.
    """
    if buf is None:
        return
    if isinstance(buf, memoryview):
        if buf.readonly:
            raise TypeError("Cannot zero immutable type: read-only memoryview. Use bytearray.")
        if len(buf) == 0:
            return
        try:
            ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
        except Exception:
            chunk = b"\x00" * min(len(buf), 65536)
            for offset in range(0, len(buf), len(chunk)):
                end = min(offset + len(chunk), len(buf))
                buf[offset:end] = chunk[:end - offset]
    elif isinstance(buf, bytearray):
        if len(buf) == 0:
            return
        try:
            ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
        except Exception:
            chunk = b"\x00" * min(len(buf), 65536)
            for offset in range(0, len(buf), len(chunk)):
                end = min(offset + len(chunk), len(buf))
                buf[offset:end] = chunk[:end - offset]
    elif isinstance(buf, list):
        for i in range(len(buf)):
            buf[i] = 0
    elif isinstance(buf, (bytes, str)):
        raise TypeError(f"Cannot zero immutable type: {type(buf).__name__}. Use bytearray.")
    else:
        raise TypeError(f"Cannot zero unsupported type: {type(buf).__name__}. Expected bytearray, memoryview, or list.")


def prompt_passphrase(
    confirm: bool = False,
    prompt: str = "Enter passphrase: ",
    confirm_prompt: str = "Confirm passphrase: ",
) -> bytearray:
    """Safely prompts for a passphrase without echoing characters to terminal.

    Uses constant-time comparison for passphrase verification.

    Args:
        confirm: If True, asks user to type the passphrase a second time to verify.
        prompt: Initial prompt string.
        confirm_prompt: Confirmation prompt string.

    Returns:
        bytearray: UTF-8 encoded passphrase as a mutable bytearray that can be zeroed.

    Raises:
        ValueError: If passphrases do not match or if an empty passphrase is provided.
    """
    p1 = None
    p2 = None
    try:
        try:
            p1 = getpass.getpass(prompt)
        except EOFError:
            raise ValueError("Passphrase cannot be empty.")
        if not p1:
            raise ValueError("Passphrase cannot be empty.")

        if confirm:
            try:
                p2 = getpass.getpass(confirm_prompt)
            except EOFError:
                raise ValueError("Passphrases do not match.")
            if not hmac.compare_digest(p1, p2):
                raise ValueError("Passphrases do not match.")

        raw_bytes = p1.encode("utf-8")
        if len(raw_bytes) > MAX_PASSPHRASE_BYTES:
            raise ValueError(f"Passphrase exceeds maximum allowed length ({MAX_PASSPHRASE_BYTES} bytes).")
        result = bytearray(raw_bytes)
        return result
    finally:
        del p1, p2


def prompt_secret(
    prompt: str = "Enter secret plaintext: ",
    multiline: bool = False,
    max_bytes: int = MAX_SECRET_BYTES,
) -> bytearray:
    """Prompts the user for secret plaintext if not provided via file.

    Maintains binary transparency (does not strip trailing bytes from piped input)
    and ensures zeroed memory on size limit violations and zero intermediate heap copies.
    """
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError(f"Invalid max_bytes: {max_bytes} (must be a positive integer)")

    if sys.stdin.isatty():
        if multiline:
            print(
                f"{prompt} (multi-line mode)\n"
                "[*] Paste/type your secret, then press Ctrl+D (EOF on Linux/macOS) "
                "or Ctrl+Z then Enter (on Windows) to finish:",
                file=sys.stderr,
            )
            raw = sys.stdin.read(max_bytes + 1)
            if len(raw) > max_bytes:
                del raw
                raise ValueError(f"Secret input exceeds maximum allowed size ({max_bytes} bytes).")
            if not raw:
                raise ValueError("Secret cannot be empty.")
            res = None
            try:
                res = bytearray(raw.encode("utf-8"))
                del raw
                if len(res) > max_bytes:
                    zero_memory(res)
                    res = None
                    raise ValueError(f"Secret input exceeds maximum allowed size ({max_bytes} bytes).")
                return res
            except BaseException:
                if res is not None:
                    zero_memory(res)
                raise
        else:
            print(
                "[*] Notice: Single-line mode. For multi-line secrets (e.g. Emergency Kit), "
                "use --multiline or -i.",
                file=sys.stderr,
            )
            try:
                s = getpass.getpass(f"{prompt} (hidden): ")
            except EOFError:
                raise ValueError("Secret cannot be empty.")
            if not s:
                raise ValueError("Secret cannot be empty.")
            res = None
            try:
                res = bytearray(s.encode("utf-8"))
                del s
                if len(res) > max_bytes:
                    zero_memory(res)
                    res = None
                    raise ValueError(f"Secret input exceeds maximum allowed size ({max_bytes} bytes).")
                return res
            except BaseException:
                if res is not None:
                    zero_memory(res)
                raise
    else:
        # Non-TTY (pipe or redirected input): read chunks into bytearray with zeroing on overflow
        buf = bytearray()
        chunk_size = 64 * 1024
        chunk_buf = bytearray(chunk_size)
        try:
            while True:
                n = sys.stdin.buffer.readinto(chunk_buf)
                if not n:
                    break
                buf.extend(memoryview(chunk_buf)[:n])
                if len(buf) > max_bytes:
                    zero_memory(buf)
                    raise ValueError(f"Secret input exceeds maximum allowed size ({max_bytes} bytes).")
            if not buf:
                raise ValueError("Secret cannot be empty.")
            return buf
        except BaseException:
            zero_memory(buf)
            raise
        finally:
            zero_memory(chunk_buf)


def read_secure_file(path: str, is_binary: bool = True, max_bytes: int = MAX_SECRET_BYTES) -> Union[bytearray, str]:
    """Safely reads a regular file preventing hangs on FIFOs, following special files, and verifying regular file status.

    Returns mutable bytearray if is_binary=True, or str if is_binary=False.
    Wipes intermediate memory if size limit is exceeded.
    """
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError(f"Invalid max_bytes: {max_bytes} (must be a positive integer)")
    if not isinstance(path, str) or not path.strip():
        raise ValueError("Invalid file path.")
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    # Use O_NONBLOCK to prevent blocking on FIFOs or special device files
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    f = None
    try:
        fstat = os.fstat(fd)
        if not stat.S_ISREG(fstat.st_mode):
            raise OSError(f"Refusing to read non-regular file for security: {path}")

        # Reset O_NONBLOCK for reliable synchronous reading
        try:
            import fcntl
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~getattr(os, "O_NONBLOCK", 0))
        except (ImportError, OSError):
            pass

        f = open(fd, "rb" if is_binary else "r", encoding=None if is_binary else "utf-8", closefd=True)
        if is_binary:
            buf = bytearray()
            chunk_size = 64 * 1024
            chunk_buf = bytearray(chunk_size)
            try:
                while True:
                    n = f.readinto(chunk_buf)
                    if not n:
                        break
                    buf.extend(memoryview(chunk_buf)[:n])
                    if len(buf) > max_bytes:
                        zero_memory(buf)
                        raise ValueError(f"File '{path}' exceeds maximum allowed size ({max_bytes} bytes).")
                return buf
            except BaseException:
                zero_memory(buf)
                raise
            finally:
                zero_memory(chunk_buf)
        else:
            data = f.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError(f"File '{path}' exceeds maximum allowed size ({max_bytes} chars).")
            return data
    except BaseException:
        if f is not None:
            try:
                f.close()
            except Exception:
                pass
        else:
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    else:
        f.close()


def write_secure_file(path: str, data: Union[bytes, bytearray, str], is_binary: bool = True) -> None:
    """Writes data to a file with owner-only permissions (0600) and refuses symlinks and hardlinks.

    Hardened against TOCTOU race conditions via O_NOFOLLOW, hardlink attacks via post-open st_nlink verification,
    multi-user ownership hijacking via UID check, prevents pre-check truncation, and enforces owner-only permissions.
    """
    existed_before = os.path.lexists(path)
    # Pre-check existing path to prevent hangs on FIFOs or special files
    if existed_before:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            raise OSError(f"Refusing to write to symlink for security: {path}")
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"Refusing to write to non-regular file for security: {path}")

    # Note: O_TRUNC is deliberately omitted from initial open flags so existing files are NOT truncated
    # before st_nlink, S_ISREG, and ownership validation can be securely verified on the file descriptor.
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    mode = 0o600
    fd = os.open(path, flags, mode)
    f = None
    target_stat = None
    try:
        fstat = os.fstat(fd)
        target_stat = fstat
        # Prevent symlinks, FIFOs, device files, and non-regular files
        if not stat.S_ISREG(fstat.st_mode):
            raise OSError(f"Refusing to write to non-regular file for security: {path}")

        # Prevent hardlink attacks without truncating existing target
        if fstat.st_nlink > 1:
            raise OSError(f"Refusing to write to hardlink target for security: {path}")

        # Prevent multi-user hijacking: refuse writing to existing file owned by another user
        if hasattr(os, "getuid") and fstat.st_uid != os.getuid():
            raise OSError(f"Refusing to write to file owned by another user (UID {fstat.st_uid} != {os.getuid()}): {path}")

        # Reset non-blocking flag for reliable synchronous writing
        try:
            import fcntl
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~getattr(os, "O_NONBLOCK", 0))
        except (ImportError, OSError):
            pass

        # Enforce owner-only permissions on existing files before writing sensitive content
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass

        # Safely truncate now that all security validations have succeeded
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)

        f = open(fd, "wb" if is_binary else "w", encoding=None if is_binary else "utf-8", closefd=True)
        f.write(data)
        f.flush()
        try:
            os.fsync(fd)
        except OSError:
            pass
        try:
            if hasattr(os, "chmod"):
                os.chmod(path, 0o600, follow_symlinks=False)
        except (AttributeError, OSError, NotImplementedError):
            pass
    except BaseException:
        if f is not None:
            try:
                f.close()
            except Exception:
                pass
        else:
            try:
                os.close(fd)
            except OSError:
                pass
        # Clean up newly created incomplete file to prevent leaving sensitive remnants
        if not existed_before:
            try:
                if os.path.lexists(path):
                    l_st = os.lstat(path)
                    if target_stat is None or not hasattr(target_stat, "st_ino") or l_st.st_ino == target_stat.st_ino:
                        os.unlink(path)
            except OSError:
                pass
        raise
    else:
        f.close()
