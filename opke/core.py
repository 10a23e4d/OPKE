"""Core cryptographic engine for OPKE v2.0.

Implements Argon2id KDF key derivation and dual-layer AEAD cascade encryption:
Layer 1: ChaCha20-Poly1305
Layer 2: AES-256-GCM
"""

import hmac
import os
from typing import Tuple, Union
from argon2.exceptions import HashingError
from argon2.low_level import ARGON2_VERSION, Type, ffi, lib
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from opke.security import zero_memory, MAX_SECRET_BYTES, MAX_PASSPHRASE_BYTES

# Default KDF parameters (Offline Paper-Key Cold Storage profile)
DEFAULT_M_KIB = 8388608  # 8 GiB
DEFAULT_T = 64           # 64 iterations
DEFAULT_P = 8            # 8 parallel threads

# Validation limits
MAX_M_KIB = 67108864     # 64 GiB max memory limit
MIN_M_KIB = 8            # Argon2 minimum
MAX_T = 1000             # 1000 iterations max limit
MIN_T = 1
MAX_P = 256              # 256 threads max
MIN_P = 1
MIN_CIPHERTEXT_BYTES = 17 # 1-byte plaintext + 16-byte Poly1305 tag
MAX_CIPHERTEXT_BYTES = MAX_SECRET_BYTES + 16  # 64 MiB plaintext + 16-byte Poly1305 tag

# Cryptographic sizes in bytes
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 64
SUBKEY_LEN = 32

# Predefined profiles
PROFILES = {
    "production": {"m_kib": 8388608, "t": 64, "p": 8},
    "standard": {"m_kib": 8388608, "t": 64, "p": 8},
    "moderate": {"m_kib": 1048576, "t": 16, "p": 4},
    "fast": {"m_kib": 65536, "t": 2, "p": 2},
    "test": {"m_kib": 65536, "t": 2, "p": 2},
}


class CryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class AuthenticationError(CryptoError):
    """Raised when AEAD authentication verification fails."""
    pass


def derive_key_and_split(
    passphrase: Union[bytes, bytearray],
    salt: bytes,
    m_kib: int = DEFAULT_M_KIB,
    t: int = DEFAULT_T,
    p: int = DEFAULT_P,
) -> Tuple[bytearray, bytearray]:
    """Derives a 64-byte key using Argon2id (v0x13) and splits into two 32-byte keys.

    Uses zero-copy CFFI buffer access to ensure no immutable copies of the passphrase
    are retained in Python heap memory.

    Args:
        passphrase: User passphrase (bytes or bytearray).
        salt: Cryptographic random salt (16 bytes).
        m_kib: Argon2 memory cost in KiB.
        t: Argon2 time cost (iterations).
        p: Argon2 parallelism (threads).

    Returns:
        Tuple[bytearray, bytearray]: (Key_ChaCha, Key_AES), each 32 bytes.
    """
    if not isinstance(passphrase, (bytes, bytearray)):
        raise TypeError(f"Passphrase must be bytes or bytearray, got {type(passphrase).__name__}")
    if len(passphrase) == 0:
        raise ValueError("Passphrase cannot be empty.")
    if len(passphrase) > MAX_PASSPHRASE_BYTES:
        raise ValueError(f"Passphrase exceeds maximum allowed length ({MAX_PASSPHRASE_BYTES} bytes).")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be exactly {SALT_LEN} bytes, got {len(salt) if hasattr(salt, '__len__') else type(salt).__name__}")
    if type(p) is not int or p < MIN_P:
        raise ValueError(f"Parallelism must be at least {MIN_P}, got {p}")
    if p > MAX_P:
        raise ValueError(f"Parallelism exceeds maximum limit ({MAX_P}): {p}")
    if type(t) is not int or t < MIN_T:
        raise ValueError(f"Time cost must be at least {MIN_T}, got {t}")
    if t > MAX_T:
        raise ValueError(f"Time cost exceeds maximum limit ({MAX_T}): {t}")
    if type(m_kib) is not int or m_kib < MIN_M_KIB:
        raise ValueError(f"Memory cost too low: {m_kib} KiB (minimum {MIN_M_KIB} KiB)")
    if m_kib > MAX_M_KIB:
        raise ValueError(f"Memory cost exceeds maximum allowed ({MAX_M_KIB} KiB): {m_kib} KiB")
    if m_kib < 8 * p:
        raise ValueError(f"Memory cost too low: {m_kib} KiB (Argon2 requires m_kib >= 8 * p = {8 * p} KiB)")

    # Prepare CFFI buffers
    out_buf = ffi.new("uint8_t[]", KEY_LEN)
    salt_buf = ffi.new("uint8_t[]", salt)
    key_chacha = None
    key_aes = None
    try:
        try:
            # Zero-copy buffer pointer to passphrase (avoids creating immutable bytes on Python heap)
            c_pass = ffi.from_buffer("uint8_t[]", passphrase)

            rv = lib.argon2_hash(
                t,
                m_kib,
                p,
                c_pass,
                len(passphrase),
                salt_buf,
                len(salt),
                out_buf,
                KEY_LEN,
                ffi.NULL,
                0,
                Type.ID.value,
                ARGON2_VERSION,
            )
            if rv != lib.ARGON2_OK:
                err_msg = ffi.string(lib.argon2_error_message(rv)).decode("utf-8", errors="replace")
                raise CryptoError(f"Argon2id key derivation failed (error code {rv}: {err_msg})")

            # Zero-copy directly from CFFI buffer into subkey bytearrays
            key_chacha = bytearray(ffi.buffer(out_buf, SUBKEY_LEN))
            key_aes = bytearray(ffi.buffer(out_buf + SUBKEY_LEN, SUBKEY_LEN))
        except BaseException:
            zero_memory(key_chacha)
            zero_memory(key_aes)
            raise
    finally:
        # Erase raw derived key from CFFI buffer
        ffi.memmove(out_buf, b"\x00" * KEY_LEN, KEY_LEN)

    if hmac.compare_digest(key_chacha, key_aes):
        zero_memory(key_chacha)
        zero_memory(key_aes)
        raise CryptoError("Argon2id derived degenerate identical subkeys.")

    return key_chacha, key_aes


def encrypt_cascade(
    plaintext: Union[bytes, bytearray],
    key_chacha: Union[bytes, bytearray],
    key_aes: Union[bytes, bytearray],
    nonce_chacha: bytes = None,
    nonce_aes: bytes = None,
) -> Tuple[bytes, bytes, bytes, bytes]:
    """Encrypts plaintext using dual AEAD cascade (ChaCha20-Poly1305 + AES-256-GCM).

    Process:
    1. Layer 1 (ChaCha20-Poly1305):
       Plaintext is encrypted with key_chacha and nonce_chacha.
       Produces intermediate ciphertext and 16-byte Tag_ChaCha.
       (PyCA ChaCha20Poly1305 outputs ciphertext + tag concatenated).
    2. Layer 2 (AES-256-GCM):
       The entire Layer 1 output (intermediate ciphertext + Tag_ChaCha) is encrypted
       with key_aes and nonce_aes.
       Produces final ciphertext (data) and 16-byte Tag_AES.

    Args:
        plaintext: The secret data to encrypt.
        key_chacha: 32-byte key for ChaCha20-Poly1305.
        key_aes: 32-byte key for AES-256-GCM.
        nonce_chacha: Optional 12-byte nonce (generated via CSPRNG if None).
        nonce_aes: Optional 12-byte nonce (generated via CSPRNG if None).

    Returns:
        Tuple[bytes, bytes, bytes, bytes]:
            (final_ciphertext, tag_aes, nonce_chacha, nonce_aes)
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError(f"Plaintext must be bytes or bytearray, got {type(plaintext).__name__}")
    if len(plaintext) == 0:
        raise ValueError("Plaintext cannot be empty.")
    if len(plaintext) > MAX_SECRET_BYTES:
        raise ValueError(f"Plaintext exceeds maximum allowed size ({MAX_SECRET_BYTES} bytes).")
    if not isinstance(key_chacha, (bytes, bytearray)) or len(key_chacha) != SUBKEY_LEN:
        raise ValueError(f"Key_ChaCha must be {SUBKEY_LEN} bytes, got {len(key_chacha) if hasattr(key_chacha, '__len__') else type(key_chacha).__name__}")
    if not isinstance(key_aes, (bytes, bytearray)) or len(key_aes) != SUBKEY_LEN:
        raise ValueError(f"Key_AES must be {SUBKEY_LEN} bytes, got {len(key_aes) if hasattr(key_aes, '__len__') else type(key_aes).__name__}")
    if hmac.compare_digest(key_chacha, key_aes):
        raise ValueError("Key_ChaCha and Key_AES must be independent and distinct.")

    if nonce_chacha is None:
        nonce_chacha = os.urandom(NONCE_LEN)
    elif not isinstance(nonce_chacha, (bytes, bytearray)) or len(nonce_chacha) != NONCE_LEN:
        raise ValueError(f"Nonce_ChaCha must be {NONCE_LEN} bytes, got {len(nonce_chacha) if hasattr(nonce_chacha, '__len__') else type(nonce_chacha).__name__}")

    if nonce_aes is None:
        while True:
            nonce_aes = os.urandom(NONCE_LEN)
            if not hmac.compare_digest(nonce_chacha, nonce_aes):
                break
    elif not isinstance(nonce_aes, (bytes, bytearray)) or len(nonce_aes) != NONCE_LEN:
        raise ValueError(f"Nonce_AES must be {NONCE_LEN} bytes, got {len(nonce_aes) if hasattr(nonce_aes, '__len__') else type(nonce_aes).__name__}")

    if hmac.compare_digest(nonce_chacha, nonce_aes):
        raise ValueError("Nonce_ChaCha and Nonce_AES must be distinct.")

    # Layer 1: ChaCha20-Poly1305
    chacha = ChaCha20Poly1305(key_chacha)
    aesgcm = AESGCM(key_aes)
    l1_buf = bytearray(len(plaintext) + TAG_LEN)
    l2_buf = bytearray(len(l1_buf) + TAG_LEN)
    try:
        chacha.encrypt_into(nonce_chacha, plaintext, None, l1_buf)
        aesgcm.encrypt_into(nonce_aes, l1_buf, None, l2_buf)

        # Separate final_ciphertext (data) and tag_aes
        final_ciphertext = bytes(memoryview(l2_buf)[:-TAG_LEN])
        tag_aes = bytes(memoryview(l2_buf)[-TAG_LEN:])

        return final_ciphertext, tag_aes, nonce_chacha, nonce_aes
    finally:
        zero_memory(l1_buf)
        zero_memory(l2_buf)
        del chacha, aesgcm


def decrypt_cascade(
    final_ciphertext: bytes,
    tag_aes: bytes,
    nonce_aes: bytes,
    nonce_chacha: bytes,
    key_chacha: Union[bytes, bytearray],
    key_aes: Union[bytes, bytearray],
) -> bytearray:
    """Decrypts and authenticates ciphertext through the inverse dual-layer cascade.

    Process:
    1. Layer 2 (AES-256-GCM):
       Decrypts and authenticates final_ciphertext + tag_aes with key_aes and nonce_aes.
       If verification fails, raises AuthenticationError immediately.
       Yields Layer 1 blob (intermediate ciphertext + Tag_ChaCha).
    2. Layer 1 (ChaCha20-Poly1305):
       Decrypts and authenticates Layer 1 blob with key_chacha and nonce_chacha.
       If verification fails, raises AuthenticationError immediately.
       Yields original plaintext.

    Args:
        final_ciphertext: Outer encrypted data.
        tag_aes: 16-byte AES-GCM authentication tag.
        nonce_aes: 12-byte AES-GCM nonce.
        nonce_chacha: 12-byte ChaCha20-Poly1305 nonce.
        key_chacha: 32-byte key for ChaCha20-Poly1305.
        key_aes: 32-byte key for AES-256-GCM.

    Returns:
        bytearray: Decrypted original plaintext as a mutable buffer that can be zeroed.

    Raises:
        AuthenticationError: If tag verification fails or data was tampered with.
        ValueError: If key, nonce, or tag lengths are invalid.
    """
    if not isinstance(final_ciphertext, (bytes, bytearray)):
        raise TypeError(f"Ciphertext must be bytes or bytearray, got {type(final_ciphertext).__name__}")
    if len(final_ciphertext) < MIN_CIPHERTEXT_BYTES:
        raise ValueError(f"Ciphertext too short: must be at least {MIN_CIPHERTEXT_BYTES} bytes, got {len(final_ciphertext)}")
    if len(final_ciphertext) > MAX_CIPHERTEXT_BYTES:
        raise ValueError(f"Ciphertext exceeds maximum allowed size ({MAX_CIPHERTEXT_BYTES} bytes).")
    if not isinstance(key_chacha, (bytes, bytearray)) or len(key_chacha) != SUBKEY_LEN:
        raise ValueError(f"Key_ChaCha must be {SUBKEY_LEN} bytes, got {len(key_chacha) if hasattr(key_chacha, '__len__') else type(key_chacha).__name__}")
    if not isinstance(key_aes, (bytes, bytearray)) or len(key_aes) != SUBKEY_LEN:
        raise ValueError(f"Key_AES must be {SUBKEY_LEN} bytes, got {len(key_aes) if hasattr(key_aes, '__len__') else type(key_aes).__name__}")
    if not isinstance(tag_aes, (bytes, bytearray)) or len(tag_aes) != TAG_LEN:
        raise ValueError(f"Tag_AES must be {TAG_LEN} bytes, got {len(tag_aes) if hasattr(tag_aes, '__len__') else type(tag_aes).__name__}")
    if not isinstance(nonce_aes, (bytes, bytearray)) or len(nonce_aes) != NONCE_LEN:
        raise ValueError(f"Nonce_AES must be {NONCE_LEN} bytes, got {len(nonce_aes) if hasattr(nonce_aes, '__len__') else type(nonce_aes).__name__}")
    if not isinstance(nonce_chacha, (bytes, bytearray)) or len(nonce_chacha) != NONCE_LEN:
        raise ValueError(f"Nonce_ChaCha must be {NONCE_LEN} bytes, got {len(nonce_chacha) if hasattr(nonce_chacha, '__len__') else type(nonce_chacha).__name__}")
    if hmac.compare_digest(nonce_chacha, nonce_aes):
        raise ValueError("Nonce_ChaCha and Nonce_AES must be distinct.")
    if hmac.compare_digest(key_chacha, key_aes):
        raise ValueError("Key_ChaCha and Key_AES must be independent and distinct.")

    # Layer 2 Decrypt & Verify (AES-256-GCM)
    l1_blob_len = len(final_ciphertext)
    l1_blob = bytearray(l1_blob_len)
    plaintext = None
    aesgcm = None
    chacha = None
    try:
        try:
            aesgcm = AESGCM(key_aes)
            aesgcm.decrypt_into(nonce_aes, bytes(final_ciphertext) + bytes(tag_aes), None, l1_blob)
        except InvalidTag:
            raise AuthenticationError("Decryption failed: Layer 2 (AES-GCM) authentication tag verification failed. Invalid passphrase or corrupted data.")
        except Exception as e:
            raise CryptoError(f"Layer 2 decryption failed: {e}")

        # Layer 1 Decrypt & Verify (ChaCha20-Poly1305)
        if len(l1_blob) < MIN_CIPHERTEXT_BYTES:
            raise AuthenticationError("Decryption failed: Layer 1 blob truncated.")

        plaintext_len = len(l1_blob) - TAG_LEN
        plaintext = bytearray(plaintext_len)
        try:
            chacha = ChaCha20Poly1305(key_chacha)
            chacha.decrypt_into(nonce_chacha, l1_blob, None, plaintext)
        except InvalidTag:
            zero_memory(plaintext)
            plaintext = None
            raise AuthenticationError("Decryption failed: Layer 1 (ChaCha20-Poly1305) authentication tag verification failed. Invalid passphrase or corrupted data.")
        except Exception as e:
            zero_memory(plaintext)
            plaintext = None
            raise CryptoError(f"Layer 1 decryption failed: {e}")

        if len(plaintext) == 0:
            zero_memory(plaintext)
            plaintext = None
            raise AuthenticationError("Decryption failed: Plaintext is empty.")

        return plaintext
    except BaseException:
        zero_memory(plaintext)
        raise
    finally:
        zero_memory(l1_blob)
        del aesgcm, chacha, l1_blob
