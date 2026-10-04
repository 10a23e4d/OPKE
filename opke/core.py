"""Core cryptographic engine for OPKE v2.0.

Implements Argon2id KDF key derivation and dual-layer AEAD cascade encryption:
Layer 1: ChaCha20-Poly1305
Layer 2: AES-256-GCM
"""

import os
from typing import Tuple, Union
import argon2.low_level
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from opke.security import zero_memory

# Default KDF parameters (Offline Paper-Key Cold Storage profile)
DEFAULT_M_KIB = 8388608  # 8 GiB
DEFAULT_T = 64           # 64 iterations
DEFAULT_P = 8            # 8 parallel threads

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

    Args:
        passphrase: User passphrase (bytes or bytearray).
        salt: Cryptographic random salt (16 bytes).
        m_kib: Argon2 memory cost in KiB.
        t: Argon2 time cost (iterations).
        p: Argon2 parallelism (threads).

    Returns:
        Tuple[bytearray, bytearray]: (Key_ChaCha, Key_AES), each 32 bytes.
    """
    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be exactly {SALT_LEN} bytes, got {len(salt)}")
    if m_kib < 8:
        raise ValueError(f"Memory cost too low: {m_kib} KiB")
    if t < 1:
        raise ValueError(f"Time cost must be at least 1, got {t}")
    if p < 1:
        raise ValueError(f"Parallelism must be at least 1, got {p}")

    # Derive raw 64-byte key using Argon2id v0x13
    raw_derived = argon2.low_level.hash_secret_raw(
        secret=bytes(passphrase),
        salt=salt,
        time_cost=t,
        memory_cost=m_kib,
        parallelism=p,
        hash_len=KEY_LEN,
        type=argon2.low_level.Type.ID,
        version=0x13,
    )

    key_buf = bytearray(raw_derived)
    del raw_derived

    # Split into Key_ChaCha (0..32) and Key_AES (32..64)
    key_chacha = bytearray(key_buf[:SUBKEY_LEN])
    key_aes = bytearray(key_buf[SUBKEY_LEN:])

    # Clean up master derived buffer
    zero_memory(key_buf)
    del key_buf

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
    if len(key_chacha) != SUBKEY_LEN:
        raise ValueError(f"Key_ChaCha must be {SUBKEY_LEN} bytes, got {len(key_chacha)}")
    if len(key_aes) != SUBKEY_LEN:
        raise ValueError(f"Key_AES must be {SUBKEY_LEN} bytes, got {len(key_aes)}")

    if nonce_chacha is None:
        nonce_chacha = os.urandom(NONCE_LEN)
    elif len(nonce_chacha) != NONCE_LEN:
        raise ValueError(f"Nonce_ChaCha must be {NONCE_LEN} bytes, got {len(nonce_chacha)}")

    if nonce_aes is None:
        nonce_aes = os.urandom(NONCE_LEN)
    elif len(nonce_aes) != NONCE_LEN:
        raise ValueError(f"Nonce_AES must be {NONCE_LEN} bytes, got {len(nonce_aes)}")

    # Layer 1: ChaCha20-Poly1305
    # PyCA ChaCha20Poly1305 encrypt returns: intermediate_ciphertext + 16B tag
    chacha = ChaCha20Poly1305(bytes(key_chacha))
    l1_output = chacha.encrypt(nonce_chacha, bytes(plaintext), None)

    # Layer 2: AES-256-GCM
    # PyCA AESGCM encrypt returns: final_ciphertext + 16B tag
    aesgcm = AESGCM(bytes(key_aes))
    l2_output = aesgcm.encrypt(nonce_aes, l1_output, None)

    # Separate final_ciphertext (data) and tag_aes
    final_ciphertext = l2_output[:-TAG_LEN]
    tag_aes = l2_output[-TAG_LEN:]

    return final_ciphertext, tag_aes, nonce_chacha, nonce_aes


def decrypt_cascade(
    final_ciphertext: bytes,
    tag_aes: bytes,
    nonce_aes: bytes,
    nonce_chacha: bytes,
    key_chacha: Union[bytes, bytearray],
    key_aes: Union[bytes, bytearray],
) -> bytes:
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
        bytes: Decrypted original plaintext.

    Raises:
        AuthenticationError: If tag verification fails or data was tampered with.
        ValueError: If key, nonce, or tag lengths are invalid.
    """
    if len(key_chacha) != SUBKEY_LEN:
        raise ValueError(f"Key_ChaCha must be {SUBKEY_LEN} bytes, got {len(key_chacha)}")
    if len(key_aes) != SUBKEY_LEN:
        raise ValueError(f"Key_AES must be {SUBKEY_LEN} bytes, got {len(key_aes)}")
    if len(tag_aes) != TAG_LEN:
        raise ValueError(f"Tag_AES must be {TAG_LEN} bytes, got {len(tag_aes)}")
    if len(nonce_aes) != NONCE_LEN:
        raise ValueError(f"Nonce_AES must be {NONCE_LEN} bytes, got {len(nonce_aes)}")
    if len(nonce_chacha) != NONCE_LEN:
        raise ValueError(f"Nonce_ChaCha must be {NONCE_LEN} bytes, got {len(nonce_chacha)}")

    # Layer 2 Decrypt & Verify (AES-256-GCM)
    try:
        aesgcm = AESGCM(bytes(key_aes))
        l1_blob = aesgcm.decrypt(nonce_aes, final_ciphertext + tag_aes, None)
    except InvalidTag:
        raise AuthenticationError("Decryption failed: Layer 2 (AES-GCM) authentication tag verification failed. Invalid passphrase or corrupted data.")
    except Exception as e:
        raise CryptoError(f"Layer 2 decryption failed: {e}")

    # Layer 1 Decrypt & Verify (ChaCha20-Poly1305)
    try:
        chacha = ChaCha20Poly1305(bytes(key_chacha))
        plaintext = chacha.decrypt(nonce_chacha, l1_blob, None)
    except InvalidTag:
        raise AuthenticationError("Decryption failed: Layer 1 (ChaCha20-Poly1305) authentication tag verification failed. Invalid passphrase or corrupted data.")
    except Exception as e:
        raise CryptoError(f"Layer 1 decryption failed: {e}")

    return plaintext
