"""Offline Paper-Key Encryptor (OPKE) v2.0.

A high-load offline paper-key cold-storage encryption and decryption utility
featuring Argon2id KDF and dual-layer AEAD (ChaCha20-Poly1305 + AES-256-GCM).
"""

__version__ = "2.0.0"

from opke.core import (
    derive_key_and_split,
    encrypt_cascade,
    decrypt_cascade,
    CryptoError,
    AuthenticationError,
)
from opke.envelope import (
    OPKEEnvelope,
    KDFParams,
    CipherParams,
    serialize_envelope,
    deserialize_envelope,
)

__all__ = [
    "derive_key_and_split",
    "encrypt_cascade",
    "decrypt_cascade",
    "CryptoError",
    "AuthenticationError",
    "OPKEEnvelope",
    "KDFParams",
    "CipherParams",
    "serialize_envelope",
    "deserialize_envelope",
    "__version__",
]
