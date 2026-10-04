"""Unit tests for OPKE core cryptographic algorithms."""

import os
import pytest

from opke.core import (
    AuthenticationError,
    CryptoError,
    derive_key_and_split,
    encrypt_cascade,
    decrypt_cascade,
)
from opke.security import zero_memory


def test_derive_key_and_split():
    passphrase = b"CorrectHorseBatteryStaple"
    salt = os.urandom(16)

    # Use fast parameters for quick unit test execution
    k1_a, k2_a = derive_key_and_split(passphrase, salt, m_kib=1024, t=1, p=1)
    k1_b, k2_b = derive_key_and_split(passphrase, salt, m_kib=1024, t=1, p=1)

    assert len(k1_a) == 32
    assert len(k2_a) == 32
    assert k1_a == k1_b
    assert k2_a == k2_b
    assert k1_a != k2_a  # First 32 bytes and second 32 bytes must be distinct

    # Different salt -> completely different keys
    alt_salt = os.urandom(16)
    k1_diff, k2_diff = derive_key_and_split(passphrase, alt_salt, m_kib=1024, t=1, p=1)
    assert k1_a != k1_diff
    assert k2_a != k2_diff


def test_derive_key_invalid_inputs():
    passphrase = b"test"
    with pytest.raises(ValueError, match="Salt must be exactly 16 bytes"):
        derive_key_and_split(passphrase, b"short", m_kib=1024, t=1, p=1)

    with pytest.raises(ValueError, match="Memory cost too low"):
        derive_key_and_split(passphrase, os.urandom(16), m_kib=4, t=1, p=1)

    with pytest.raises(ValueError, match="Time cost must be at least 1"):
        derive_key_and_split(passphrase, os.urandom(16), m_kib=1024, t=0, p=1)

    with pytest.raises(ValueError, match="Parallelism must be at least 1"):
        derive_key_and_split(passphrase, os.urandom(16), m_kib=1024, t=1, p=0)


@pytest.mark.parametrize(
    "secret",
    [
        b"A",
        b"xK9#mQ2$vL5*pW8^zR1@yT4&uI7(oO0)",  # VeraCrypt password style
        b"emergency-kit-user-1234-5678-9012-secret-recovery-code-phrase",
        b"Multi-byte Unicode: \xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf\xe4\xb8\x96\xe7\x95\x8c\xf0\x9f\x94\x90",
        b"Long text payload: " + os.urandom(2048),
    ],
)
def test_encrypt_decrypt_cascade_roundtrip(secret):
    key_chacha = os.urandom(32)
    key_aes = os.urandom(32)

    final_ciphertext, tag_aes, nonce_chacha, nonce_aes = encrypt_cascade(
        plaintext=secret,
        key_chacha=key_chacha,
        key_aes=key_aes,
    )

    assert len(nonce_chacha) == 12
    assert len(nonce_aes) == 12
    assert len(tag_aes) == 16
    assert len(final_ciphertext) > 0

    decrypted = decrypt_cascade(
        final_ciphertext=final_ciphertext,
        tag_aes=tag_aes,
        nonce_aes=nonce_aes,
        nonce_chacha=nonce_chacha,
        key_chacha=key_chacha,
        key_aes=key_aes,
    )

    assert decrypted == secret


def test_tamper_detection_ciphertext():
    secret = b"Highly confidential VeraCrypt Master Key"
    key_chacha = os.urandom(32)
    key_aes = os.urandom(32)

    final_ciphertext, tag_aes, nonce_chacha, nonce_aes = encrypt_cascade(
        secret, key_chacha, key_aes
    )

    # Corrupt 1 byte in the final ciphertext
    tampered_ciphertext = bytearray(final_ciphertext)
    tampered_ciphertext[0] ^= 0x01

    with pytest.raises(AuthenticationError, match="Layer 2"):
        decrypt_cascade(
            final_ciphertext=bytes(tampered_ciphertext),
            tag_aes=tag_aes,
            nonce_aes=nonce_aes,
            nonce_chacha=nonce_chacha,
            key_chacha=key_chacha,
            key_aes=key_aes,
        )


def test_tamper_detection_tag_aes():
    secret = b"Highly confidential VeraCrypt Master Key"
    key_chacha = os.urandom(32)
    key_aes = os.urandom(32)

    final_ciphertext, tag_aes, nonce_chacha, nonce_aes = encrypt_cascade(
        secret, key_chacha, key_aes
    )

    tampered_tag = bytearray(tag_aes)
    tampered_tag[0] ^= 0x01

    with pytest.raises(AuthenticationError, match="Layer 2"):
        decrypt_cascade(
            final_ciphertext=final_ciphertext,
            tag_aes=bytes(tampered_tag),
            nonce_aes=nonce_aes,
            nonce_chacha=nonce_chacha,
            key_chacha=key_chacha,
            key_aes=key_aes,
        )


def test_tamper_detection_nonce_aes():
    secret = b"Highly confidential VeraCrypt Master Key"
    key_chacha = os.urandom(32)
    key_aes = os.urandom(32)

    final_ciphertext, tag_aes, nonce_chacha, nonce_aes = encrypt_cascade(
        secret, key_chacha, key_aes
    )

    tampered_nonce = bytearray(nonce_aes)
    tampered_nonce[0] ^= 0x01

    with pytest.raises(AuthenticationError, match="Layer 2"):
        decrypt_cascade(
            final_ciphertext=final_ciphertext,
            tag_aes=tag_aes,
            nonce_aes=bytes(tampered_nonce),
            nonce_chacha=nonce_chacha,
            key_chacha=key_chacha,
            key_aes=key_aes,
        )


def test_tamper_detection_nonce_chacha():
    secret = b"Highly confidential VeraCrypt Master Key"
    key_chacha = os.urandom(32)
    key_aes = os.urandom(32)

    final_ciphertext, tag_aes, nonce_chacha, nonce_aes = encrypt_cascade(
        secret, key_chacha, key_aes
    )

    tampered_nonce = bytearray(nonce_chacha)
    tampered_nonce[0] ^= 0x01

    with pytest.raises(AuthenticationError, match="Layer 1"):
        decrypt_cascade(
            final_ciphertext=final_ciphertext,
            tag_aes=tag_aes,
            nonce_aes=nonce_aes,
            nonce_chacha=bytes(tampered_nonce),
            key_chacha=key_chacha,
            key_aes=key_aes,
        )


def test_wrong_keys():
    secret = b"Highly confidential VeraCrypt Master Key"
    key_chacha = os.urandom(32)
    key_aes = os.urandom(32)

    final_ciphertext, tag_aes, nonce_chacha, nonce_aes = encrypt_cascade(
        secret, key_chacha, key_aes
    )

    wrong_key = os.urandom(32)

    # Wrong AES key fails Layer 2
    with pytest.raises(AuthenticationError, match="Layer 2"):
        decrypt_cascade(
            final_ciphertext=final_ciphertext,
            tag_aes=tag_aes,
            nonce_aes=nonce_aes,
            nonce_chacha=nonce_chacha,
            key_chacha=key_chacha,
            key_aes=wrong_key,
        )

    # Wrong ChaCha key fails Layer 1
    with pytest.raises(AuthenticationError, match="Layer 1"):
        decrypt_cascade(
            final_ciphertext=final_ciphertext,
            tag_aes=tag_aes,
            nonce_aes=nonce_aes,
            nonce_chacha=nonce_chacha,
            key_chacha=wrong_key,
            key_aes=key_aes,
        )


def test_zero_memory():
    buf = bytearray(b"sensitive_password_data")
    assert any(b != 0 for b in buf)
    zero_memory(buf)
    assert all(b == 0 for b in buf)
