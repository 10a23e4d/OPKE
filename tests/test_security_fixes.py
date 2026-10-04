"""Comprehensive tests for security vulnerabilities and remediations in OPKE v2.0."""

import os
import stat
import subprocess
import sys
import tempfile
import pytest

from opke.core import (
    derive_key_and_split,
    encrypt_cascade,
    decrypt_cascade,
)
from opke.envelope import (
    create_envelope,
    deserialize_envelope,
    EnvelopeValidationError,
    PEM_HEADER,
    PEM_FOOTER,
)
from opke.qr import generate_qr_image, print_terminal_qr
from opke.security import zero_memory, prompt_secret, MAX_SECRET_BYTES


def run_opke(args, input_data=None, env=None):
    cmd = [sys.executable, "-m", "opke.cli"] + args
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    return subprocess.run(
        cmd,
        input=input_data if isinstance(input_data, str) else (input_data.decode("utf-8") if input_data else None),
        capture_output=True,
        text=True,
        env=full_env,
    )


def test_binary_secret_integrity_with_trailing_newlines():
    """Ensure binary secrets ending in 0x0A (\\n) or 0x0D (\\r) are NOT truncated."""
    # Key ending with 0x0A (newline) and 0x0D (carriage return)
    binary_secret_a = os.urandom(31) + b"\x0a"
    binary_secret_b = os.urandom(30) + b"\x0d\x0a"
    binary_secret_c = os.urandom(31) + b"\x0d"

    key_chacha, key_aes = derive_key_and_split(b"testpass", os.urandom(16), m_kib=1024, t=1, p=1)

    for secret in [binary_secret_a, binary_secret_b, binary_secret_c]:
        c, tag, nc, na = encrypt_cascade(secret, key_chacha, key_aes)
        pt = decrypt_cascade(c, tag, na, nc, key_chacha, key_aes)
        assert pt == secret
        assert len(pt) == len(secret)
        assert isinstance(pt, bytearray)
        zero_memory(pt)


def test_file_input_preserves_binary_exact_bytes():
    """E2E test: File input (-i) preserves binary keys ending with newline."""
    binary_secret = b"\x01\x02\x03\x04\x05\x00\xff" + os.urandom(24) + b"\x0a"
    passphrase = "BinaryPreservationTestPass1"

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f_in:
        in_path = f_in.name
        f_in.write(binary_secret)

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f_env:
        env_path = f_env.name

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f_out:
        out_path = f_out.name

    try:
        # Encrypt from file
        enc = subprocess.run(
            [sys.executable, "-m", "opke.cli", "encrypt", "-i", in_path, "-o", env_path, "--profile", "test", "-p", passphrase],
            capture_output=True,
        )
        assert enc.returncode == 0

        # Decrypt to file
        dec = subprocess.run(
            [sys.executable, "-m", "opke.cli", "decrypt", "-i", env_path, "-o", out_path, "-p", passphrase],
            capture_output=True,
        )
        assert dec.returncode == 0

        # Verify exact byte equality
        with open(out_path, "rb") as f:
            restored = f.read()

        assert restored == binary_secret
        assert len(restored) == 32
        assert restored[-1] == 0x0A

    finally:
        for p in [in_path, env_path, out_path]:
            if os.path.exists(p):
                os.remove(p)


def test_secure_file_permissions():
    """Verify that decrypted files and encrypted files are created with 0600 permissions."""
    secret = "ConfidentialEmergencyKitData"
    passphrase = "PermTestPassword123"

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f_env:
        env_path = f_env.name
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f_out:
        out_path = f_out.name

    try:
        # Encrypt
        run_opke(["encrypt", secret, "-o", env_path, "--profile", "test", "-p", passphrase])

        # Check permissions of envelope file
        env_mode = stat.S_IMODE(os.stat(env_path).st_mode)
        assert env_mode == 0o600

        # Decrypt
        run_opke(["decrypt", "-i", env_path, "-o", out_path, "-p", passphrase])

        # Check permissions of decrypted file
        out_mode = stat.S_IMODE(os.stat(out_path).st_mode)
        assert out_mode == 0o600

    finally:
        for p in [env_path, out_path]:
            if os.path.exists(p):
                os.remove(p)


def test_symlink_rejection():
    """Verify that attempting to write output to a symlink is rejected."""
    secret = "SymlinkAttackTarget"
    passphrase = "SymlinkPass123"

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f_real:
        real_target = f_real.name
    symlink_path = os.path.join(tempfile.gettempdir(), "test_opke_symlink.txt")

    try:
        if os.path.exists(symlink_path):
            os.remove(symlink_path)
        os.symlink(real_target, symlink_path)

        # Attempt to write to symlink should fail
        res = run_opke(["encrypt", secret, "-o", symlink_path, "--profile", "test", "-p", passphrase])
        assert res.returncode != 0
        assert "Refusing to write to symlink" in res.stderr

    finally:
        if os.path.islink(symlink_path) or os.path.exists(symlink_path):
            os.remove(symlink_path)
        if os.path.exists(real_target):
            os.remove(real_target)


def test_cli_security_warning_on_args():
    """Verify that passing credentials via CLI flags emits a security warning to stderr."""
    res = run_opke(["encrypt", "secret-on-cli", "-p", "pass-on-cli", "--profile", "test", "--raw"])
    assert res.returncode == 0
    assert "[!] SECURITY WARNING" in res.stderr
    assert "process tables" in res.stderr


def test_env_passphrase_scrubbed():
    """Verify that OPKE_PASSPHRASE is popped from environment upon reading."""
    code = """
import os, sys
from opke.cli import build_parser, cmd_encrypt
os.environ['OPKE_PASSPHRASE'] = 'secret_env_pass'
parser = build_parser()
args = parser.parse_args(['encrypt', 'test_secret', '--profile', 'test', '--raw'])
cmd_encrypt(args)
# Verify OPKE_PASSPHRASE is gone
assert 'OPKE_PASSPHRASE' not in os.environ
print("ENV_SCRUBBED_OK")
"""
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "ENV_SCRUBBED_OK" in proc.stdout


def test_zero_memory_behavior():
    """Verify zero_memory behavior: raises on immutable types, zeros mutable buffers."""
    b_mut = bytearray(b"sensitive_bytes_to_zero")
    zero_memory(b_mut)
    assert all(b == 0 for b in b_mut)

    m_mut = memoryview(bytearray(b"view_bytes"))
    zero_memory(m_mut)
    assert all(b == 0 for b in m_mut.tobytes())

    # None is safely ignored
    zero_memory(None)

    # Immutable types must raise TypeError to prevent false sense of security
    with pytest.raises(TypeError, match="Cannot zero immutable type"):
        zero_memory(b"immutable_bytes")

    with pytest.raises(TypeError, match="Cannot zero immutable type"):
        zero_memory("immutable_str")


def test_envelope_schema_boolean_rejection():
    """Verify that boolean values (True/False) in JSON are strictly rejected as invalid types."""
    env = create_envelope(os.urandom(16), 65536, 2, 2, os.urandom(12), os.urandom(12), os.urandom(16), b"payload")
    d = env.to_dict()

    # t = True
    d_bool_t = dict(d)
    d_bool_t["kdf"] = dict(d["kdf"])
    d_bool_t["kdf"]["t"] = True
    import json
    with pytest.raises(EnvelopeValidationError, match="Invalid or out-of-range t"):
        deserialize_envelope(json.dumps(d_bool_t))

    # p = True
    d_bool_p = dict(d)
    d_bool_p["kdf"] = dict(d["kdf"])
    d_bool_p["kdf"]["p"] = True
    with pytest.raises(EnvelopeValidationError, match="Invalid or out-of-range p"):
        deserialize_envelope(json.dumps(d_bool_p))

    # v = 2.0 (float) or True (bool)
    d_bool_v = dict(d)
    d_bool_v["v"] = True
    with pytest.raises(EnvelopeValidationError, match="Unsupported envelope version"):
        deserialize_envelope(json.dumps(d_bool_v))


def test_envelope_incomplete_pem_markers():
    """Verify that incomplete PEM markers (header without footer or vice versa) are rejected."""
    payload = "dGVzdF9iYXNlNjQ="
    with pytest.raises(EnvelopeValidationError, match="incomplete header or footer"):
        deserialize_envelope(f"{PEM_HEADER}\n{payload}")

    with pytest.raises(EnvelopeValidationError, match="incomplete header or footer"):
        deserialize_envelope(f"{payload}\n{PEM_FOOTER}")


def test_qr_capacity_fallback_and_error():
    """Verify QR fallback to Level M/L and failure on oversize payload."""
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        png_path = f.name

    try:
        # A payload around 1500 chars exceeds Level H (max 1273B) but fits in Level M/L
        medium_payload = "A" * 1500
        generate_qr_image(medium_payload, png_path)
        assert os.path.exists(png_path)
        assert os.path.getsize(png_path) > 100

        # A payload over 3000 chars of 8-bit byte data exceeds Level L (max 2953B) and must raise ValueError
        oversize_payload = "b" * 3200
        with pytest.raises(ValueError, match="exceeds maximum QR code capacity"):
            generate_qr_image(oversize_payload, png_path)

    finally:
        if os.path.exists(png_path):
            os.remove(png_path)


def test_qr_failure_exits_nonzero():
    """Verify that if --qr generation fails, opke encrypt exits with non-zero code."""
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f_qr:
        qr_file = f_qr.name

    try:
        # 3200 characters of secret causes envelope > 3500 characters, exceeding QR capacity
        huge_secret = "X" * 3200
        res = run_opke(["encrypt", huge_secret, "-p", "testpass", "--profile", "test", "--qr", qr_file])
        assert res.returncode != 0
        assert "Failed to generate QR Code image" in res.stderr

    finally:
        if os.path.exists(qr_file):
            os.remove(qr_file)


def test_max_mem_limit_enforced():
    """Verify that --max-mem stops decryption if envelope exceeds the limit."""
    secret = "TestMaxMemSecret"
    passphrase = "MaxMemPass123"

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f_env:
        env_file = f_env.name

    try:
        # Encrypt with 65536 KiB (64 MiB)
        run_opke(["encrypt", secret, "-p", passphrase, "-o", env_file, "--profile", "test"])

        # Try decrypt with max-mem lower than 65536 KiB (e.g. 1024 KiB)
        dec_fail = run_opke(["decrypt", "-i", env_file, "-p", passphrase, "--max-mem", "1024"])
        assert dec_fail.returncode != 0
        assert "exceeds specified --max-mem limit" in dec_fail.stderr

        # Decrypt with sufficient max-mem should succeed
        dec_ok = run_opke(["decrypt", "-i", env_file, "-p", passphrase, "--max-mem", "100000"])
        assert dec_ok.returncode == 0
        assert dec_ok.stdout == secret

    finally:
        if os.path.exists(env_file):
            os.remove(env_file)
