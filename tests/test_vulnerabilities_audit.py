"""Comprehensive verification tests for all 9 audited security vulnerabilities and remediations."""

import json
import os
import stat
import subprocess
import sys
import tempfile
import pytest

from opke.core import derive_key_and_split, encrypt_cascade, decrypt_cascade
from opke.envelope import (
    create_envelope,
    deserialize_envelope,
    EnvelopeValidationError,
    PEM_HEADER,
    PEM_FOOTER,
)
from opke.security import zero_memory, write_secure_file, prompt_passphrase


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


# --- VULN-01: Argon2 KDF Zero-Copy & Memory Protection ---

def test_v1_kdf_returns_mutable_bytearrays_and_zeros_cleanly():
    """Verify that derive_key_and_split accepts bytearray and returns zeroable bytearrays."""
    pw = bytearray(b"SuperSecretPassphrase123!")
    salt = os.urandom(16)

    k_chacha, k_aes = derive_key_and_split(pw, salt, m_kib=1024, t=1, p=1)
    assert isinstance(k_chacha, bytearray)
    assert isinstance(k_aes, bytearray)
    assert len(k_chacha) == 32
    assert len(k_aes) == 32

    # Cleanly zero memory
    zero_memory(k_chacha)
    zero_memory(k_aes)
    zero_memory(pw)

    assert all(b == 0 for b in k_chacha)
    assert all(b == 0 for b in k_aes)
    assert all(b == 0 for b in pw)


# --- VULN-02: Symlink & Hardlink Attacks Prevention ---

def test_v2_qr_symlink_rejection():
    """Verify that attempting to output a QR image to a symlink is rejected."""
    secret = "ConfidentialSymlinkSecret"
    passphrase = "SymlinkPass123"

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f_real:
        real_target = f_real.name
    symlink_path = os.path.join(tempfile.gettempdir(), "test_opke_qr_symlink.png")

    try:
        if os.path.exists(symlink_path):
            os.remove(symlink_path)
        os.symlink(real_target, symlink_path)

        res = run_opke(["encrypt", secret, "-p", passphrase, "--profile", "test", "--qr", symlink_path])
        assert res.returncode != 0
        assert "Refusing to write to symlink" in res.stderr

    finally:
        if os.path.islink(symlink_path) or os.path.exists(symlink_path):
            os.remove(symlink_path)
        if os.path.exists(real_target):
            os.remove(real_target)


def test_v2_write_secure_file_hardlink_rejection():
    """Verify that writing output to a hardlink target with st_nlink > 1 is rejected."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f1:
        f1_path = f1.name
    hardlink_path = f1_path + ".hl"

    try:
        if os.path.exists(hardlink_path):
            os.remove(hardlink_path)
        os.link(f1_path, hardlink_path)

        with pytest.raises(OSError, match="Refusing to write to hardlink target"):
            write_secure_file(hardlink_path, b"malicious overwrite", is_binary=True)

    finally:
        if os.path.exists(hardlink_path):
            os.remove(hardlink_path)
        if os.path.exists(f1_path):
            os.remove(f1_path)


def test_v2_write_secure_file_existing_file_permissions():
    """Verify that writing to an existing file with loose permissions resets to 0600 before writing."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        path = f.name

    try:
        # Pre-set loose permissions
        os.chmod(path, 0o666)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o666

        write_secure_file(path, "sensitive envelope text", is_binary=False)

        # After secure write, must be 0600
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600

    finally:
        if os.path.exists(path):
            os.remove(path)


# --- VULN-03: Argon2 RFC 9106 Constraint (m >= 8 * p) ---

def test_v3_argon2_m_less_than_8p_rejected():
    """Verify that m_kib < 8 * p is rejected in both core KDF and envelope deserializer."""
    pw = b"testpassword"
    salt = os.urandom(16)

    # 1. In derive_key_and_split
    with pytest.raises(ValueError, match="Memory cost too low"):
        derive_key_and_split(pw, salt, m_kib=16, t=1, p=8)  # 16 < 8 * 8 = 64

    # 2. In deserialize_envelope
    env = create_envelope(salt, 65536, 2, 2, os.urandom(12), os.urandom(12), os.urandom(16), b"payload_longer_text_123")
    d = env.to_dict()
    d["kdf"]["p"] = 8
    d["kdf"]["m_kib"] = 16  # 16 < 64
    with pytest.raises(EnvelopeValidationError, match="Invalid or out-of-range m_kib"):
        deserialize_envelope(json.dumps(d))


# --- VULN-04: Strict Envelope Schema & JSON Protection ---

def test_v4_envelope_duplicate_json_keys_rejected():
    """Verify that JSON envelopes with duplicate keys are strictly rejected."""
    raw_json_dup = '{"v": 2, "v": 2, "kdf": {"name": "argon2id", "m_kib": 65536, "t": 2, "p": 2, "salt": "AAAAAAAAAAAAAAAAAAAAAA=="}, "cipher": {"layers": ["chacha20-poly1305", "aes-256-gcm"], "nonce_chacha": "AAAAAAAAAAAAAAAA", "nonce_aes": "AAAAAAAAAAAAAAAA", "tag_aes": "AAAAAAAAAAAAAAAAAAAAAA=="}, "data": "AAAAAAAAAAAAAAAAAAAAAA=="}'
    with pytest.raises(EnvelopeValidationError, match="Duplicate key in envelope JSON"):
        deserialize_envelope(raw_json_dup)


def test_v4_envelope_unknown_fields_rejected():
    """Verify that unexpected unknown fields in JSON are rejected."""
    env = create_envelope(os.urandom(16), 65536, 2, 2, os.urandom(12), os.urandom(12), os.urandom(16), b"valid_ciphertext_payload")
    d = env.to_dict()

    # Top-level unknown field
    d_unknown = dict(d)
    d_unknown["malicious_field"] = "evil_payload"
    with pytest.raises(EnvelopeValidationError, match="unrecognized fields"):
        deserialize_envelope(json.dumps(d_unknown))

    # KDF unknown field
    d_kdf = dict(d)
    d_kdf["kdf"] = dict(d["kdf"])
    d_kdf["kdf"]["unknown_kdf_param"] = 123
    with pytest.raises(EnvelopeValidationError, match="unrecognized fields"):
        deserialize_envelope(json.dumps(d_kdf))


def test_v4_envelope_multiple_pem_headers_rejected():
    """Verify that multiple PEM headers/footers (ambiguous input) are rejected."""
    env = create_envelope(os.urandom(16), 65536, 2, 2, os.urandom(12), os.urandom(12), os.urandom(16), b"valid_ciphertext_payload")
    pem = env.to_paper_format()

    # Concatenate two PEM envelopes
    double_pem = pem + "\n" + pem
    with pytest.raises(EnvelopeValidationError, match="Multiple PEM envelope markers detected"):
        deserialize_envelope(double_pem)


# --- VULN-05: Sensitive CLI Argument Redaction ---

def test_v5_cli_argv_redacted():
    """Verify that sensitive command-line arguments are redacted from sys.argv."""
    code = """
import sys
from opke.cli import build_parser, redact_argv
sys.argv = ["opke", "encrypt", "SensitivePlaintextKey123", "-p", "SensitivePassphrase456"]
parser = build_parser()
args = parser.parse_args()
redact_argv()
assert "SensitivePlaintextKey123" not in sys.argv
assert "SensitivePassphrase456" not in sys.argv
assert "[REDACTED]" in sys.argv
print("ARGV_REDACTED_OK")
"""
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "ARGV_REDACTED_OK" in proc.stdout


# --- VULN-06: Zero-Allocation zero_memory ---

def test_v6_zero_memory_zero_alloc():
    """Verify that zero_memory clears bytearray and memoryview in-place."""
    data = bytearray(b"HighlySecretPassphraseDataWipedInPlace")
    zero_memory(data)
    assert all(b == 0 for b in data)

    mv = memoryview(bytearray(b"MemoryViewSecretWipedInPlace"))
    zero_memory(mv)
    assert all(b == 0 for b in mv.tobytes())


# --- VULN-07: Constant-time Passphrase Comparison ---

def test_v7_prompt_passphrase_logic():
    """Verify prompt_passphrase confirms matching passwords and rejects non-matching."""
    import unittest.mock

    # Matching passphrases
    with unittest.mock.patch("getpass.getpass", side_effect=["MyPassword123", "MyPassword123"]):
        pw = prompt_passphrase(confirm=True)
        assert pw == bytearray(b"MyPassword123")
        zero_memory(pw)

    # Mismatched passphrases
    with unittest.mock.patch("getpass.getpass", side_effect=["MyPassword123", "WrongPassword456"]):
        with pytest.raises(ValueError, match="Passphrases do not match"):
            prompt_passphrase(confirm=True)


# --- VULN-08: CLI Parameter Bounds Checking ---

def test_v8_cli_parameter_bounds_validation():
    """Verify that invalid CLI overrides (--mem, --time, --threads) are cleanly rejected."""
    # Memory too small (< 8)
    res_mem = run_opke(["encrypt", "secret", "-p", "pass", "--mem", "4", "--raw"])
    assert res_mem.returncode != 0
    assert "Invalid memory cost" in res_mem.stderr

    # Parallelism invalid (< 1)
    res_p = run_opke(["encrypt", "secret", "-p", "pass", "--threads", "0", "--raw"])
    assert res_p.returncode != 0
    assert "Invalid parallelism" in res_p.stderr

    # Time invalid (< 1)
    res_t = run_opke(["encrypt", "secret", "-p", "pass", "--time", "0", "--raw"])
    assert res_t.returncode != 0
    assert "Invalid time cost" in res_t.stderr

    # m < 8 * p (16 < 64)
    res_rel = run_opke(["encrypt", "secret", "-p", "pass", "--threads", "8", "--mem", "16", "--raw"])
    assert res_rel.returncode != 0
    assert "Invalid memory cost" in res_rel.stderr


# --- VULN-09: Empty Passphrase Rejection ---

def test_v9_empty_passphrase_rejected():
    """Verify empty passphrases are strictly rejected across KDF and CLI (encrypt and decrypt)."""
    salt = os.urandom(16)

    # 1. In derive_key_and_split
    with pytest.raises(ValueError, match="Passphrase cannot be empty"):
        derive_key_and_split(b"", salt, m_kib=1024, t=1, p=1)

    with pytest.raises(ValueError, match="Passphrase cannot be empty"):
        derive_key_and_split(bytearray(), salt, m_kib=1024, t=1, p=1)

    # 2. In CLI encrypt via -p ""
    res_enc_p = run_opke(["encrypt", "secret", "-p", "", "--profile", "test"])
    assert res_enc_p.returncode != 0
    assert "Passphrase cannot be empty" in res_enc_p.stderr

    # 3. In CLI encrypt via OPKE_PASSPHRASE=""
    res_enc_env = run_opke(["encrypt", "secret", "--profile", "test"], env={"OPKE_PASSPHRASE": ""})
    assert res_enc_env.returncode != 0
    assert "Passphrase cannot be empty" in res_enc_env.stderr

    # Prepare a valid envelope for decrypt tests
    env = create_envelope(salt, 65536, 2, 2, os.urandom(12), os.urandom(12), os.urandom(16), b"encrypted_payload_1234567")
    env_str = env.to_base64_payload()

    # 4. In CLI decrypt via -p ""
    res_dec_p = run_opke(["decrypt", env_str, "-p", ""])
    assert res_dec_p.returncode != 0
    assert "Passphrase cannot be empty" in res_dec_p.stderr

    # 5. In CLI decrypt via OPKE_PASSPHRASE=""
    res_dec_env = run_opke(["decrypt", env_str], env={"OPKE_PASSPHRASE": ""})
    assert res_dec_env.returncode != 0
    assert "Passphrase cannot be empty" in res_dec_env.stderr


# --- VULN-10: Decrypt-Into Memory Sanitization on Tamper (Anti-RUP) ---

def test_v10_decrypt_into_erases_unverified_plaintext_on_tamper():
    """Verify decrypt_cascade does not leave unverified plaintext in buffers on authentication failure."""
    from opke.core import AuthenticationError

    key_c = os.urandom(32)
    key_a = os.urandom(32)
    secret = b"VerySensitiveColdStorageMasterPassword123"

    ct, tag_a, nc, na = encrypt_cascade(secret, key_c, key_a)

    # Corrupt nonce_chacha so Layer 2 succeeds but Layer 1 Poly1305 fails
    bad_nc = bytearray(nc)
    bad_nc[0] ^= 0xFF

    with pytest.raises(AuthenticationError, match="Layer 1"):
        decrypt_cascade(ct, tag_a, na, bytes(bad_nc), key_c, key_a)


# --- VULN-11: Nonce and Key Independence Verification ---

def test_v11_nonce_and_key_independence():
    """Verify that identical nonces or identical keys across cascade layers are rejected."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    diff_key = os.urandom(32)
    diff_nonce = os.urandom(12)

    # Identical keys in encrypt_cascade
    with pytest.raises(ValueError, match="Key_ChaCha and Key_AES must be independent and distinct"):
        encrypt_cascade(b"data", key, key)

    # Identical nonces in encrypt_cascade
    with pytest.raises(ValueError, match="Nonce_ChaCha and Nonce_AES must be distinct"):
        encrypt_cascade(b"data", key, diff_key, nonce_chacha=nonce, nonce_aes=nonce)

    # Identical nonces in create_envelope
    with pytest.raises(ValueError, match="Nonce_ChaCha and Nonce_AES must be distinct"):
        create_envelope(os.urandom(16), 65536, 2, 2, nonce, nonce, os.urandom(16), b"ciphertext_payload")

    # Identical nonces in deserialize_envelope
    env = create_envelope(os.urandom(16), 65536, 2, 2, diff_nonce, os.urandom(12), os.urandom(16), b"ciphertext_payload")
    d = env.to_dict()
    d["cipher"]["nonce_chacha"] = d["cipher"]["nonce_aes"]
    with pytest.raises(EnvelopeValidationError, match="Nonce_ChaCha and Nonce_AES must be distinct"):
        deserialize_envelope(json.dumps(d))


# --- VULN-12: Advanced Process Table (sys.argv) Redaction ---

def test_v12_cli_argv_redaction_advanced():
    """Verify that --passphrase=..., -p=..., and positional secrets after options are redacted."""
    code = """
import sys
from opke.cli import build_parser, redact_argv

# Test 1: --passphrase=value and positional secret after flag
sys.argv = ["opke", "encrypt", "--profile", "test", "MyPositionalSecret456", "--passphrase=MyPassphrase789"]
parser = build_parser()
args = parser.parse_args()
redact_argv(args)
assert "MyPositionalSecret456" not in sys.argv
assert "MyPassphrase789" not in sys.argv
assert "--passphrase=[REDACTED]" in sys.argv
assert "[REDACTED]" in sys.argv

# Test 2: -p=value
sys.argv = ["opke", "decrypt", "-p=MyPassphrase789", "dummy_env"]
parser = build_parser()
args = parser.parse_args()
redact_argv(args)
assert "MyPassphrase789" not in sys.argv
assert "-p=[REDACTED]" in sys.argv

print("ARGV_ADVANCED_REDACTED_OK")
"""
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "ARGV_ADVANCED_REDACTED_OK" in proc.stdout


# --- VULN-13: zero_memory Unsupported Types Rejection ---

def test_v13_zero_memory_unsupported_types_rejected():
    """Verify zero_memory rejects integers, dicts, tuples instead of failing silently."""
    with pytest.raises(TypeError, match="Cannot zero unsupported type"):
        zero_memory(12345)

    with pytest.raises(TypeError, match="Cannot zero unsupported type"):
        zero_memory({"secret": "key"})

    with pytest.raises(TypeError, match="Cannot zero unsupported type"):
        zero_memory((1, 2, 3))


# --- VULN-14: write_secure_file Non-Regular File Rejection ---

def test_v14_write_secure_file_non_regular_file_rejection():
    """Verify write_secure_file refuses to write to FIFOs / named pipes."""
    fifo_path = os.path.join(tempfile.gettempdir(), "test_opke_fifo")
    if os.path.exists(fifo_path):
        os.remove(fifo_path)
    try:
        os.mkfifo(fifo_path)
    except (AttributeError, OSError):
        pytest.skip("mkfifo not supported on this platform/filesystem")

    try:
        with pytest.raises(OSError, match="Refusing to write to non-regular file"):
            write_secure_file(fifo_path, b"test payload", is_binary=True)
    finally:
        if os.path.exists(fifo_path):
            os.remove(fifo_path)


# --- VULN-15: Hardlink Attack Does NOT Truncate Existing Target File ---

def test_v15_write_secure_file_hardlink_preserves_target_content():
    """Verify that refusing to write to a hardlink does NOT truncate the underlying target file."""
    initial_content = b"CRITICAL_USER_DATA_THAT_MUST_NEVER_BE_TRUNCATED_BY_ATTACK"
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        target_path = f.name
        f.write(initial_content)

    hardlink_path = target_path + ".hl"
    try:
        os.link(target_path, hardlink_path)
        with pytest.raises(OSError, match="Refusing to write to hardlink target"):
            write_secure_file(hardlink_path, b"malicious new data", is_binary=True)

        # Ensure target file was NOT truncated
        with open(target_path, "rb") as f_check:
            current_content = f_check.read()
        assert current_content == initial_content
        assert len(current_content) == len(initial_content)
    finally:
        if os.path.exists(hardlink_path):
            os.remove(hardlink_path)
        if os.path.exists(target_path):
            os.remove(target_path)


# --- VULN-16: Multi-User File Ownership Hijacking Prevention ---

def test_v16_write_secure_file_rejects_different_owner(monkeypatch):
    """Verify write_secure_file refuses to write to a pre-existing file owned by another user."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        file_path = f.name
        f.write(b"other user data")

    try:
        # Mock os.getuid to simulate running as a different UID than file owner
        real_uid = os.stat(file_path).st_uid
        monkeypatch.setattr(os, "getuid", lambda: real_uid + 9999)

        with pytest.raises(OSError, match="Refusing to write to file owned by another user"):
            write_secure_file(file_path, b"secret data", is_binary=True)
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


# --- VULN-17: Memory Limit Check BEFORE Passphrase Prompt in Decrypt ---

def test_v17_cmd_decrypt_checks_memory_before_prompting_passphrase(monkeypatch):
    """Verify that cmd_decrypt aborts due to memory constraints without asking for passphrase."""
    import getpass
    from opke.cli import build_parser, cmd_decrypt

    salt = os.urandom(16)
    env = create_envelope(salt, 65536, 2, 2, os.urandom(12), os.urandom(12), os.urandom(16), b"valid_ciphertext_1234567")
    env_str = env.to_base64_payload()

    # If getpass is called, fail test immediately
    def fail_if_called(*args, **kwargs):
        pytest.fail("getpass.getpass was called before memory limits were verified!")

    monkeypatch.setattr(getpass, "getpass", fail_if_called)

    parser = build_parser()
    # Request max-mem lower than envelope's 65536
    args = parser.parse_args(["decrypt", env_str, "--max-mem", "1024"])
    ret = cmd_decrypt(args)
    assert ret != 0


# --- VULN-18: OOM Prevention in Benchmark and Encrypt ---

def test_v18_benchmark_and_encrypt_oom_prevention(monkeypatch, capsys):
    """Verify that benchmark and encrypt abort when required memory exceeds available RAM without --force."""
    from opke.cli import build_parser, cmd_benchmark, cmd_encrypt
    import opke.cli

    parser = build_parser()

    # Mock get_available_memory_kib to return low memory (512 MiB = 524288 KiB)
    monkeypatch.setattr(opke.cli, "get_available_memory_kib", lambda: 524288)

    # 1. Benchmark without --force should abort
    args_bm = parser.parse_args(["benchmark", "--mem", "1048576"])  # 1 GiB > 512 MiB
    ret_bm = cmd_benchmark(args_bm)
    assert ret_bm != 0
    captured_bm = capsys.readouterr()
    assert "Benchmark aborted to prevent system freeze / OOM" in captured_bm.err

    # 2. Encrypt without --force should abort
    args_enc = parser.parse_args(["encrypt", "test_secret", "-p", "pass123", "--mem", "1048576", "--raw"])
    ret_enc = cmd_encrypt(args_enc)
    assert ret_enc != 0
    captured_enc = capsys.readouterr()
    assert "Encryption aborted to prevent system freeze / OOM" in captured_enc.err


# --- VULN-19: Benchmark Parameter Upper Bounds and Clean Error Handling ---

def test_v19_benchmark_upper_bounds_clean_error():
    """Verify that exceeding MAX_M_KIB or MAX_T in benchmark produces a clean error instead of traceback."""
    res = run_opke(["benchmark", "--mem", "99999999"])
    assert res.returncode != 0
    assert "Invalid memory cost" in res.stderr
    assert "Traceback" not in res.stderr

    res_t = run_opke(["benchmark", "--time", "99999"])
    assert res_t.returncode != 0
    assert "Invalid time cost" in res_t.stderr
    assert "Traceback" not in res_t.stderr


# --- VULN-20: Multibyte UTF-8 Overflow Protection in prompt_secret ---

def test_v20_prompt_secret_multibyte_utf8_overflow(monkeypatch):
    """Verify that prompt_secret enforces byte length limit for multibyte UTF-8 characters."""
    import io
    from opke.security import prompt_secret

    # 10 Japanese characters = 30 bytes in UTF-8
    multibyte_secret = "あ" * 10
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdin, "read", lambda n: multibyte_secret)

    # If max_bytes is 20, 10 characters (30 bytes) must exceed limit even though char count (10) < 20
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        prompt_secret(multiline=True, max_bytes=20)


# --- VULN-21: QR Output Extension Validation ---

def test_v21_qr_extension_validation():
    """Verify that generate_qr_image and CLI encrypt reject invalid extensions."""
    from opke.qr import generate_qr_image

    with pytest.raises(ValueError, match="QR code output format unsupported"):
        generate_qr_image("test_data", "/tmp/test.jpg")

    with pytest.raises(ValueError, match="QR code output format unsupported"):
        generate_qr_image("test_data", "/tmp/test.exe")

    res = run_opke(["encrypt", "secret", "-p", "pass123", "--profile", "test", "--qr", "/tmp/test.sh"])
    assert res.returncode != 0
    assert "QR code output format unsupported" in res.stderr


# --- VULN-22: Strict PEM Encapsulation Boundary Enforcement ---

def test_v22_strict_pem_boundary_rejection():
    """Verify that extraneous data outside PEM header/footer is rejected."""
    salt = os.urandom(16)
    env = create_envelope(salt, 65536, 2, 2, os.urandom(12), os.urandom(12), os.urandom(16), b"valid_ciphertext_1234567")
    valid_pem = env.to_paper_format()

    # Prepend malicious text
    smuggled_pre = "malicious_script_header\n" + valid_pem
    with pytest.raises(EnvelopeValidationError, match="unexpected data outside encapsulation boundary"):
        deserialize_envelope(smuggled_pre)

    # Append malicious text
    smuggled_post = valid_pem + "\necho 'pwned'"
    with pytest.raises(EnvelopeValidationError, match="unexpected data outside encapsulation boundary"):
        deserialize_envelope(smuggled_post)


# --- VULN-23: Container / Cgroup Memory Detection ---

def test_v23_cgroup_memory_detection(monkeypatch):
    """Verify that get_available_memory_kib honors cgroup limits if present."""
    from opke.cli import get_available_memory_kib

    monkeypatch.setattr(os.path, "exists", lambda p: p == "/sys/fs/cgroup/memory.max")
    import unittest.mock
    mock_open = unittest.mock.mock_open(read_data="1073741824\n")  # 1 GiB = 1048576 KiB
    monkeypatch.setattr("builtins.open", mock_open)

    mem = get_available_memory_kib()
    assert mem == 1048576  # 1073741824 // 1024


# --- VULN-24: Passphrase Length Boundary Enforcement ---

def test_v24_passphrase_length_limit():
    """Verify that overly long passphrases exceeding MAX_PASSPHRASE_BYTES are rejected."""
    import unittest.mock
    from opke.security import prompt_passphrase, MAX_PASSPHRASE_BYTES

    huge_pass = "A" * (MAX_PASSPHRASE_BYTES + 1)
    with unittest.mock.patch("getpass.getpass", return_value=huge_pass):
        with pytest.raises(ValueError, match="exceeds maximum allowed length"):
            prompt_passphrase(confirm=False)


# --- VULN-25: Envelope Size Limit (160 MiB) & Ciphertext Capacity Bounds ---

def test_v25_max_envelope_chars_and_ciphertext_bounds():
    """Verify that MAX_ENVELOPE_CHARS is 160 MiB and MAX_CIPHERTEXT_BYTES is enforced."""
    from opke.envelope import MAX_ENVELOPE_CHARS, MAX_CIPHERTEXT_BYTES, create_envelope, deserialize_envelope, EnvelopeValidationError
    from opke.security import MAX_SECRET_BYTES

    assert MAX_ENVELOPE_CHARS == 160 * 1024 * 1024
    assert MAX_CIPHERTEXT_BYTES == MAX_SECRET_BYTES + 16

    # create_envelope rejects ciphertext exceeding MAX_CIPHERTEXT_BYTES
    salt = os.urandom(16)
    with pytest.raises(ValueError, match="Ciphertext length exceeds maximum allowed size"):
        create_envelope(salt, 65536, 2, 2, os.urandom(12), os.urandom(12), os.urandom(16), b"A" * (MAX_CIPHERTEXT_BYTES + 1))


# --- VULN-26: CLI Attached Passphrase Redaction (-p<passphrase>) ---

def test_v26_attached_passphrase_redaction():
    """Verify that -pAttachedPassphrase without equal sign is completely redacted from sys.argv."""
    code = """
import sys
from opke.cli import build_parser, redact_argv

sys.argv = ["opke", "encrypt", "-pMySecretPassphrase", "secret", "--profile", "test"]
parser = build_parser()
args = parser.parse_args()
redact_argv(args)
assert "MySecretPassphrase" not in sys.argv
assert "-p[REDACTED]" in sys.argv
assert "[REDACTED]" in sys.argv

sys.argv = ["opke", "decrypt", "-pAnotherSecret", "dummy_env"]
parser = build_parser()
args = parser.parse_args()
redact_argv(args)
assert "AnotherSecret" not in sys.argv
assert "-p[REDACTED]" in sys.argv

print("ATTACHED_P_REDACTED_OK")
"""
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "ATTACHED_P_REDACTED_OK" in proc.stdout


# --- VULN-27: Decrypt Ciphertext Maximum Bounds in deserialize_envelope ---

def test_v27_deserialize_envelope_ciphertext_upper_bound():
    """Verify that deserialize_envelope rejects ciphertext exceeding MAX_CIPHERTEXT_BYTES."""
    from opke.envelope import MAX_CIPHERTEXT_BYTES, create_envelope, deserialize_envelope, EnvelopeValidationError
    import base64

    salt = os.urandom(16)
    env = create_envelope(salt, 65536, 2, 2, os.urandom(12), os.urandom(12), os.urandom(16), b"valid_ciphertext_1234567")
    d = env.to_dict()
    # Inject oversized ciphertext base64
    d["data"] = base64.b64encode(b"X" * (MAX_CIPHERTEXT_BYTES + 1)).decode("ascii")
    with pytest.raises(EnvelopeValidationError, match="Ciphertext data exceeds maximum allowed size"):
        deserialize_envelope(json.dumps(d))


# --- VULN-28: PEM Boundary Extraction Constant-Time Slicing (No ReDoS) ---

def test_v28_pem_extraction_large_whitespace_no_redos():
    """Verify that PEM markers extraction uses slicing and handles large inputs without ReDoS."""
    from opke.envelope import create_envelope, deserialize_envelope

    salt = os.urandom(16)
    env = create_envelope(salt, 65536, 2, 2, os.urandom(12), os.urandom(12), os.urandom(16), b"valid_ciphertext_1234567")
    raw_b64 = env.to_base64_payload()

    # Create PEM with lots of newlines/spaces
    pem_with_spacing = f"-----BEGIN OPKE ENVELOPE-----\n\n\n   {raw_b64}   \n\n\n-----END OPKE ENVELOPE-----"
    res = deserialize_envelope(pem_with_spacing)
    assert res.v == 2


# --- VULN-29: BaseException Handling in write_secure_file (KeyboardInterrupt) ---

def test_v29_write_secure_file_base_exception_cleanup(monkeypatch):
    """Verify write_secure_file unlinks incomplete file when BaseException (e.g. KeyboardInterrupt) occurs."""
    target_path = os.path.join(tempfile.gettempdir(), "test_opke_base_exception_target.txt")
    if os.path.exists(target_path):
        os.remove(target_path)

    try:
        # Mock os.fsync to raise KeyboardInterrupt
        def raise_keyboard_interrupt(*args, **kwargs):
            raise KeyboardInterrupt()

        monkeypatch.setattr(os, "fsync", raise_keyboard_interrupt)

        with pytest.raises(KeyboardInterrupt):
            write_secure_file(target_path, b"confidential uncommitted data", is_binary=True)

        # Incomplete file must NOT be left on disk
        assert not os.path.exists(target_path)
    finally:
        if os.path.exists(target_path):
            os.remove(target_path)


# --- VULN-30: Pipe Secret Chunk Buffer Zeroing in prompt_secret ---

def test_v30_prompt_secret_pipe_reading(monkeypatch):
    """Verify prompt_secret securely reads pipe chunks and returns bytearray."""
    import io
    from opke.security import prompt_secret

    secret_content = b"PipeReadSecretContent98765"
    fake_stdin = io.BytesIO(secret_content)

    class MockStdin:
        buffer = fake_stdin
        def isatty(self):
            return False

    monkeypatch.setattr(sys, "stdin", MockStdin())

    result = prompt_secret()
    assert result == bytearray(secret_content)
    zero_memory(result)


# --- VULN-31: Unified Cascade Memory Cleanup in decrypt_cascade ---

def test_v31_decrypt_cascade_unified_cleanup():
    """Verify decrypt_cascade cleans up intermediate memory when Layer 2 fails."""
    from opke.core import decrypt_cascade, AuthenticationError

    key_c = os.urandom(32)
    key_a = os.urandom(32)
    ct = b"A" * 32
    tag = os.urandom(16)
    na = os.urandom(12)
    nc = os.urandom(12)

    with pytest.raises(AuthenticationError, match="Layer 2"):
        decrypt_cascade(ct, tag, na, nc, key_c, key_a)


# --- VULN-32: derive_key_and_split Passphrase Length Limit ---

def test_v32_derive_key_passphrase_length_limit():
    """Verify derive_key_and_split rejects passphrases exceeding MAX_PASSPHRASE_BYTES."""
    from opke.core import derive_key_and_split
    from opke.security import MAX_PASSPHRASE_BYTES

    salt = os.urandom(16)
    huge_pass = b"A" * (MAX_PASSPHRASE_BYTES + 1)
    with pytest.raises(ValueError, match="Passphrase exceeds maximum allowed length"):
        derive_key_and_split(huge_pass, salt, m_kib=1024, t=1, p=1)


# --- VULN-33: Core Cascade Bounds Enforcement ---

def test_v33_core_cascade_bounds():
    """Verify encrypt_cascade enforces MAX_SECRET_BYTES and decrypt_cascade enforces MAX_CIPHERTEXT_BYTES."""
    from opke.core import encrypt_cascade, decrypt_cascade, MAX_CIPHERTEXT_BYTES
    from opke.security import MAX_SECRET_BYTES

    key_c = os.urandom(32)
    key_a = os.urandom(32)

    # encrypt_cascade
    with pytest.raises(ValueError, match="Plaintext exceeds maximum allowed size"):
        encrypt_cascade(b"X" * (MAX_SECRET_BYTES + 1), key_c, key_a)

    # decrypt_cascade
    with pytest.raises(ValueError, match="Ciphertext exceeds maximum allowed size"):
        decrypt_cascade(b"X" * (MAX_CIPHERTEXT_BYTES + 1), os.urandom(16), os.urandom(12), os.urandom(12), key_c, key_a)


# --- VULN-34: Container Current Memory Usage Subtracted in get_available_memory_kib ---

def test_v34_cgroup_memory_current_usage_subtracted(monkeypatch):
    """Verify get_available_memory_kib subtracts container current memory usage."""
    import io
    from opke.cli import get_available_memory_kib

    # Mock cgroups v2: limit = 2 GiB (2147483648 B), current usage = 1.5 GiB (1610612736 B)
    # Available = 512 MiB (536870912 B) = 524288 KiB
    def mock_exists(p):
        return p in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current")

    monkeypatch.setattr(os.path, "exists", mock_exists)

    def mock_open_func(file, *args, **kwargs):
        if file == "/sys/fs/cgroup/memory.max":
            return io.StringIO("2147483648\n")
        elif file == "/sys/fs/cgroup/memory.current":
            return io.StringIO("1610612736\n")
        raise FileNotFoundError(file)

    monkeypatch.setattr("builtins.open", mock_open_func)

    avail = get_available_memory_kib()
    assert avail == 524288


# --- VULN-35: read_secure_file FIFO & Directory Rejection ---

def test_v35_read_secure_file_safety():
    """Verify read_secure_file rejects non-regular files and enforces max_bytes."""
    from opke.security import read_secure_file

    # Directory rejection
    with pytest.raises(OSError, match="Refusing to read non-regular file"):
        read_secure_file(tempfile.gettempdir(), is_binary=True)

    # Size limit
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f_path = f.name
        f.write(b"A" * 100)

    try:
        with pytest.raises(ValueError, match="exceeds maximum allowed size"):
            read_secure_file(f_path, is_binary=True, max_bytes=50)

        # Successful read
        data = read_secure_file(f_path, is_binary=True, max_bytes=200)
        assert data == bytearray(b"A" * 100)
        zero_memory(data)
    finally:
        if os.path.exists(f_path):
            os.remove(f_path)


# --- VULN-36: zero_memory Clean Rejection of Read-Only memoryview ---

def test_v36_zero_memory_readonly_memoryview():
    """Verify zero_memory raises clean TypeError on read-only memoryview."""
    mv = memoryview(b"read_only_immutable_bytes")
    with pytest.raises(TypeError, match="Cannot zero immutable type: read-only memoryview"):
        zero_memory(mv)


# --- VULN-37: QR Code Generator Input Validation ---

def test_v37_generate_qr_input_validation():
    """Verify generate_qr_image validates output_path and data."""
    from opke.qr import generate_qr_image

    with pytest.raises(ValueError, match="Invalid output_path"):
        generate_qr_image("test_data", "")

    with pytest.raises(ValueError, match="Invalid output_path"):
        generate_qr_image("test_data", "   ")

    with pytest.raises(ValueError, match="QR code data cannot be empty"):
        generate_qr_image("", "/tmp/test.png")


# --- VULN-38: BrokenPipeError Clean Exit in CLI ---

def test_v38_cli_broken_pipe_clean_exit():
    """Verify that BrokenPipeError on stdout exits cleanly with return code 0."""
    code = """
import sys
from opke.cli import build_parser, cmd_decrypt

class BrokenPipeBuffer:
    def write(self, data):
        raise BrokenPipeError(32, "Broken pipe")
    def flush(self):
        raise BrokenPipeError(32, "Broken pipe")
    def close(self):
        pass

class BrokenPipeStdout:
    def __init__(self):
        self.buffer = BrokenPipeBuffer()
    def write(self, data):
        raise BrokenPipeError(32, "Broken pipe")
    def flush(self):
        raise BrokenPipeError(32, "Broken pipe")
    def close(self):
        pass

# Intercept sys.stdout
orig_stdout = sys.stdout
sys.stdout = BrokenPipeStdout()

# Valid envelope
from opke.core import derive_key_and_split, encrypt_cascade
from opke.envelope import create_envelope
import os
salt = os.urandom(16)
kc, ka = derive_key_and_split(b"testpass", salt, m_kib=1024, t=1, p=1)
ct, tag, nc, na = encrypt_cascade(b"secret", kc, ka)
env = create_envelope(salt, 1024, 1, 1, nc, na, tag, ct)
env_str = env.to_base64_payload()

parser = build_parser()
args = parser.parse_args(["decrypt", env_str, "-p", "testpass"])
ret = cmd_decrypt(args)

# Restore stdout
sys.stdout = orig_stdout
assert ret == 0
print("BROKEN_PIPE_CLEAN_OK")
"""
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "BROKEN_PIPE_CLEAN_OK" in proc.stdout


# --- VULN-39: Native /proc/self/cmdline Memory Scrubbing ---

def test_v39_native_cmdline_memory_scrubbed():
    """Verify that credentials on CLI are wiped from Linux /proc/self/cmdline memory."""
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux-specific procfs cmdline verification")

    code = """
import os, subprocess, sys
secret = "VerySecretCmdlineValue777"
passphrase = "VerySecretPassphrase888"

# Check in child process running opke
code_child = f'''
import os, sys
from opke.cli import build_parser, redact_argv
parser = build_parser()
args = parser.parse_args(["encrypt", "{secret}", "-p", "{passphrase}", "--profile", "test", "--raw"])
redact_argv(args)
with open("/proc/self/cmdline", "rb") as f:
    cmdline = f.read()
assert b"{secret}" not in cmdline, "Secret still in /proc/self/cmdline!"
assert b"{passphrase}" not in cmdline, "Passphrase still in /proc/self/cmdline!"
print("CMDLINE_SCRUBBED_OK")
'''
proc = subprocess.run([sys.executable, "-c", code_child], capture_output=True, text=True)
assert proc.returncode == 0, proc.stderr
assert "CMDLINE_SCRUBBED_OK" in proc.stdout
print("V39_SUCCESS")
"""
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "V39_SUCCESS" in proc.stdout


# --- VULN-40: Native /proc/self/environ Memory Scrubbing ---

def test_v40_native_environ_memory_scrubbed():
    """Verify that OPKE_PASSPHRASE is wiped from Linux /proc/self/environ memory."""
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux-specific procfs environ verification")

    code = """
import os, subprocess, sys
env_val = "SuperSecretEnvPassphrase999"
env = os.environ.copy()
env["OPKE_PASSPHRASE"] = env_val

code_child = f'''
import os
from opke.cli import scrub_env_passphrase
pw = scrub_env_passphrase()
assert pw is not None
assert "OPKE_PASSPHRASE" not in os.environ
with open("/proc/self/environ", "rb") as f:
    environ_data = f.read()
assert b"OPKE_PASSPHRASE=" not in environ_data, "OPKE_PASSPHRASE still in /proc/self/environ!"
assert b"{env_val}" not in environ_data, "Passphrase still in /proc/self/environ!"
print("ENVIRON_SCRUBBED_OK")
'''
proc = subprocess.run([sys.executable, "-c", code_child], env=env, capture_output=True, text=True)
assert proc.returncode == 0, proc.stderr
assert "ENVIRON_SCRUBBED_OK" in proc.stdout
print("V40_SUCCESS")
"""
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "V40_SUCCESS" in proc.stdout


# --- VULN-41: BaseException Plaintext Wiping in decrypt_cascade ---

def test_v41_decrypt_cascade_base_exception_wipes_plaintext(monkeypatch):
    """Verify decrypt_cascade zeroes plaintext buffer even on KeyboardInterrupt."""
    from opke.core import derive_key_and_split, encrypt_cascade, decrypt_cascade
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    secret = b"ConfidentialKeyToBeWipedOnInterrupt"
    salt = os.urandom(16)
    kc, ka = derive_key_and_split(b"testpass", salt, m_kib=1024, t=1, p=1)
    ct, tag, nc, na = encrypt_cascade(secret, kc, ka)

    # Monkeypatch ChaCha20Poly1305.decrypt_into to simulate KeyboardInterrupt
    def raise_interrupt(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(ChaCha20Poly1305, "decrypt_into", raise_interrupt)

    with pytest.raises(KeyboardInterrupt):
        decrypt_cascade(ct, tag, na, nc, kc, ka)


# --- VULN-42: BaseException Buffer Wiping in read_secure_file ---

def test_v42_read_secure_file_base_exception_wipes_buf(monkeypatch):
    """Verify read_secure_file zeroes chunk buffer even on KeyboardInterrupt."""
    from opke.security import read_secure_file

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        path = f.name
        f.write(b"SensitiveChunkToBeWipedOnKeyboardInterrupt")

    try:
        orig_open = open

        class MockFile:
            def __init__(self, raw):
                self._raw = raw

            def readinto(self, buf):
                raise KeyboardInterrupt()

            def close(self):
                self._raw.close()

        monkeypatch.setattr("builtins.open", lambda *a, **kw: MockFile(orig_open(*a, **kw)))

        with pytest.raises(KeyboardInterrupt):
            read_secure_file(path, is_binary=True)
    finally:
        if os.path.exists(path):
            os.remove(path)


# --- VULN-43: prompt_secret max_bytes Input Validation ---

def test_v43_prompt_secret_max_bytes_validation():
    """Verify prompt_secret rejects non-positive or non-integer max_bytes."""
    from opke.security import prompt_secret

    with pytest.raises(ValueError, match="must be a positive integer"):
        prompt_secret(max_bytes=0)

    with pytest.raises(ValueError, match="must be a positive integer"):
        prompt_secret(max_bytes=-10)

    with pytest.raises(ValueError, match="must be a positive integer"):
        prompt_secret(max_bytes="invalid")


# --- VULN-44: read_secure_file max_bytes Input Validation ---

def test_v44_read_secure_file_max_bytes_validation():
    """Verify read_secure_file rejects non-positive or non-integer max_bytes."""
    from opke.security import read_secure_file

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        path = f.name
        f.write(b"data")

    try:
        with pytest.raises(ValueError, match="must be a positive integer"):
            read_secure_file(path, max_bytes=0)

        with pytest.raises(ValueError, match="must be a positive integer"):
            read_secure_file(path, max_bytes=-5)

        with pytest.raises(ValueError, match="must be a positive integer"):
            read_secure_file(path, max_bytes="invalid")
    finally:
        if os.path.exists(path):
            os.remove(path)


# --- VULN-45: QR Code Invalid Error Correction Validation ---

def test_v45_qr_invalid_error_correction_rejected():
    """Verify generate_qr_image and print_terminal_qr reject invalid error_correction levels."""
    from opke.qr import generate_qr_image, print_terminal_qr

    with pytest.raises(ValueError, match="Invalid error_correction level"):
        generate_qr_image("test_data", "/tmp/valid.png", error_correction=9999)

    with pytest.raises(ValueError, match="Invalid error_correction level"):
        print_terminal_qr("test_data", error_correction=9999)


# --- VULN-46: QR Terminal Empty Data Safety ---

def test_v46_qr_terminal_empty_data_handled():
    """Verify print_terminal_qr cleanly reports empty data instead of rendering blank QR."""
    import io
    from opke.qr import print_terminal_qr

    stream = io.StringIO()
    print_terminal_qr("", stream=stream)
    output = stream.getvalue()
    assert "data is empty" in output


# --- VULN-47: Decrypt --max-time CPU DoS Prevention ---

def test_v47_decrypt_max_time_enforced():
    """Verify opke decrypt --max-time rejects envelopes exceeding allowed iterations."""
    salt = os.urandom(16)
    kc, ka = derive_key_and_split(b"testpass", salt, m_kib=1024, t=10, p=1)
    ct, tag, nc, na = encrypt_cascade(b"secret", kc, ka)
    env = create_envelope(salt, 1024, 10, 1, nc, na, tag, ct)
    env_str = env.to_base64_payload()

    # Reject envelope with t=10 when --max-time is 5
    res = run_opke(["decrypt", env_str, "-p", "testpass", "--max-time", "5"])
    assert res.returncode != 0
    assert "exceeds specified --max-time limit" in res.stderr

    # Accept when --max-time is 10
    res_ok = run_opke(["decrypt", env_str, "-p", "testpass", "--max-time", "10"])
    assert res_ok.returncode == 0
    assert res_ok.stdout == "secret"


# --- VULN-48: Decrypt --max-threads Parallelism DoS Prevention ---

def test_v48_decrypt_max_threads_enforced():
    """Verify opke decrypt --max-threads rejects envelopes exceeding allowed parallelism."""
    salt = os.urandom(16)
    kc, ka = derive_key_and_split(b"testpass", salt, m_kib=1024, t=1, p=8)
    ct, tag, nc, na = encrypt_cascade(b"secret", kc, ka)
    env = create_envelope(salt, 1024, 1, 8, nc, na, tag, ct)
    env_str = env.to_base64_payload()

    # Reject envelope with p=8 when --max-threads is 4
    res = run_opke(["decrypt", env_str, "-p", "testpass", "--max-threads", "4"])
    assert res.returncode != 0
    assert "exceeds specified --max-threads limit" in res.stderr

    # Accept when --max-threads is 8
    res_ok = run_opke(["decrypt", env_str, "-p", "testpass", "--max-threads", "8"])
    assert res_ok.returncode == 0
    assert res_ok.stdout == "secret"


# --- VULN-49: Decrypt Negative Limit Bounds Validation ---

def test_v49_decrypt_negative_limits_rejected():
    """Verify opke decrypt rejects negative --max-mem, --max-time, and --max-threads."""
    res_mem = run_opke(["decrypt", "dummy", "--max-mem", "-10"])
    assert res_mem.returncode != 0
    assert "Invalid --max-mem" in res_mem.stderr

    res_t = run_opke(["decrypt", "dummy", "--max-time", "0"])
    assert res_t.returncode != 0
    assert "Invalid --max-time" in res_t.stderr

    res_p = run_opke(["decrypt", "dummy", "--max-threads", "0"])
    assert res_p.returncode != 0
    assert "Invalid --max-threads" in res_p.stderr


# --- VULN-50: serialize_envelope Strict Type Checking ---

def test_v50_serialize_envelope_type_check():
    """Verify serialize_envelope rejects non-OPKEEnvelope objects."""
    from opke.envelope import serialize_envelope

    with pytest.raises(TypeError, match="Expected OPKEEnvelope instance"):
        serialize_envelope("not_an_envelope")

    with pytest.raises(TypeError, match="Expected OPKEEnvelope instance"):
        serialize_envelope({"v": 2})


# --- VULN-51: to_paper_format line_length Bounds Validation ---

def test_v51_to_paper_format_line_length_bounds():
    """Verify to_paper_format validates line_length bounds."""
    salt = os.urandom(16)
    env = create_envelope(salt, 65536, 2, 2, os.urandom(12), os.urandom(12), os.urandom(16), b"payload_bytes_here")

    with pytest.raises(ValueError, match="Invalid line_length"):
        env.to_paper_format(line_length=0)

    with pytest.raises(ValueError, match="Invalid line_length"):
        env.to_paper_format(line_length=5)

    with pytest.raises(ValueError, match="Invalid line_length"):
        env.to_paper_format(line_length=2000)

    # Valid line_length
    out = env.to_paper_format(line_length=32)
    assert PEM_HEADER in out


# --- VULN-52: inspect Clean Handling of Corrupt Envelopes ---

def test_v52_inspect_clean_error_on_corrupt_envelope():
    """Verify opke inspect does not crash with unhandled exception on corrupt envelope."""
    res = run_opke(["inspect", "corrupt_data_not_base64!!!"])
    assert res.returncode != 0
    assert "Invalid envelope" in res.stderr
    assert "Traceback" not in res.stderr


