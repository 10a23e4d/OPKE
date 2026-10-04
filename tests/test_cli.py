"""End-to-end and unit tests for OPKE CLI commands."""

import os
import subprocess
import sys
import tempfile
import pytest

from opke.cli import build_parser, main
from opke.envelope import PEM_HEADER, PEM_FOOTER


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


def test_cli_version():
    res = run_opke(["--version"])
    assert res.returncode == 0
    assert "OPKE (Offline Paper-Key Encryptor) v2.0.0" in res.stdout


def test_cli_encrypt_and_decrypt_roundtrip():
    secret_text = "VeraCrypt-Master-Key-9941a88b8e0b497491cf"
    passphrase = "UltraSecureLongMemorablePassword"

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f_env:
        env_file = f_env.name
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f_qr:
        qr_file = f_qr.name

    try:
        # 1. Encrypt with fast profile for quick test run
        enc_res = run_opke(
            [
                "encrypt",
                secret_text,
                "-p", passphrase,
                "-o", env_file,
                "--profile", "test",
                "--qr", qr_file,
            ]
        )
        assert enc_res.returncode == 0
        assert os.path.exists(env_file)
        assert os.path.exists(qr_file)

        with open(env_file, "r", encoding="utf-8") as f:
            envelope_text = f.read()
        assert PEM_HEADER in envelope_text
        assert PEM_FOOTER in envelope_text

        # 2. Inspect envelope
        ins_res = run_opke(["inspect", "-i", env_file])
        assert ins_res.returncode == 0
        assert "Version:         2" in ins_res.stdout
        assert "chacha20-poly1305 -> aes-256-gcm" in ins_res.stdout

        # 3. Decrypt with correct passphrase
        dec_res = run_opke(["decrypt", "-i", env_file, "-p", passphrase])
        assert dec_res.returncode == 0
        assert dec_res.stdout.strip() == secret_text

        # 4. Decrypt with wrong passphrase should fail
        dec_wrong = run_opke(["decrypt", "-i", env_file, "-p", "WrongPassword"])
        assert dec_wrong.returncode != 0
        assert "Layer 2 (AES-GCM) authentication tag verification failed" in dec_wrong.stderr

    finally:
        if os.path.exists(env_file):
            os.remove(env_file)
        if os.path.exists(qr_file):
            os.remove(qr_file)


def test_cli_pipe_roundtrip():
    secret_text = "Emergency-Kit-Token-XYZ-999-AAA"
    passphrase = "PipePassphrase456"

    # Pipe secret into encrypt, output raw Base64 to stdout
    enc_res = run_opke(
        ["encrypt", "-p", passphrase, "--profile", "test", "--raw"],
        input_data=secret_text,
    )
    assert enc_res.returncode == 0
    b64_output = enc_res.stdout.strip()
    assert len(b64_output) > 50

    # Pipe raw Base64 into decrypt
    dec_res = run_opke(
        ["decrypt", "-p", passphrase],
        input_data=b64_output,
    )
    assert dec_res.returncode == 0
    assert dec_res.stdout.strip() == secret_text


def test_cli_benchmark():
    # Run benchmark with test/fast settings
    res = run_opke(["benchmark", "--profile", "test"])
    assert res.returncode == 0
    assert "Completed in" in res.stdout
    assert "Memory bandwidth evaluated" in res.stdout
