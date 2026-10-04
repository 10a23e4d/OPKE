"""Unit tests for QR code generation utilities."""

import io
import os
import tempfile
import pytest

from opke.qr import generate_qr_image, print_terminal_qr


def test_generate_qr_png():
    payload = "test_payload_for_qr_generation_opke_v2"
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        tmp_path = f.name

    try:
        generate_qr_image(payload, tmp_path)
        assert os.path.exists(tmp_path)
        file_size = os.path.getsize(tmp_path)
        assert file_size > 100  # Valid PNG image size

        # Verify PNG header
        with open(tmp_path, "rb") as f:
            header = f.read(8)
            assert header == b"\x89PNG\r\n\x1a\n"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_generate_qr_svg():
    payload = "test_payload_for_qr_svg_generation"
    with tempfile.NamedTemporaryFile(suffix=".svg", delete=False) as f:
        tmp_path = f.name

    try:
        generate_qr_image(payload, tmp_path)
        assert os.path.exists(tmp_path)
        with open(tmp_path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "<svg" in content
            assert "</svg>" in content
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_print_terminal_qr():
    payload = "compact_terminal_qr_test"
    buffer = io.StringIO()
    print_terminal_qr(payload, stream=buffer)
    output = buffer.getvalue()
    assert len(output) > 0
