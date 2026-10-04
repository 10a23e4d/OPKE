"""QR Code generation utilities for OPKE v2.0.

Supports:
- High error correction level (Level H: 30% restoration capability)
- PNG and SVG image export for paper printing
- Terminal ANSI/Unicode block rendering for immediate screen scanning
"""

import io
import sys
from typing import Optional
import qrcode
import qrcode.constants
from qrcode.image.svg import SvgImage

from opke.security import write_secure_file


VALID_EC_LEVELS = {
    qrcode.constants.ERROR_CORRECT_L,
    qrcode.constants.ERROR_CORRECT_M,
    qrcode.constants.ERROR_CORRECT_Q,
    qrcode.constants.ERROR_CORRECT_H,
}


def generate_qr_image(
    data: str,
    output_path: str,
    error_correction: int = qrcode.constants.ERROR_CORRECT_H,
    box_size: int = 10,
    border: int = 4,
) -> None:
    """Generates a QR code image file (PNG or SVG) from data.

    Attempts generation with requested error_correction (default Level H).
    If data exceeds capacity, automatically falls back to Level Q, Level M, then Level L.
    Raises ValueError if data exceeds the maximum capacity of QR Version 40 (2,953 bytes).

    Uses write_secure_file to prevent symlink attacks and race conditions,
    ensuring 0600 permissions upon creation.

    Args:
        data: String to encode in the QR code (typically the Base64 envelope).
        output_path: Target file path (.png or .svg).
        error_correction: Preferred QR error correction level.
        box_size: Number of pixels per QR box.
        border: Quiet zone border width in boxes.
    """
    if not isinstance(output_path, str) or not output_path.strip():
        raise ValueError("Invalid output_path: must be a non-empty string.")
    if not isinstance(data, str) or not data:
        raise ValueError("QR code data cannot be empty.")
    if error_correction not in VALID_EC_LEVELS:
        raise ValueError(f"Invalid error_correction level: {error_correction}")

    lower_path = output_path.lower()
    if not (lower_path.endswith(".png") or lower_path.endswith(".svg")):
        raise ValueError(f"QR code output format unsupported: '{output_path}'. Target file must have a .png or .svg extension.")
    is_svg = lower_path.endswith(".svg")
    image_factory = SvgImage if is_svg else None

    if type(box_size) is not int or box_size < 1 or box_size > 100:
        raise ValueError(f"Invalid box_size: {box_size} (must be integer between 1 and 100)")
    if type(border) is not int or border < 0 or border > 50:
        raise ValueError(f"Invalid border: {border} (must be integer between 0 and 50)")

    # Priority of error correction levels to try
    levels = [
        error_correction,
        qrcode.constants.ERROR_CORRECT_Q,
        qrcode.constants.ERROR_CORRECT_M,
        qrcode.constants.ERROR_CORRECT_L,
    ]
    # Deduplicate while preserving order
    seen = set()
    ec_levels = [x for x in levels if not (x in seen or seen.add(x))]

    qr_obj = None
    last_err = None
    for ec in ec_levels:
        try:
            candidate_qr = qrcode.QRCode(
                version=None,
                error_correction=ec,
                box_size=box_size,
                border=border,
                image_factory=image_factory,
            )
            candidate_qr.add_data(data)
            candidate_qr.make(fit=True)
            qr_obj = candidate_qr
            break
        except Exception as e:
            last_err = e

    if qr_obj is None:
        raise ValueError(
            f"Envelope size ({len(data)} chars) exceeds maximum QR code capacity (2,953 bytes). "
            f"Please use the PEM text envelope instead. ({last_err})"
        )

    img = qr_obj.make_image(fill_color="black", back_color="white")
    bio = io.BytesIO()
    if is_svg:
        img.save(bio)
    else:
        img.save(bio, format="PNG")

    write_secure_file(output_path, bio.getvalue(), is_binary=True)


def print_terminal_qr(
    data: str,
    stream: Optional[io.TextIOBase] = None,
    error_correction: int = qrcode.constants.ERROR_CORRECT_M,
) -> None:
    """Renders a compact QR code directly into the terminal using ANSI blocks.

    Defaults to stderr to avoid corrupting stdout redirection pipelines.
    """
    if stream is None:
        stream = sys.stderr

    if error_correction not in VALID_EC_LEVELS:
        raise ValueError(f"Invalid error_correction level: {error_correction}")
    if not isinstance(data, str) or not data:
        try:
            print("[-] Terminal QR generation unavailable: data is empty", file=stream)
        except BrokenPipeError:
            pass
        return

    last_err = None
    levels = [error_correction]
    if error_correction != qrcode.constants.ERROR_CORRECT_L:
        levels.append(qrcode.constants.ERROR_CORRECT_L)

    for ec in levels:
        try:
            qr = qrcode.QRCode(
                version=None,
                error_correction=ec,
                border=2,
            )
            qr.add_data(data)
            qr.make(fit=True)
            qr.print_ascii(out=stream, invert=True)
            return
        except BrokenPipeError:
            return
        except Exception as e:
            last_err = e

    try:
        print(f"[-] Terminal QR generation unavailable: {last_err}", file=stream)
    except BrokenPipeError:
        pass
