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


def generate_qr_image(
    data: str,
    output_path: str,
    error_correction: int = qrcode.constants.ERROR_CORRECT_H,
    box_size: int = 10,
    border: int = 4,
) -> None:
    """Generates a QR code image file (PNG or SVG) from data.

    Args:
        data: String to encode in the QR code (typically the Base64 envelope).
        output_path: Target file path (.png or .svg).
        error_correction: QR error correction level (default ERROR_CORRECT_H = 30%).
        box_size: Number of pixels per QR box.
        border: Quiet zone border width in boxes.
    """
    is_svg = output_path.lower().endswith(".svg")
    image_factory = SvgImage if is_svg else None

    qr = qrcode.QRCode(
        version=None,  # Automatically determine minimum version required
        error_correction=error_correction,
        box_size=box_size,
        border=border,
        image_factory=image_factory,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_path)


def print_terminal_qr(
    data: str,
    stream: Optional[io.TextIOBase] = None,
    error_correction: int = qrcode.constants.ERROR_CORRECT_M,
) -> None:
    """Renders a compact QR code directly into the terminal using ANSI blocks.

    Uses ERROR_CORRECT_M for terminal display to keep the matrix size compact
    enough to fit within typical terminal window widths.
    """
    if stream is None:
        stream = sys.stdout

    qr = qrcode.QRCode(
        version=None,
        error_correction=error_correction,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)

    # Use qrcode's built-in ASCII/Unicode block renderer
    qr.print_ascii(out=stream, invert=True)
