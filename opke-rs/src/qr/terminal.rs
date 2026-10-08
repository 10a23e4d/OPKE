//! Terminal QR code rendering using ANSI half-block characters.

use std::io::{self, Write};
use qrcode::{Color, EcLevel, QrCode};

use crate::error::OpkeError;

/// Renders a high-contrast half-block QR code directly to a writer (e.g. stderr).
pub fn print_terminal_qr<W: Write>(data: &str, mut out: W) -> Result<(), OpkeError> {
    if data.is_empty() {
        return Err(OpkeError::Validation("QR code data cannot be empty.".into()));
    }

    let levels = [EcLevel::M, EcLevel::L];
    let mut qr_code = None;
    for ec in levels {
        if let Ok(code) = QrCode::with_error_correction_level(data.as_bytes(), ec) {
            qr_code = Some(code);
            break;
        }
    }

    let code = match qr_code {
        Some(c) => c,
        None => return Ok(()), // Silently skip if data exceeds terminal QR capacity
    };

    let width = code.width();
    let quiet_zone = 2;
    let total_width = width + 2 * quiet_zone;
    let total_height = width + 2 * quiet_zone;

    // Helper to sample module at (x, y) including quiet zone (white background)
    let is_dark = |x: usize, y: usize| -> bool {
        if x < quiet_zone || x >= quiet_zone + width || y < quiet_zone || y >= quiet_zone + width {
            false
        } else {
            code[(x - quiet_zone, y - quiet_zone)] == Color::Dark
        }
    };

    // Render using Unicode half-blocks:
    // ▀ (upper dark, lower light)
    // ▄ (upper light, lower dark)
    // █ (both dark)
    // ' ' (both light)
    // Using white background (light) and black foreground (dark).
    for y in (0..total_height).step_by(2) {
        for x in 0..total_width {
            let top_dark = is_dark(x, y);
            let bottom_dark = if y + 1 < total_height {
                is_dark(x, y + 1)
            } else {
                false
            };

            let ch = match (top_dark, bottom_dark) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            };
            write!(out, "{}", ch).map_err(OpkeError::Io)?;
        }
        writeln!(out).map_err(OpkeError::Io)?;
    }

    out.flush().map_err(OpkeError::Io)?;
    Ok(())
}

/// Convenience function to render QR code to stderr.
pub fn print_terminal_qr_stderr(data: &str) -> Result<(), OpkeError> {
    print_terminal_qr(data, io::stderr())
}
