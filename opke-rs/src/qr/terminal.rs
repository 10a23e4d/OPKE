//! Terminal QR code rendering using ANSI half-block characters.

use qrcode::{Color, EcLevel, QrCode};
use std::io::{self, Write};

use crate::error::OpkeError;

/// Renders a high-contrast half-block QR code directly to a writer (e.g. stderr).
pub fn print_terminal_qr<W: Write>(data: &str, mut out: W) -> Result<(), OpkeError> {
    if data.is_empty() {
        return Err(OpkeError::Validation(
            "Terminal QR generation unavailable: data is empty".into(),
        ));
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
        None => {
            return Err(OpkeError::ResourceLimit(
                "Terminal QR generation unavailable: data exceeds maximum QR code capacity (2,953 bytes).".into(),
            ));
        }
    };

    let width = code.width();
    let quiet_zone = 4; // ISO/IEC 18004 4-module quiet zone (VULN-94)
    let total_width = width + 2 * quiet_zone;
    let mut total_height = width + 2 * quiet_zone;
    // Ensure total_height is even so the bottom quiet zone row is not truncated to a half-block (VULN-155)
    if total_height % 2 != 0 {
        total_height += 1;
    }

    // Helper to sample module at (x, y) including quiet zone (white background)
    let is_dark = |x: usize, y: usize| -> bool {
        if x < quiet_zone || x >= quiet_zone + width || y < quiet_zone || y >= quiet_zone + width {
            false
        } else {
            code[(x - quiet_zone, y - quiet_zone)] == Color::Dark
        }
    };

    // Render using Unicode half-blocks with ANSI white background (47) and black foreground (30)
    // to guarantee standard QR code polarity on both dark and light terminal themes (VULN-53).
    // ▀ (upper dark, lower light)
    // ▄ (upper light, lower dark)
    // █ (both dark)
    // ' ' (both light)
    for y in (0..total_height).step_by(2) {
        write!(out, "\x1b[47m\x1b[30m").map_err(OpkeError::Io)?;
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
        writeln!(out, "\x1b[0m").map_err(OpkeError::Io)?;
    }

    out.flush().map_err(OpkeError::Io)?;
    Ok(())
}

#[cfg(windows)]
fn enable_windows_vt_mode() {
    const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4; // -12i32 as u32
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> *mut std::ffi::c_void;
        fn GetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, dwMode: u32) -> i32;
    }
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        if !handle.is_null() && handle as isize != -1 {
            let mut mode = 0u32;
            if GetConsoleMode(handle, &mut mode) != 0 {
                let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

/// Convenience function to render QR code to stderr.
pub fn print_terminal_qr_stderr(data: &str) -> Result<(), OpkeError> {
    #[cfg(windows)]
    enable_windows_vt_mode();

    print_terminal_qr(data, io::stderr())
}
