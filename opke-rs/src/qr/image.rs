//! QR Code image generation (PNG and SVG) with automatic error correction level fallback.

use image::{Rgb, RgbImage};
use qrcode::{render::svg, Color, EcLevel, QrCode};
use std::path::Path;

use crate::error::OpkeError;
use crate::security::write_secure_file_with_options;

pub const MAX_QR_CAPACITY_BYTES: usize = 2953;

/// Generates a PNG or SVG QR code image file from string data.
/// Attempts generation with Level H, falling back to Level Q, Level M, Level L if size requires.
pub fn generate_qr_image(data: &str, output_path: impl AsRef<Path>) -> Result<(), OpkeError> {
    generate_qr_image_with_options(data, output_path, false)
}

/// Generates a PNG or SVG QR code image file with explicit --force override for ACLs (VULN-32).
pub fn generate_qr_image_with_options(
    data: &str,
    output_path: impl AsRef<Path>,
    force: bool,
) -> Result<(), OpkeError> {
    let p = output_path.as_ref();
    if p.as_os_str().is_empty() || p.to_string_lossy().trim().is_empty() {
        return Err(OpkeError::Validation(
            "Invalid output_path: path cannot be empty.".into(),
        ));
    }

    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() && std::fs::symlink_metadata(parent).is_err() {
            return Err(OpkeError::Validation(format!(
                "Invalid output_path: parent directory '{}' does not exist.",
                parent.display()
            )));
        }
    }

    let lower_ext = p
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_lowercase();

    if lower_ext != "png" && lower_ext != "svg" {
        return Err(OpkeError::Validation(format!(
            "QR code output format unsupported: '{}'. Target file must have a .png or .svg extension.",
            p.display()
        )));
    }

    if data.is_empty() {
        return Err(OpkeError::Validation(
            "QR code data cannot be empty.".into(),
        ));
    }

    let levels = [EcLevel::H, EcLevel::Q, EcLevel::M, EcLevel::L];
    let mut qr_code = None;
    let mut last_err = String::new();

    for ec in levels {
        match QrCode::with_error_correction_level(data.as_bytes(), ec) {
            Ok(code) => {
                qr_code = Some(code);
                break;
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
    }

    let code = qr_code.ok_or_else(|| {
        OpkeError::Validation(format!(
            "Envelope size ({} chars) exceeds maximum QR code capacity ({} bytes). Please use the PEM text envelope instead. ({})",
            data.len(),
            MAX_QR_CAPACITY_BYTES,
            last_err
        ))
    })?;

    if lower_ext == "svg" {
        let svg_data = code
            .render()
            .min_dimensions(300, 300)
            .quiet_zone(true)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build();
        write_secure_file_with_options(p, svg_data.as_bytes(), force)?;
    } else {
        // High quality pixel rendering matching Python box_size = 10, border = 4
        let width = code.width();
        let border = 4usize;
        let box_size = 10usize;
        let total_modules = width + 2 * border;
        let img_dimension = (total_modules * box_size) as u32;

        let mut img = RgbImage::from_pixel(img_dimension, img_dimension, Rgb([255, 255, 255]));

        for y in 0..width {
            for x in 0..width {
                if code[(x, y)] == Color::Dark {
                    let start_x = ((x + border) * box_size) as u32;
                    let start_y = ((y + border) * box_size) as u32;
                    for dy in 0..(box_size as u32) {
                        for dx in 0..(box_size as u32) {
                            img.put_pixel(start_x + dx, start_y + dy, Rgb([0, 0, 0]));
                        }
                    }
                }
            }
        }

        let mut png_bytes = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut png_bytes),
            image::ImageFormat::Png,
        )
        .map_err(|e| OpkeError::Crypto(format!("Failed to encode PNG: {}", e)))?;

        write_secure_file_with_options(p, &png_bytes, force)?;
    }

    Ok(())
}
