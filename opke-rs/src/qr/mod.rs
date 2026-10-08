//! QR code generation for OPKE: image export and terminal rendering.

pub mod image;
pub mod terminal;

pub use image::generate_qr_image;
pub use terminal::{print_terminal_qr, print_terminal_qr_stderr};
