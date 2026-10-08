//! PEM format encoding and decoding for paper key cold storage.

use crate::error::OpkeError;

pub const PEM_HEADER: &str = "-----BEGIN OPKE ENVELOPE-----";
pub const PEM_FOOTER: &str = "-----END OPKE ENVELOPE-----";

/// Wraps Base64 payload in paper-friendly PEM header/footer with 64-character lines.
pub fn to_paper_format(b64_payload: &str, line_length: usize) -> Result<String, OpkeError> {
    if !(16..=1024).contains(&line_length) {
        return Err(OpkeError::Validation(format!(
            "Invalid line_length: {} (must be between 16 and 1024)",
            line_length
        )));
    }

    let mut output = String::with_capacity(b64_payload.len() + 100);
    output.push_str(PEM_HEADER);
    output.push('\n');

    let chars: Vec<char> = b64_payload.chars().collect();
    for chunk in chars.chunks(line_length) {
        let line: String = chunk.iter().collect();
        output.push_str(&line);
        output.push('\n');
    }

    output.push_str(PEM_FOOTER);
    output.push('\n');

    Ok(output)
}

/// Strips PEM header/footer if present, strictly verifying boundary integrity.
pub fn strip_pem(raw_input: &str) -> Result<String, OpkeError> {
    let text = raw_input.trim();
    let has_header = text.contains(PEM_HEADER);
    let has_footer = text.contains(PEM_FOOTER);

    if has_header || has_footer {
        if !(has_header && has_footer) {
            return Err(OpkeError::Envelope(
                "Malformed PEM envelope: incomplete header or footer.".into(),
            ));
        }
        if text.matches(PEM_HEADER).count() > 1 || text.matches(PEM_FOOTER).count() > 1 {
            return Err(OpkeError::Envelope(
                "Multiple PEM envelope markers detected; ambiguous input.".into(),
            ));
        }
        if !text.starts_with(PEM_HEADER) || !text.ends_with(PEM_FOOTER) {
            return Err(OpkeError::Envelope(
                "Malformed PEM envelope: unexpected data outside encapsulation boundary.".into(),
            ));
        }
        let stripped = &text[PEM_HEADER.len()..text.len() - PEM_FOOTER.len()];
        return Ok(stripped.trim().to_string());
    }

    Ok(text.to_string())
}
