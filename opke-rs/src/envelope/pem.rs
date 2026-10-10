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

    if !b64_payload.is_ascii() {
        return Err(OpkeError::Validation(
            "Base64 payload contains non-ASCII characters.".into(),
        ));
    }

    let num_lines = if b64_payload.is_empty() {
        0
    } else {
        b64_payload.len().div_ceil(line_length)
    };
    let cap = PEM_HEADER.len() + 1 + b64_payload.len() + num_lines + PEM_FOOTER.len() + 1;
    let mut output = String::with_capacity(cap);
    output.push_str(PEM_HEADER);
    output.push('\n');

    for chunk in b64_payload.as_bytes().chunks(line_length) {
        let line = std::str::from_utf8(chunk).map_err(|e| {
            OpkeError::Validation(format!("Invalid non-UTF-8 chunk in payload: {}", e))
        })?;
        output.push_str(line);
        output.push('\n');
    }

    output.push_str(PEM_FOOTER);
    output.push('\n');

    Ok(output)
}

/// Strips PEM header/footer if present, extracting encapsulated content per RFC 7468.
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
        let header_idx = text.find(PEM_HEADER).unwrap();
        let footer_idx = text.find(PEM_FOOTER).unwrap();
        let content_start = header_idx + PEM_HEADER.len();
        if footer_idx < content_start {
            return Err(OpkeError::Envelope(
                "Malformed PEM envelope: footer appears before header.".into(),
            ));
        }
        // RFC 7468: Explanatory text outside the encapsulation boundaries is ignored.
        let stripped = &text[content_start..footer_idx];
        return Ok(stripped.trim().to_string());
    }

    Ok(text.to_string())
}
