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
    if !text.contains(PEM_HEADER) && !text.contains(PEM_FOOTER) {
        return Ok(text.to_string());
    }

    let mut in_block = false;
    let mut found_block = false;
    let mut payload = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == PEM_HEADER {
            if in_block || found_block {
                return Err(OpkeError::Envelope(
                    "Multiple PEM envelope markers detected; ambiguous input.".into(),
                ));
            }
            in_block = true;
        } else if trimmed == PEM_FOOTER {
            if !in_block {
                return Err(OpkeError::Envelope(
                    "Malformed PEM envelope: footer appears before header.".into(),
                ));
            }
            in_block = false;
            found_block = true;
        } else if in_block {
            payload.push_str(trimmed);
        }
    }

    if in_block {
        return Err(OpkeError::Envelope(
            "Malformed PEM envelope: incomplete header or footer.".into(),
        ));
    }

    if found_block {
        return Ok(payload);
    }

    // Fallback for compact/single-line formats where headers/footers share a line
    if let (Some(h_pos), Some(f_pos)) = (text.find(PEM_HEADER), text.rfind(PEM_FOOTER)) {
        if f_pos < h_pos + PEM_HEADER.len() {
            return Err(OpkeError::Envelope(
                "Malformed PEM envelope: footer appears before header.".into(),
            ));
        }
        let content = &text[h_pos + PEM_HEADER.len()..f_pos];
        if content.contains(PEM_HEADER) || content.contains(PEM_FOOTER) {
            return Err(OpkeError::Envelope(
                "Multiple PEM envelope markers detected; ambiguous input.".into(),
            ));
        }
        let cleaned: String = content.chars().filter(|c| !c.is_whitespace()).collect();
        return Ok(cleaned);
    }

    Err(OpkeError::Envelope(
        "Malformed PEM envelope: incomplete header or footer.".into(),
    ))
}
