//! Security integration tests covering deep-dive vulnerabilities (VULN-75 to VULN-121).

use clap::Parser;
use opke::cli::args::Cli;
use opke::core::{decrypt_cascade, encrypt_cascade, NONCE_LEN, SUBKEY_LEN};
use opke::envelope::{create_envelope, deserialize_envelope, pem};
use opke::qr::print_terminal_qr;
use opke::security::write_secure_file;
use tempfile::NamedTempFile;

// =========================================================================
// VULN-78: Duplicate JSON key detection with Unicode escape sequences
// =========================================================================
#[test]
fn test_v78_duplicate_json_keys_with_unicode_escapes() {
    // 1. Unicode escape for 'v' (\u0076) alongside literal "v"
    let json_escaped_v = r#"{
        "\u0076": 3,
        "v": 2,
        "kdf": {
            "name": "argon2id",
            "m_kib": 65536,
            "t": 2,
            "p": 2,
            "salt": "AAAAAAAAAAAAAAAAAAAAAA=="
        },
        "cipher": {
            "layers": ["chacha20-poly1305", "aes-256-gcm"],
            "nonce_chacha": "AQEBAQEBAQEBAQEB",
            "nonce_aes": "AgICAgICAgICAgIC",
            "tag_aes": "AwMDAwMDAwMDAwMDAwMDAw=="
        },
        "data": "dmFsaWRfY2lwaGVydGV4dF8xMjM0NTY3"
    }"#;

    let res = deserialize_envelope(json_escaped_v);
    assert!(
        res.is_err(),
        "Unicode-escaped duplicate key '\\u0076' vs 'v' must be rejected"
    );
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("Duplicate JSON key detected: 'v'"),
        "Expected duplicate key 'v', got: {}",
        err
    );

    // 2. Unicode escape for "kdf" (\u006b\u0064\u0066)
    let json_escaped_kdf = r#"{
        "v": 3,
        "\u006b\u0064\u0066": {
            "name": "argon2id",
            "m_kib": 65536,
            "t": 2,
            "p": 2,
            "salt": "AAAAAAAAAAAAAAAAAAAAAA=="
        },
        "kdf": {
            "name": "argon2id",
            "m_kib": 65536,
            "t": 2,
            "p": 2,
            "salt": "AAAAAAAAAAAAAAAAAAAAAA=="
        },
        "cipher": {
            "layers": ["chacha20-poly1305", "aes-256-gcm"],
            "nonce_chacha": "AQEBAQEBAQEBAQEB",
            "nonce_aes": "AgICAgICAgICAgIC",
            "tag_aes": "AwMDAwMDAwMDAwMDAwMDAw=="
        },
        "data": "dmFsaWRfY2lwaGVydGV4dF8xMjM0NTY3"
    }"#;

    let res_kdf = deserialize_envelope(json_escaped_kdf);
    assert!(
        res_kdf.is_err(),
        "Unicode-escaped duplicate key 'kdf' must be rejected"
    );
    let err_kdf = res_kdf.unwrap_err().to_string();
    assert!(
        err_kdf.contains("Duplicate JSON key detected: 'kdf'"),
        "Expected duplicate key 'kdf', got: {}",
        err_kdf
    );
}

// =========================================================================
// VULN-86 & VULN-87: Path validation for verbatim Windows paths & subdirectories
// =========================================================================
#[test]
fn test_v86_v87_path_validation_verbatim_and_reserved() {
    // VULN-86: Verbatim Windows path prefix \\?\ should not trigger false positive ADS check
    #[cfg(windows)]
    {
        let tmp = NamedTempFile::new().unwrap();
        let path_str = tmp.path().to_str().unwrap();
        let verbatim_path = format!(r"\\?\{}", path_str);
        // Path validation should strip \\?\ and not fail on NTFS ADS check for drive colon
        let res = write_secure_file(&verbatim_path, b"test payload");
        assert!(
            res.is_ok(),
            "Verbatim \\?\\ path must not be rejected as NTFS ADS: {:?}",
            res.err()
        );
    }

    // VULN-87: Reserved device names in nested subdirectories
    let nested_reserved_paths = [
        "subdir/CON/secret.txt",
        "nested/path/aux.json",
        "data/prn.log",
        "keys/CONIN$",
        "out/CONOUT$",
    ];
    for p in &nested_reserved_paths {
        let res = write_secure_file(p, b"secret");
        assert!(
            res.is_err(),
            "Nested reserved device name in '{}' must be rejected",
            p
        );
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.contains("Windows reserved device names are prohibited"),
            "Error should mention reserved device name: {}",
            msg
        );
    }
}

// =========================================================================
// VULN-90: Inspect command stdin '-' parsing
// =========================================================================
#[test]
fn test_v90_inspect_hyphen_stdin_parsing() {
    // 1. Positional '-'
    let cli_pos = Cli::try_parse_from(["opke", "inspect", "-"]);
    assert!(
        cli_pos.is_ok(),
        "Inspect with positional '-' must be accepted by CLI"
    );

    // 2. Option -i '-'
    let cli_opt = Cli::try_parse_from(["opke", "inspect", "-i", "-"]);
    assert!(
        cli_opt.is_ok(),
        "Inspect with -i '-' must be accepted by CLI"
    );
}

// =========================================================================
// VULN-94: Terminal QR quiet zone dimensions
// =========================================================================
#[test]
fn test_v94_terminal_qr_quiet_zone_dimensions() {
    let mut out = Vec::new();
    let res = print_terminal_qr("OPKE-VULN-94-TEST", &mut out);
    assert!(res.is_ok());

    let text = String::from_utf8(out).unwrap();
    // Verify each line has width = width + 2 * quiet_zone (quiet_zone = 4)
    // Strip ANSI escape codes to count rendered characters per row
    let lines: Vec<&str> = text.lines().collect();
    assert!(!lines.is_empty());

    for line in lines {
        let mut clean = String::new();
        let mut in_ansi = false;
        for c in line.chars() {
            if c == '\x1b' {
                in_ansi = true;
            } else if in_ansi && c == 'm' {
                in_ansi = false;
            } else if !in_ansi {
                clean.push(c);
            }
        }
        if !clean.is_empty() {
            // QR version 1 is 21x21 modules; with 4 modules on each side, width is at least 29 modules
            assert!(
                clean.chars().count() >= 29,
                "Rendered QR line width ({}) should include at least 4 modules quiet zone on each side",
                clean.chars().count()
            );
        }
    }
}

// =========================================================================
// VULN-95: Deserializing raw JSON preserves internal spaces
// =========================================================================
#[test]
fn test_v95_raw_json_preserves_internal_spaces() {
    let salt = [1u8; 16];
    let nonce1 = [2u8; 12];
    let nonce2 = [3u8; 12];
    let tag = [4u8; 16];
    let ct = b"confidential_ciphertext_32_bytes";

    let env = create_envelope(&salt, 65536, 2, 2, &nonce1, &nonce2, &tag, ct, Some(3)).unwrap();
    let json_compact = serde_json::to_string(&env).unwrap();
    let json_pretty = serde_json::to_string_pretty(&env).unwrap();

    // Pretty printed JSON has indentation, newlines, and spaces
    assert!(json_pretty.contains("  "));
    let deserialized = deserialize_envelope(&json_pretty).unwrap();
    assert_eq!(deserialized.v, 3);
    assert_eq!(deserialized.kdf.name, "argon2id");
    assert_eq!(deserialized.kdf.m_kib, 65536);

    let deserialized_compact = deserialize_envelope(&json_compact).unwrap();
    assert_eq!(deserialized_compact.v, 3);
}

// =========================================================================
// VULN-98: Base64 non-ASCII validation in paper format
// =========================================================================
#[test]
fn test_v98_pem_paper_format_rejects_non_ascii() {
    let non_ascii_b64 = "YWJjZGVm\u{00FF}\u{0100}";
    let res = pem::to_paper_format(non_ascii_b64, 64);
    assert!(res.is_err(), "Non-ASCII base64 payload must be rejected");
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("non-ASCII"),
        "Expected non-ASCII error, got: {}",
        err
    );

    let valid_ascii = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw";
    assert!(pem::to_paper_format(valid_ascii, 64).is_ok());
}

// =========================================================================
// VULN-109: RFC 7468 PEM allows surrounding explanatory text
// =========================================================================
#[test]
fn test_v109_pem_rfc7468_surrounding_text_allowed() {
    let base64_payload = "SGVsbG8gV29ybGQgT1BLRSB2Mw==";
    let pem_with_surrounding = format!(
        "Please store this offline paper key in a safe place:\n{}\nGenerated on 2026-10-10 by OPKE.",
        pem::to_paper_format(base64_payload, 64).unwrap()
    );

    let stripped = pem::strip_pem(&pem_with_surrounding);
    assert!(
        stripped.is_ok(),
        "RFC 7468 allows explanatory text outside PEM boundary: {:?}",
        stripped.err()
    );
    assert_eq!(stripped.unwrap(), base64_payload);
}

// =========================================================================
// VULN-101: In-place cascade decryption roundtrip and tamper detection
// =========================================================================
#[test]
fn test_v101_in_place_cascade_decryption() {
    let plaintext = b"Top secret operational keying material (confidential)";
    let key_chacha = [0x11u8; SUBKEY_LEN];
    let key_aes = [0x22u8; SUBKEY_LEN];
    let nonce_chacha = Some([0x33u8; NONCE_LEN]);
    let nonce_aes = Some([0x44u8; NONCE_LEN]);
    let aad = b"OPKE-v3-AAD-BINDING";

    let (ct, tag_aes, n_ch, n_ae) = encrypt_cascade(
        plaintext,
        &key_chacha,
        &key_aes,
        nonce_chacha,
        nonce_aes,
        Some(aad),
    )
    .unwrap();

    // Successful in-place decryption
    let decrypted = decrypt_cascade(
        &ct,
        &tag_aes,
        &n_ch,
        &n_ae,
        &key_chacha,
        &key_aes,
        Some(aad),
    )
    .unwrap();
    assert_eq!(decrypted.as_slice(), plaintext);

    // Tampered ciphertext detection
    let mut tampered_ct = ct.clone();
    tampered_ct[0] ^= 0x01;
    let res_tamper_ct = decrypt_cascade(
        &tampered_ct,
        &tag_aes,
        &n_ch,
        &n_ae,
        &key_chacha,
        &key_aes,
        Some(aad),
    );
    assert!(
        res_tamper_ct.is_err(),
        "Tampered ciphertext must fail authentication"
    );

    // Tampered AES tag detection
    let mut tampered_tag = tag_aes;
    tampered_tag[0] ^= 0x01;
    let res_tamper_tag = decrypt_cascade(
        &ct,
        &tampered_tag,
        &n_ch,
        &n_ae,
        &key_chacha,
        &key_aes,
        Some(aad),
    );
    assert!(
        res_tamper_tag.is_err(),
        "Tampered tag must fail authentication"
    );

    // Tampered AAD detection
    let res_tamper_aad = decrypt_cascade(
        &ct,
        &tag_aes,
        &n_ch,
        &n_ae,
        &key_chacha,
        &key_aes,
        Some(b"TAMPERED-AAD"),
    );
    assert!(
        res_tamper_aad.is_err(),
        "Tampered AAD must fail authentication"
    );
}
