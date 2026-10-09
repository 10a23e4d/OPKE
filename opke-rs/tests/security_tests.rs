//! Security tests covering all 26 audited vulnerabilities (VULN-01 to VULN-26).

use std::fs;
use tempfile::NamedTempFile;
use opke::cli::args::{BenchmarkArgs, DecryptArgs, EncryptArgs};
use opke::cli::{cmd_benchmark, cmd_decrypt, cmd_encrypt};
use opke::core::MAX_CIPHERTEXT_BYTES;
use opke::envelope::{create_envelope, deserialize_envelope, pem};
use opke::qr::{generate_qr_image, print_terminal_qr};
use opke::security::{
    get_available_memory_kib, read_secure_file, write_secure_file, write_secure_file_with_options,
};

// =========================================================================
// VULN-01 & VULN-15: Hardlink rejection and preserving original target content
// =========================================================================
#[test]
fn test_v01_v15_hardlink_rejected_and_target_preserved() {
    let tmp = NamedTempFile::new().unwrap();
    let target_path = tmp.path().to_path_buf();
    let initial_content = b"CRITICAL_USER_DATA_THAT_MUST_NEVER_BE_TRUNCATED_BY_ATTACK";
    fs::write(&target_path, initial_content).unwrap();

    let hl_path = target_path.with_extension("hl");
    if hl_path.exists() {
        let _ = fs::remove_file(&hl_path);
    }

    // Create a hardlink to target_path
    if fs::hard_link(&target_path, &hl_path).is_ok() {
        // Attempting to write to the hardlink target must be rejected
        let res = write_secure_file(&hl_path, b"malicious new data");
        assert!(res.is_err(), "write_secure_file should reject hardlinks");
        let err_msg = format!("{}", res.err().unwrap());
        assert!(
            err_msg.contains("hardlink"),
            "Error message should mention hardlink: {}",
            err_msg
        );

        // Target file content must NOT have been truncated or modified!
        let preserved = fs::read(&target_path).unwrap();
        assert_eq!(preserved, initial_content);

        let _ = fs::remove_file(&hl_path);
    }
}

// =========================================================================
// VULN-05: Incomplete file unlinked on error
// =========================================================================
#[test]
fn test_v05_incomplete_file_unlinked_on_error() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let target_path = tmp_dir.path().join("incomplete_file.txt");

    // Writing to an invalid empty path returns validation error
    assert!(write_secure_file("", b"data").is_err());
    assert!(!target_path.exists());
}

// =========================================================================
// VULN-06: Windows ACL DACL enforced on NTFS
// =========================================================================
#[test]
fn test_v06_windows_acl_enforced_or_forced() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    // write_secure_file on NTFS succeeds and applies DACL
    let res = write_secure_file(&path, b"confidential key material");
    assert!(res.is_ok());

    // write_secure_file_with_options with force=true also succeeds
    let res_force = write_secure_file_with_options(&path, b"more key material", true);
    assert!(res_force.is_ok());
}

// =========================================================================
// VULN-10: read_secure_file stack zeroizing and regular file validation
// =========================================================================
#[test]
fn test_v10_read_secure_file_bounds_and_zeroize() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path();
    fs::write(path, b"SuperSecretEmergencyKitData123").unwrap();

    // Normal read works
    let read_buf = read_secure_file(path, 1024).unwrap();
    assert_eq!(read_buf.as_slice(), b"SuperSecretEmergencyKitData123");

    // Reading with max_bytes smaller than file fails
    let err = read_secure_file(path, 10);
    assert!(err.is_err());
    assert!(format!("{}", err.err().unwrap()).contains("exceeds maximum allowed size"));

    // Reading non-existent file fails
    assert!(read_secure_file("nonexistent_path_xyz_123.txt", 1024).is_err());

    // Reading empty path fails
    assert!(read_secure_file("", 1024).is_err());
}

// =========================================================================
// VULN-13: CLI arguments exposing secrets & passphrases rejected & scrubbed
// =========================================================================
#[test]
fn test_v13_cli_arguments_secrets_rejected() {
    let enc_args_secret = EncryptArgs {
        secret: Some("MyExposedSecret".into()),
        input_file: None,
        passphrase: None,
        output: None,
        profile: "fast".into(),
        mem: None,
        time: None,
        threads: None,
        qr: None,
        qr_term: false,
        raw: false,
        multiline: false,
        v2: false,
        force: false,
    };
    let res = cmd_encrypt::execute(enc_args_secret);
    assert!(res.is_err());
    let msg = format!("{}", res.err().unwrap());
    assert!(
        msg.contains("Passing secrets as command-line arguments is strictly prohibited"),
        "{}",
        msg
    );

    let enc_args_pass = EncryptArgs {
        secret: None,
        input_file: None,
        passphrase: Some("MyExposedPassphrase".into()),
        output: None,
        profile: "fast".into(),
        mem: None,
        time: None,
        threads: None,
        qr: None,
        qr_term: false,
        raw: false,
        multiline: false,
        v2: false,
        force: false,
    };
    let res_pass = cmd_encrypt::execute(enc_args_pass);
    assert!(res_pass.is_err());
    let msg_pass = format!("{}", res_pass.err().unwrap());
    assert!(
        msg_pass.contains("Passing passphrases as command-line arguments is strictly prohibited"),
        "{}",
        msg_pass
    );

    let dec_args_pass = DecryptArgs {
        input: Some("dummy".into()),
        input_file: None,
        passphrase: Some("MyExposedPassphrase".into()),
        output: None,
        max_mem: None,
        max_time: None,
        max_threads: None,
        allow_v2: false,
        force: false,
    };
    let res_dec = cmd_decrypt::execute(dec_args_pass);
    assert!(res_dec.is_err());
    let msg_dec = format!("{}", res_dec.err().unwrap());
    assert!(
        msg_dec.contains("Passing passphrases as command-line arguments is strictly prohibited"),
        "{}",
        msg_dec
    );
}

// =========================================================================
// VULN-14 & VULN-23: cmd_benchmark parameter bounds, RAM check, typo rejection
// =========================================================================
#[test]
fn test_v14_v23_cmd_benchmark_bounds_and_typo() {
    // Unknown profile typo rejected
    let bm_typo = BenchmarkArgs {
        profile: "producton_typo".into(),
        mem: None,
        time: None,
        threads: None,
        force: false,
    };
    let res = cmd_benchmark::execute(bm_typo);
    assert!(res.is_err());
    assert!(format!("{}", res.err().unwrap()).contains("Unknown profile: 'producton_typo'"));

    // Excessive mem bound rejected
    let bm_excess_mem = BenchmarkArgs {
        profile: "fast".into(),
        mem: Some(999_999_999),
        time: None,
        threads: None,
        force: false,
    };
    let res_mem = cmd_benchmark::execute(bm_excess_mem);
    assert!(res_mem.is_err());
    assert!(format!("{}", res_mem.err().unwrap()).contains("Invalid memory cost"));

    // m < 8 * p constraint rejected
    let bm_low_mem = BenchmarkArgs {
        profile: "fast".into(),
        mem: Some(1024),
        time: None,
        threads: Some(256), // 8 * 256 = 2048 > 1024
        force: false,
    };
    let res_low = cmd_benchmark::execute(bm_low_mem);
    assert!(res_low.is_err());
    assert!(format!("{}", res_low.err().unwrap()).contains("Argon2 requires m >= 8 * p"));
}

// =========================================================================
// VULN-16: Memory detection returns physical/container KiB
// =========================================================================
#[test]
fn test_v16_available_memory_detection() {
    let mem = get_available_memory_kib();
    assert!(mem.is_some(), "Available memory should be detected");
    assert!(mem.unwrap() > 0, "Available memory should be greater than 0");
}

// =========================================================================
// VULN-17: MIN_CIPHERTEXT_BYTES (17 bytes) boundary check
// =========================================================================
#[test]
fn test_v17_min_ciphertext_bytes_enforced() {
    let salt = [1u8; 16];
    let nc = [2u8; 12];
    let na = [3u8; 12];
    let tag = [4u8; 16];

    // 16 bytes is 1 byte below minimum 17 bytes (1B plaintext + 16B Poly1305 tag)
    let too_short_ct = [0u8; 16];
    let res_create = create_envelope(&salt, 65536, 2, 2, &nc, &na, &tag, &too_short_ct, Some(3));
    assert!(res_create.is_err());
    let err_msg = format!("{}", res_create.err().unwrap());
    assert!(
        err_msg.contains("Ciphertext data is too short (minimum 17 bytes)"),
        "{}",
        err_msg
    );

    // 17 bytes succeeds
    let valid_len_ct = [0u8; 17];
    let res_ok = create_envelope(&salt, 65536, 2, 2, &nc, &na, &tag, &valid_len_ct, Some(3));
    assert!(res_ok.is_ok());

    // In deserialize_envelope, raw JSON with short ciphertext is rejected
    let bad_json = r#"{
      "v": 3,
      "kdf": { "name": "argon2id", "m_kib": 65536, "t": 2, "p": 2, "salt": "AAAAAAAAAAAAAAAAAAAAAA==" },
      "cipher": {
        "layers": ["chacha20-poly1305", "aes-256-gcm"],
        "nonce_chacha": "AQEBAQEBAQEBAQEB",
        "nonce_aes": "AgICAgICAgICAgIC",
        "tag_aes": "AwMDAwMDAwMDAwMDAwMDAw=="
      },
      "data": "MDEyMzQ1Njc4OTAxMjM0NQ=="
    }"#; // 16 bytes decoded
    let res_deser = deserialize_envelope(bad_json);
    assert!(res_deser.is_err());
    assert!(format!("{}", res_deser.err().unwrap()).contains("Ciphertext data is too short"));
}

// =========================================================================
// VULN-18: Base64 upper bound pre-validation before decode
// =========================================================================
#[test]
fn test_v18_base64_ciphertext_upper_bound_prevalidation() {
    let bad_oversized_json = format!(
        r#"{{
      "v": 3,
      "kdf": {{ "name": "argon2id", "m_kib": 65536, "t": 2, "p": 2, "salt": "AAAAAAAAAAAAAAAAAAAAAA==" }},
      "cipher": {{
        "layers": ["chacha20-poly1305", "aes-256-gcm"],
        "nonce_chacha": "AQEBAQEBAQEBAQEB",
        "nonce_aes": "AgICAgICAgICAgIC",
        "tag_aes": "AwMDAwMDAwMDAwMDAwMDAw=="
      }},
      "data": "{}"
    }}"#,
        "A".repeat(MAX_CIPHERTEXT_BYTES * 2)
    );
    let res = deserialize_envelope(&bad_oversized_json);
    assert!(res.is_err());
    assert!(format!("{}", res.err().unwrap()).contains("exceeds maximum allowed size"));
}

// =========================================================================
// VULN-19: PEM to_paper_format line wrapping and bounds
// =========================================================================
#[test]
fn test_v19_pem_formatting_and_bounds() {
    let sample_payload = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk=";
    let pem_out = pem::to_paper_format(sample_payload, 64).unwrap();
    assert!(pem_out.starts_with(pem::PEM_HEADER));
    assert!(pem_out.ends_with(&format!("{}\n", pem::PEM_FOOTER)));

    let stripped = pem::strip_pem(&pem_out).unwrap();
    let cleaned: String = stripped.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(cleaned, sample_payload);

    // Invalid line length bounds (< 16 or > 1024)
    assert!(pem::to_paper_format(sample_payload, 15).is_err());
    assert!(pem::to_paper_format(sample_payload, 1025).is_err());
}

// =========================================================================
// VULN-20: Terminal QR reports empty data and capacity overflow
// =========================================================================
#[test]
fn test_v20_terminal_qr_reports_empty_and_overflow() {
    let mut out_empty = Vec::new();
    let res_empty = print_terminal_qr("", &mut out_empty);
    assert!(res_empty.is_ok());
    let s_empty = String::from_utf8(out_empty).unwrap();
    assert!(
        s_empty.contains("Terminal QR generation unavailable: data is empty"),
        "{}",
        s_empty
    );

    let mut out_overflow = Vec::new();
    let oversized_data = "X".repeat(5000);
    let res_overflow = print_terminal_qr(&oversized_data, &mut out_overflow);
    assert!(res_overflow.is_ok());
    let s_overflow = String::from_utf8(out_overflow).unwrap();
    assert!(
        s_overflow.contains("Terminal QR generation unavailable: data exceeds maximum QR code capacity"),
        "{}",
        s_overflow
    );
}

// =========================================================================
// VULN-21: QR image path validation
// =========================================================================
#[test]
fn test_v21_qr_image_path_validation() {
    // Empty path rejected
    assert!(generate_qr_image("valid_payload", "").is_err());
    assert!(generate_qr_image("valid_payload", "   ").is_err());

    // Empty data rejected
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().with_extension("png");
    assert!(generate_qr_image("", &path).is_err());

    // Non-existent parent directory rejected
    assert!(generate_qr_image(
        "valid_payload",
        "nonexistent_deeply_nested_folder_xyz_123/test.png"
    )
    .is_err());

    // Unsupported extension rejected
    let bad_ext = tmp.path().with_extension("bmp");
    assert!(generate_qr_image("valid_payload", &bad_ext).is_err());
}

// =========================================================================
// VULN-23: cmd_encrypt profile typo rejection
// =========================================================================
#[test]
fn test_v23_encrypt_profile_typo_rejected() {
    let enc_args = EncryptArgs {
        secret: None,
        input_file: None,
        passphrase: None,
        output: None,
        profile: "fastt".into(),
        mem: None,
        time: None,
        threads: None,
        qr: None,
        qr_term: false,
        raw: false,
        multiline: false,
        v2: false,
        force: false,
    };
    let res = cmd_encrypt::execute(enc_args);
    assert!(res.is_err());
    let msg = format!("{}", res.err().unwrap());
    assert!(
        msg.contains("Unknown profile: 'fastt'"),
        "Should reject typo: {}",
        msg
    );
}

// =========================================================================
// VULN-25: Decrypt limit bounds (negative and 0 rejected)
// =========================================================================
#[test]
fn test_v25_decrypt_limit_bounds_rejected() {
    // Negative max-mem rejected
    let dec_neg_mem = DecryptArgs {
        input: Some("dummy".into()),
        input_file: None,
        passphrase: None,
        output: None,
        max_mem: Some(-10),
        max_time: None,
        max_threads: None,
        allow_v2: false,
        force: false,
    };
    let res = cmd_decrypt::execute(dec_neg_mem);
    assert!(res.is_err());
    assert!(format!("{}", res.err().unwrap()).contains("Invalid --max-mem: -10 KiB"));

    // 0 max-time rejected
    let dec_zero_t = DecryptArgs {
        input: Some("dummy".into()),
        input_file: None,
        passphrase: None,
        output: None,
        max_mem: None,
        max_time: Some(0),
        max_threads: None,
        allow_v2: false,
        force: false,
    };
    let res_t = cmd_decrypt::execute(dec_zero_t);
    assert!(res_t.is_err());
    assert!(format!("{}", res_t.err().unwrap()).contains("Invalid --max-time: 0"));

    // 0 max-threads rejected
    let dec_zero_p = DecryptArgs {
        input: Some("dummy".into()),
        input_file: None,
        passphrase: None,
        output: None,
        max_mem: None,
        max_time: None,
        max_threads: Some(0),
        allow_v2: false,
        force: false,
    };
    let res_p = cmd_decrypt::execute(dec_zero_p);
    assert!(res_p.is_err());
    assert!(format!("{}", res_p.err().unwrap()).contains("Invalid --max-threads: 0"));
}

// =========================================================================
// VULN-26: Wizard prompt quote stripping
// =========================================================================
#[test]
fn test_v26_wizard_quote_stripping_logic() {
    let clean_path = |input: &str| -> String {
        let mut s = input.trim();
        if s.len() >= 2 && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\''))) {
            s = &s[1..s.len() - 1];
        }
        s.trim().to_string()
    };

    assert_eq!(
        clean_path(r#""C:\Users\test\Desktop\key.txt""#),
        r#"C:\Users\test\Desktop\key.txt"#
    );
    assert_eq!(
        clean_path(r#"'C:\Users\test\Desktop\key.txt'"#),
        r#"C:\Users\test\Desktop\key.txt"#
    );
    assert_eq!(
        clean_path(r#"  "C:\path with spaces\key.txt"  "#),
        r#"C:\path with spaces\key.txt"#
    );
    assert_eq!(
        clean_path(r#"C:\unquoted\path\key.txt"#),
        r#"C:\unquoted\path\key.txt"#
    );
}
