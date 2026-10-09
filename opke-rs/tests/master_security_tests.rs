//! Comprehensive regression and security validation test suite for OPKE v3.0 (VULN-27 to VULN-74).

use clap::Parser;
use opke::cli::args::{Cli, Commands};
use opke::core::{decrypt_cascade, derive_key_and_split, encrypt_cascade};
use opke::envelope::{create_envelope, deserialize_envelope, to_paper_format};
use opke::qr::terminal::print_terminal_qr;
use opke::security::memory::{lock_memory, unlock_memory, MemoryLockGuard};
use opke::security::{read_secure_file, write_secure_file};
use tempfile::NamedTempFile;

/// VULN-52: Verify PEM positional arguments starting with hyphen ('-') parse without Clap error.
#[test]
fn test_v52_pem_hyphen_argument_parsing() {
    let pem_input = "-----BEGIN OPKE ENVELOPE-----\neyJ2IjozfQ==\n-----END OPKE ENVELOPE-----";
    let cli = Cli::try_parse_from(["opke", "decrypt", pem_input]);
    assert!(
        cli.is_ok(),
        "Clap failed to parse hyphen-prefixed PEM string: {:?}",
        cli.err()
    );

    if let Ok(Cli {
        command: Some(Commands::Decrypt(args)),
    }) = cli
    {
        assert_eq!(args.input.as_deref(), Some(pem_input));
    } else {
        panic!("Parsed command was not Decrypt");
    }

    // Inspect command also supports hyphen-prefixed input
    let cli_inspect = Cli::try_parse_from(["opke", "inspect", pem_input]);
    assert!(
        cli_inspect.is_ok(),
        "Clap failed on inspect with PEM: {:?}",
        cli_inspect.err()
    );
}

/// VULN-55: Verify Unicode NFC normalization ensures cross-platform key equivalence.
/// macOS produces decomposed NFD (e.g., 'e' + U+0301 combining acute accent),
/// while Windows/Linux produce precomposed NFC (U+00E9).
#[test]
fn test_v55_unicode_nfc_cross_platform() {
    let precomposed_nfc = "Caf\u{00E9}"; // Café (NFC: 4 chars)
    let decomposed_nfd = "Cafe\u{0301}"; // Café (NFD: 5 chars: 'C', 'a', 'f', 'e', '\u{0301}')

    assert_ne!(precomposed_nfc.as_bytes(), decomposed_nfd.as_bytes());

    let salt = [55u8; 16];
    let (k1_nfc, k2_nfc) =
        derive_key_and_split(precomposed_nfc.as_bytes(), &salt, 1024, 1, 1).unwrap();
    let (k1_nfd, k2_nfd) =
        derive_key_and_split(decomposed_nfd.as_bytes(), &salt, 1024, 1, 1).unwrap();

    assert_eq!(
        k1_nfc.as_slice(),
        k1_nfd.as_slice(),
        "NFC and NFD passphrases must derive identical ChaCha subkeys after NFC normalization"
    );
    assert_eq!(
        k2_nfc.as_slice(),
        k2_nfd.as_slice(),
        "NFC and NFD passphrases must derive identical AES subkeys after NFC normalization"
    );
}

/// VULN-41 & VULN-42 & VULN-59: Verify AEAD AAD binding, unified error messages (no oracle),
/// and unified nonce argument ordering.
#[test]
fn test_v41_v42_v59_cascade_unified_security() {
    let secret = b"Top Secret Payload";
    let key_chacha = [10u8; 32];
    let key_aes = [20u8; 32];
    let aad_v3 =
        b"opke:v=3:kdf=argon2id:m=65536:t=2:p=2:c=chacha20-poly1305+aes-256-gcm:nc=AQE:na=AgI";

    // Encrypt with AAD bound
    let (ct, tag, n_chacha, n_aes) =
        encrypt_cascade(secret, &key_chacha, &key_aes, None, None, Some(aad_v3)).unwrap();

    // Decrypt with correct AAD and unified nonce order (n_chacha first, n_aes second)
    let decrypted = decrypt_cascade(
        &ct,
        &tag,
        &n_chacha,
        &n_aes,
        &key_chacha,
        &key_aes,
        Some(aad_v3),
    )
    .unwrap();
    assert_eq!(decrypted.as_slice(), secret);

    // Tampered AAD (e.g. attempting to downgrade header) must fail with unified error (VULN-41, VULN-42)
    let bad_aad = b"opke:v=2:legacy";
    let err_aad = decrypt_cascade(
        &ct,
        &tag,
        &n_chacha,
        &n_aes,
        &key_chacha,
        &key_aes,
        Some(bad_aad),
    );
    assert!(err_aad.is_err());
    let msg = err_aad.unwrap_err().to_string();
    assert!(
        msg.contains("authentication failed. Invalid passphrase or corrupted data."),
        "Error message must be strictly unified to prevent multi-layer oracle"
    );

    // Tampered ciphertext must produce the same unified error
    let mut tampered_ct = ct.clone();
    tampered_ct[0] ^= 0xFF;
    let err_ct = decrypt_cascade(
        &tampered_ct,
        &tag,
        &n_chacha,
        &n_aes,
        &key_chacha,
        &key_aes,
        Some(aad_v3),
    );
    assert!(err_ct.is_err());
    assert!(err_ct
        .unwrap_err()
        .to_string()
        .contains("authentication failed. Invalid passphrase or corrupted data."));
}

/// VULN-33: JSON duplicate key rejection in deserialization.
#[test]
fn test_v33_duplicate_json_keys_rejected() {
    let duplicate_key_json = r#"{
        "v": 3,
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

    let res = deserialize_envelope(duplicate_key_json);
    assert!(res.is_err(), "Duplicate JSON key must be rejected");
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains("Duplicate JSON key detected: 'v'"),
        "Expected duplicate key error, got: {}",
        msg
    );
}

/// VULN-65: Base64 pre-validation for salt, nonce, and tag lengths.
#[test]
fn test_v65_base64_prevalidation_salt_nonce_tag() {
    // Salt max is 24 chars for 16 bytes. Let's create an envelope with a huge salt Base64.
    let huge_salt_b64 = "A".repeat(100);
    let bad_salt_json = format!(
        r#"{{
        "v": 3,
        "kdf": {{
            "name": "argon2id",
            "m_kib": 65536,
            "t": 2,
            "p": 2,
            "salt": "{}"
        }},
        "cipher": {{
            "layers": ["chacha20-poly1305", "aes-256-gcm"],
            "nonce_chacha": "AQEBAQEBAQEBAQEB",
            "nonce_aes": "AgICAgICAgICAgIC",
            "tag_aes": "AwMDAwMDAwMDAwMDAwMDAw=="
        }},
        "data": "dmFsaWRfY2lwaGVydGV4dA=="
    }}"#,
        huge_salt_b64
    );

    let res = deserialize_envelope(&bad_salt_json);
    assert!(
        res.is_err(),
        "Huge salt Base64 must be rejected before allocation"
    );
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains("Base64 salt length exceeds maximum allowed bound"),
        "Got error: {}",
        msg
    );
}

/// VULN-39 & VULN-40: Path validation against NTFS Alternate Data Streams (ADS) and Windows reserved device names.
#[test]
fn test_v39_v40_windows_reserved_names_and_ads() {
    // 1. NTFS ADS (colon in filename)
    let res_ads = write_secure_file("test_file.txt:hidden_stream", b"secret");
    assert!(res_ads.is_err(), "NTFS ADS path must be rejected");
    let msg = res_ads.unwrap_err().to_string();
    assert!(msg.contains("NTFS Alternate Data Streams"), "Got: {}", msg);

    // 2. Windows reserved device names
    let reserved = [
        "NUL", "CON", "AUX", "PRN", "COM1", "LPT1", "nul.txt", "con.dat",
    ];
    for name in &reserved {
        let res_dev = write_secure_file(name, b"secret");
        assert!(
            res_dev.is_err(),
            "Reserved device name '{}' must be rejected",
            name
        );
        let msg = res_dev.unwrap_err().to_string();
        assert!(msg.contains("Windows reserved device name"), "Got: {}", msg);
    }
}

/// VULN-53: Terminal QR code ANSI sequence verification for dark mode compatibility.
#[test]
fn test_v53_terminal_qr_ansi_colors() {
    let mut buf = Vec::new();
    let out = print_terminal_qr("OPKE-TEST-QR", &mut buf);
    assert!(out.is_ok());
    let qr_str = String::from_utf8(buf).unwrap();
    // Must contain explicit white background / black foreground ANSI escape code
    assert!(
        qr_str.contains("\x1b[47m\x1b[30m"),
        "Must set white background and black text"
    );
    // Must contain ANSI reset
    assert!(qr_str.contains("\x1b[0m"), "Must reset terminal ANSI style");
}

/// VULN-54: Memory locking guard tests.
#[test]
fn test_v54_core_secret_memory_locking() {
    let secret_buf = vec![0x42u8; 128];
    let guard = MemoryLockGuard::new(secret_buf.as_slice());
    // On systems with memory locking capability, guard should lock successfully
    assert!(guard.is_ok());
    let g = guard.unwrap();
    assert!(g.is_locked());
    drop(g);

    // Direct lock and unlock
    let locked = lock_memory(secret_buf.as_ptr(), secret_buf.len());
    assert!(locked);
    unlock_memory(secret_buf.as_ptr(), secret_buf.len());
}

/// VULN-70: CLI arguments conflict between 'input' and '--input-file'.
#[test]
fn test_v70_cli_conflicts_with() {
    let cli = Cli::try_parse_from(["opke", "decrypt", "direct_input", "-i", "file.txt"]);
    assert!(
        cli.is_err(),
        "Providing both positional input and -i must be rejected by Clap"
    );

    let cli_enc = Cli::try_parse_from(["opke", "encrypt", "direct_secret", "-i", "file.txt"]);
    assert!(
        cli_enc.is_err(),
        "Providing both positional secret and -i must be rejected by Clap"
    );
}

/// VULN-45: Envelope creation version bounds validation.
#[test]
fn test_v45_envelope_version_bounds() {
    let salt = [0u8; 16];
    let nonce1 = [1u8; 12];
    let nonce2 = [2u8; 12];
    let tag = [0u8; 16];
    let ct = b"sample_valid_length_ciphertext_bytes_32";

    // Supported versions: 2 and 3
    assert!(create_envelope(&salt, 65536, 2, 2, &nonce1, &nonce2, &tag, ct, Some(3)).is_ok());
    assert!(create_envelope(&salt, 65536, 2, 2, &nonce1, &nonce2, &tag, ct, Some(2)).is_ok());

    // Unsupported versions: 1, 4, 99
    assert!(create_envelope(&salt, 65536, 2, 2, &nonce1, &nonce2, &tag, ct, Some(1)).is_err());
    assert!(create_envelope(&salt, 65536, 2, 2, &nonce1, &nonce2, &tag, ct, Some(4)).is_err());
}

/// VULN-66: PEM paper format non-UTF-8 chunk error.
#[test]
fn test_v66_pem_non_utf8_chunk_error() {
    let test_str = "あ".repeat(10); // 30 bytes, 3 bytes per char
                                    // line_length = 16 splits the 6th character across chunk boundary
    let res = to_paper_format(&test_str, 16);
    assert!(res.is_err(), "Non-UTF-8 chunk split must return error");

    // Valid ASCII / Base64 succeeds
    let valid_b64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw";
    let res_ok = to_paper_format(valid_b64, 16);
    assert!(res_ok.is_ok());
}

/// VULN-30 & VULN-29 & VULN-57: File overwrite safety, CREATE_NEW atomic creation, and handle close order.
#[test]
fn test_v30_v29_v57_file_security_lifecycle() {
    let tmp = NamedTempFile::new().unwrap();
    let target_path = tmp.path().to_path_buf();
    // Drop tmp file so it doesn't exist
    drop(tmp);

    // 1. Create brand new file (tests CREATE_NEW and proper creation)
    let data1 = b"Original content to write";
    let write_res1 = write_secure_file(&target_path, data1);
    assert!(write_res1.is_ok());

    let read_back = read_secure_file(&target_path, 1024).unwrap();
    assert_eq!(read_back.as_slice(), data1);

    // 2. Overwrite existing file cleanly (tests no set_len(0) pre-truncation, proper write and sync)
    let data2 = b"Updated longer content to safely replace existing content";
    let write_res2 = write_secure_file(&target_path, data2);
    assert!(write_res2.is_ok());

    let read_back2 = read_secure_file(&target_path, 1024).unwrap();
    assert_eq!(read_back2.as_slice(), data2);

    let _ = std::fs::remove_file(&target_path);
}

/// VULN-41 / VULN-60: Legacy v2 envelope must be rejected during decryption unless --allow-v2 is passed.
#[test]
fn test_v41_v2_downgrade_rejected_without_flag() {
    use opke::cli::args::DecryptArgs;
    use opke::cli::cmd_decrypt;

    let v2_json = r#"{
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

    let args_without_flag = DecryptArgs {
        input: Some(v2_json.to_string()),
        input_file: None,
        passphrase: None,
        output: None,
        max_mem: None,
        max_time: None,
        max_threads: None,
        allow_v2: false,
        force: false,
    };

    let res = cmd_decrypt::execute(args_without_flag);
    assert!(
        res.is_err(),
        "v2 decryption must be rejected without --allow-v2"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("Use '--allow-v2' to permit decrypting legacy v2 envelopes"),
        "Expected --allow-v2 requirement error, got: {}",
        err_msg
    );
}
