use opke::core::{
    decrypt_cascade, derive_key_and_split, encrypt_cascade,
};
use opke::envelope::{create_envelope, deserialize_envelope, serialize_envelope};
use opke::qr::generate_qr_image;
use tempfile::NamedTempFile;

#[test]
fn test_kdf_determinism_and_split() {
    let passphrase = b"CorrectHorseBatteryStaple";
    let salt = [42u8; 16];

    let (k1_a, k2_a) = derive_key_and_split(passphrase, &salt, 1024, 1, 1).unwrap();
    let (k1_b, k2_b) = derive_key_and_split(passphrase, &salt, 1024, 1, 1).unwrap();

    assert_eq!(k1_a.as_slice(), k1_b.as_slice());
    assert_eq!(k2_a.as_slice(), k2_b.as_slice());
    assert_ne!(k1_a.as_slice(), k2_a.as_slice()); // Must be distinct

    let alt_salt = [43u8; 16];
    let (k1_diff, k2_diff) = derive_key_and_split(passphrase, &alt_salt, 1024, 1, 1).unwrap();
    assert_ne!(k1_a.as_slice(), k1_diff.as_slice());
    assert_ne!(k2_a.as_slice(), k2_diff.as_slice());
}

#[test]
fn test_encrypt_decrypt_roundtrip_various_payloads() {
    let payloads: Vec<&[u8]> = vec![
        b"A",
        b"xK9#mQ2$vL5*pW8^zR1@yT4&uI7(oO0)",
        "日本語テスト秘密リカバリーキー🔐".as_bytes(),
        b"Emergency Kit recovery code 1234-5678-9012-3456",
    ];

    let key_chacha = [1u8; 32];
    let key_aes = [2u8; 32];

    for secret in payloads {
        let (ct, tag, n_chacha, n_aes) =
            encrypt_cascade(secret, &key_chacha, &key_aes, None, None).unwrap();

        assert_eq!(n_chacha.len(), 12);
        assert_eq!(n_aes.len(), 12);
        assert_ne!(n_chacha, n_aes);
        assert_eq!(tag.len(), 16);
        assert!(!ct.is_empty());

        let decrypted =
            decrypt_cascade(&ct, &tag, &n_aes, &n_chacha, &key_chacha, &key_aes).unwrap();

        assert_eq!(decrypted.as_slice(), secret);
    }
}

#[test]
fn test_tamper_detection_layer2() {
    let secret = b"VeraCrypt Super Secret Key";
    let key_chacha = [11u8; 32];
    let key_aes = [22u8; 32];

    let (mut ct, tag, n_chacha, n_aes) =
        encrypt_cascade(secret, &key_chacha, &key_aes, None, None).unwrap();

    // Flip 1 bit in ciphertext
    ct[0] ^= 0x01;
    let err = decrypt_cascade(&ct, &tag, &n_aes, &n_chacha, &key_chacha, &key_aes);
    assert!(err.is_err());
    let err_msg = err.unwrap_err().to_string();
    assert!(err_msg.contains("Layer 2 (AES-GCM) authentication tag verification failed"));
}

#[test]
fn test_envelope_v3_roundtrip_pem_and_b64() {
    let salt = [7u8; 16];
    let n_chacha = [8u8; 12];
    let n_aes = [9u8; 12];
    let tag = [10u8; 16];
    let ct = b"sample_encrypted_data_block_for_test";

    let env = create_envelope(&salt, 65536, 2, 2, &n_chacha, &n_aes, &tag, ct, Some(3)).unwrap();
    assert_eq!(env.v, 3);

    // Test PEM serialization
    let pem_text = serialize_envelope(&env, true).unwrap();
    assert!(pem_text.starts_with("-----BEGIN OPKE ENVELOPE-----"));
    assert!(pem_text.ends_with("-----END OPKE ENVELOPE-----\n"));

    let parsed_env = deserialize_envelope(&pem_text).unwrap();
    assert_eq!(parsed_env.v, 3);
    assert_eq!(parsed_env.kdf.m_kib, 65536);
    assert_eq!(parsed_env.kdf.t, 2);
    assert_eq!(parsed_env.kdf.p, 2);

    let decoded = parsed_env.get_decoded_bytes().unwrap();
    assert_eq!(decoded.salt, salt);
    assert_eq!(decoded.nonce_chacha, n_chacha);
    assert_eq!(decoded.nonce_aes, n_aes);
    assert_eq!(decoded.tag_aes, tag);
    assert_eq!(decoded.final_ciphertext, ct);
}

#[test]
fn test_envelope_v2_backward_compatibility() {
    // Valid v2 envelope JSON
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

    let parsed = deserialize_envelope(v2_json).unwrap();
    assert_eq!(parsed.v, 2);
    assert_eq!(parsed.kdf.name, "argon2id");
    assert_eq!(parsed.cipher.layers, vec!["chacha20-poly1305", "aes-256-gcm"]);
}

#[test]
fn test_invalid_envelope_rejected() {
    // Unknown fields must be rejected (DoS / schema validation)
    let bad_json = r#"{"v": 3, "kdf": {"name": "argon2id", "m_kib": 65536, "t": 2, "p": 2, "salt": "AAAA"}, "cipher": {"layers": ["chacha20-poly1305", "aes-256-gcm"], "nonce_chacha": "AAAA", "nonce_aes": "BBBB", "tag_aes": "CCCC"}, "data": "DDDD", "malicious_extra": 123}"#;
    assert!(deserialize_envelope(bad_json).is_err());

    // Unsupported version (e.g. v4)
    let v4_json = r#"{"v": 4, "kdf": {"name": "argon2id", "m_kib": 65536, "t": 2, "p": 2, "salt": "AAAA"}, "cipher": {"layers": ["chacha20-poly1305", "aes-256-gcm"], "nonce_chacha": "AAAA", "nonce_aes": "BBBB", "tag_aes": "CCCC"}, "data": "DDDD"}"#;
    assert!(deserialize_envelope(v4_json).is_err());
}

#[test]
fn test_qr_generation_png_and_svg() {
    let tmp_png = NamedTempFile::new().unwrap();
    let png_path = tmp_png.path().with_extension("png");

    let tmp_svg = NamedTempFile::new().unwrap();
    let svg_path = tmp_svg.path().with_extension("svg");

    let data = "OPKE-TEST-QR-DATA-1234567890";
    generate_qr_image(data, &png_path).unwrap();
    generate_qr_image(data, &svg_path).unwrap();

    let png_bytes = std::fs::read(&png_path).unwrap();
    assert!(png_bytes.starts_with(b"\x89PNG\r\n\x1a\n"));

    let svg_str = std::fs::read_to_string(&svg_path).unwrap();
    assert!(svg_str.contains("<svg"));

    let _ = std::fs::remove_file(png_path);
    let _ = std::fs::remove_file(svg_path);
}
