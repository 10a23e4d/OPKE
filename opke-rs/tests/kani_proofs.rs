//! Kani formal verification harnesses for OPKE core and envelope logic.
//! Run with: `cargo kani --tests`

use opke::core::{
    compute_ciphertext_len, extract_distinct_subkeys, is_valid_kdf_params, max_arch_m_kib, KEY_LEN,
    MAX_CIPHERTEXT_BYTES, MAX_P, MAX_SECRET_BYTES, MAX_T, MIN_CIPHERTEXT_BYTES, MIN_M_KIB, MIN_P,
    MIN_T, SUBKEY_LEN, TAG_LEN,
};
use opke::envelope::{compute_pem_capacity, max_b64_len_for_bytes, PEM_FOOTER, PEM_HEADER};

#[test]
fn test_kani_harness_target_functions_sanity() {
    assert!(is_valid_kdf_params(MIN_M_KIB, MIN_T, MIN_P));
    assert!(!is_valid_kdf_params(MIN_M_KIB - 1, MIN_T, MIN_P));
    assert!(!is_valid_kdf_params(max_arch_m_kib() + 1, MIN_T, MIN_P));
    assert!(!is_valid_kdf_params(64, MIN_T, 16)); // m_kib < 8 * p
    assert!(!is_valid_kdf_params(64, MAX_T + 1, MIN_P));
    assert!(!is_valid_kdf_params(64, MIN_T, MAX_P + 1));

    assert_eq!(compute_ciphertext_len(0), None);
    assert_eq!(compute_ciphertext_len(1), Some(MIN_CIPHERTEXT_BYTES));
    assert_eq!(compute_ciphertext_len(2), Some(2 + TAG_LEN));
    assert_eq!(
        compute_ciphertext_len(MAX_SECRET_BYTES),
        Some(MAX_CIPHERTEXT_BYTES)
    );
    assert_eq!(compute_ciphertext_len(MAX_SECRET_BYTES + 1), None);
    assert!(max_b64_len_for_bytes(MAX_CIPHERTEXT_BYTES).is_some());

    let mut master = [0u8; KEY_LEN];
    let mut k1 = [0u8; SUBKEY_LEN];
    let mut k2 = [0u8; SUBKEY_LEN];
    assert!(!extract_distinct_subkeys(&master, &mut k1, &mut k2));
    master[0] = 1;
    assert!(extract_distinct_subkeys(&master, &mut k1, &mut k2));

    assert_eq!(compute_pem_capacity(128, 15), None);
    assert_eq!(compute_pem_capacity(128, 1025), None);
    let cap = compute_pem_capacity(128, 64).unwrap();
    let min_expected = PEM_HEADER.len() + 1 + 128 + PEM_FOOTER.len() + 1;
    assert!(cap >= min_expected);
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Prove that production KDF parameter gate (`is_valid_kdf_params`)
    /// never overflows (including `8 * p`) and strictly enforces all Argon2id bounds.
    #[kani::proof]
    fn verify_kdf_parameter_bounds() {
        let m_kib: u32 = kani::any();
        let t: u32 = kani::any();
        let p: u32 = kani::any();

        let is_valid = is_valid_kdf_params(m_kib, t, p);
        let max_arch_kib = max_arch_m_kib();

        if is_valid {
            assert!(m_kib >= MIN_M_KIB && m_kib <= max_arch_kib);
            assert!(t >= MIN_T && t <= MAX_T);
            assert!(p >= MIN_P && p <= MAX_P);
            assert!(m_kib >= 8 * p);
        } else {
            assert!(
                m_kib < MIN_M_KIB
                    || m_kib > max_arch_kib
                    || t < MIN_T
                    || t > MAX_T
                    || p < MIN_P
                    || p > MAX_P
                    || m_kib < 8u32.saturating_mul(p)
            );
        }
    }

    /// Prove that production ciphertext size and Base64 length calculations (`compute_ciphertext_len`
    /// and `max_b64_len_for_bytes`) never overflow `usize` and reject out-of-range inputs.
    #[kani::proof]
    fn verify_ciphertext_size_arithmetic() {
        let secret_len: usize = kani::any();

        let ct_opt = compute_ciphertext_len(secret_len);
        if secret_len >= 1 && secret_len <= MAX_SECRET_BYTES {
            let ct_len = ct_opt.expect("Valid secret_len must produce Some(ct_len)");
            assert_eq!(ct_len, secret_len + TAG_LEN);
            assert!(ct_len >= MIN_CIPHERTEXT_BYTES && ct_len <= MAX_CIPHERTEXT_BYTES);

            let b64_len = max_b64_len_for_bytes(ct_len)
                .expect("Valid ciphertext length must not overflow Base64 bound");
            assert!(b64_len >= ct_len);
        } else {
            assert!(ct_opt.is_none());
        }
    }

    /// Prove that production dual-layer subkey extraction (`extract_distinct_subkeys`)
    /// preserves disjoint slices and accurately enforces constant-time key separation.
    #[kani::proof]
    fn verify_key_separation_properties() {
        let master_key: [u8; KEY_LEN] = kani::any();
        let mut key_chacha = [0u8; SUBKEY_LEN];
        let mut key_aes = [0u8; SUBKEY_LEN];

        let is_distinct = extract_distinct_subkeys(&master_key, &mut key_chacha, &mut key_aes);

        // Invariant 1: Disjoint subkey bounds exactly match master key halves
        assert_eq!(&key_chacha[..], &master_key[..SUBKEY_LEN]);
        assert_eq!(&key_aes[..], &master_key[SUBKEY_LEN..]);

        // Invariant 2: Constant-time non-degeneracy check matches exact slice inequality
        let direct_distinct = key_chacha != key_aes;
        assert_eq!(is_distinct, direct_distinct);
    }

    /// Prove that production PEM capacity calculation (`compute_pem_capacity`)
    /// never overflows `usize` and strictly validates line_length bounds.
    #[kani::proof]
    fn verify_pem_capacity_arithmetic() {
        let b64_len: usize = kani::any();
        let line_len: usize = kani::any();

        kani::assume(b64_len <= MAX_CIPHERTEXT_BYTES * 2);

        let cap_opt = compute_pem_capacity(b64_len, line_len);
        if (16..=1024).contains(&line_len) {
            let cap = cap_opt.expect("Valid line_len and bounded b64_len must not overflow");
            let min_expected = PEM_HEADER.len() + 1 + b64_len + PEM_FOOTER.len() + 1;
            assert!(cap >= min_expected);
        } else {
            assert!(cap_opt.is_none());
        }
    }
}
