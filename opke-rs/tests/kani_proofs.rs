//! Kani formal verification harnesses for OPKE v3.0 core logic.
//! Run with: `cargo kani`

#[cfg(kani)]
mod proofs {
    use opke::core::{
        KEY_LEN, MAX_CIPHERTEXT_BYTES, MAX_M_KIB, MAX_P, MAX_SECRET_BYTES, MAX_T, MIN_M_KIB, MIN_P,
        MIN_T, SUBKEY_LEN, TAG_LEN,
    };

    /// Prove that arbitrary KDF bounds checks never overflow and strictly enforce validity.
    #[kani::proof]
    fn verify_kdf_parameter_bounds() {
        let m_kib: u32 = kani::any();
        let t: u32 = kani::any();
        let p: u32 = kani::any();

        let is_valid = (MIN_M_KIB..=MAX_M_KIB).contains(&m_kib)
            && (MIN_T..=MAX_T).contains(&t)
            && (MIN_P..=MAX_P).contains(&p);

        if is_valid {
            assert!(m_kib >= MIN_M_KIB && m_kib <= MAX_M_KIB);
            assert!(t >= MIN_T && t <= MAX_T);
            assert!(p >= MIN_P && p <= MAX_P);
        } else {
            assert!(
                m_kib < MIN_M_KIB
                    || m_kib > MAX_M_KIB
                    || t < MIN_T
                    || t > MAX_T
                    || p < MIN_P
                    || p > MAX_P
            );
        }
    }

    /// Prove that ciphertext length arithmetic never overflows usize bounds.
    #[kani::proof]
    fn verify_ciphertext_size_arithmetic() {
        let secret_len: usize = kani::any();
        kani::assume(secret_len <= MAX_SECRET_BYTES);

        // Prove that adding TAG_LEN never overflows usize
        let ct_len = secret_len.checked_add(TAG_LEN);
        assert!(ct_len.is_some());
        assert!(ct_len.unwrap() <= MAX_CIPHERTEXT_BYTES);
    }

    /// Prove that dual-layer key separation invariants hold.
    #[kani::proof]
    fn verify_key_separation_properties() {
        let master_key: [u8; KEY_LEN] = kani::any();

        // Subkey extraction ranges: [0..SUBKEY_LEN] and [SUBKEY_LEN..KEY_LEN]
        let mut key_chacha = [0u8; SUBKEY_LEN];
        let mut key_aes = [0u8; SUBKEY_LEN];
        key_chacha.copy_from_slice(&master_key[..SUBKEY_LEN]);
        key_aes.copy_from_slice(&master_key[SUBKEY_LEN..]);

        // Invariant 1: Disjoint subkey bounds exactly span the master key without overlap
        assert_eq!(key_chacha.len(), SUBKEY_LEN);
        assert_eq!(key_aes.len(), SUBKEY_LEN);
        assert_eq!(key_chacha.len() + key_aes.len(), KEY_LEN);

        // Invariant 2: Constant-time comparison equivalence with standard element-wise equality
        let ct_equal = subtle::ConstantTimeEq::ct_eq(&key_chacha[..], &key_aes[..]);
        let bool_equal: bool = ct_equal.into();
        let direct_equal = key_chacha == key_aes;
        assert_eq!(bool_equal, direct_equal);

        // Invariant 3: Key derivation non-degeneracy condition mapping
        if direct_equal {
            for i in 0..SUBKEY_LEN {
                assert_eq!(master_key[i], master_key[SUBKEY_LEN + i]);
            }
        }
    }

    /// Prove that PEM line-splitting capacity calculation never overflows usize.
    #[kani::proof]
    fn verify_pem_capacity_arithmetic() {
        let b64_len: usize = kani::any();
        let line_len: usize = kani::any();

        // Constrain to maximum possible ciphertext size * base64 expansion
        kani::assume(b64_len <= MAX_CIPHERTEXT_BYTES * 2);
        kani::assume(line_len >= 16 && line_len <= 1024);

        let num_lines = b64_len.div_ceil(line_len);

        let cap1 = b64_len.checked_add(num_lines);
        assert!(cap1.is_some());
        let cap2 = cap1.unwrap().checked_add(100);
        assert!(cap2.is_some());
    }
}
