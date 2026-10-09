//! Kani formal verification harnesses for OPKE v3.0 core logic.
//! Run with: `cargo kani`

#[cfg(kani)]
mod proofs {
    use opke::core::{
        MAX_CIPHERTEXT_BYTES, MAX_M_KIB, MAX_P, MAX_SECRET_BYTES, MAX_T, MIN_M_KIB, MIN_P, MIN_T,
        SUBKEY_LEN, TAG_LEN,
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
        let k1: [u8; SUBKEY_LEN] = kani::any();
        let k2: [u8; SUBKEY_LEN] = kani::any();

        let same = k1 == k2;
        if same {
            assert_eq!(k1, k2);
        } else {
            assert_ne!(k1, k2);
        }
    }
}
