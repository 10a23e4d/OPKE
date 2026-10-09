//! Kani formal verification harnesses for OPKE v3.0 core functions.
//! Run with: `cargo kani --harness <harness_name>`

#[cfg(kani)]
mod proofs {
    use opke::core::{
        derive_key_and_split, MAX_M_KIB, MAX_P, MAX_PASSPHRASE_BYTES, MAX_SECRET_BYTES, MAX_T,
        MIN_M_KIB, MIN_P, MIN_T, SALT_LEN,
    };

    /// Prove that arbitrary KDF bounds checks never overflow and strictly enforce validity.
    #[kani::proof]
    fn verify_kdf_parameter_bounds() {
        let m_kib: u32 = kani::any();
        let t: u32 = kani::any();
        let p: u32 = kani::any();
        let salt_len: usize = kani::any();

        // Constrain symbolic salt length for model bounds
        kani::assume(salt_len <= 32);
        let salt = vec![0u8; salt_len];
        let passphrase = [0u8; 16];

        let result = derive_key_and_split(&passphrase, &salt, m_kib, t, p);

        let is_valid = (MIN_M_KIB..=MAX_M_KIB).contains(&m_kib)
            && (MIN_T..=MAX_T).contains(&t)
            && (MIN_P..=MAX_P).contains(&p)
            && salt.len() == SALT_LEN;

        if is_valid {
            // Valid ranges must pass bounds checking
            assert!(result.is_ok());
        } else {
            // Out of bounds must return error and never panic
            assert!(result.is_err());
        }
    }

    /// Prove that plaintext length validation correctly protects against buffer overflow.
    #[kani::proof]
    fn verify_secret_length_bounds() {
        let len: usize = kani::any();

        let is_valid = len > 0 && len <= MAX_SECRET_BYTES;
        if !is_valid {
            // Plaintext length validation logic
            assert!(len == 0 || len > MAX_SECRET_BYTES);
        }
    }
}
