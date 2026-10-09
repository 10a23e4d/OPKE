#![no_main]

use libfuzzer_sys::fuzz_target;
use opke::core::decrypt_cascade;

fuzz_target!(|data: &[u8]| {
    // Need at least 16 (tag) + 12 (nonce1) + 12 (nonce2) + 32 (key1) + 32 (key2) = 104 bytes
    if data.len() < 104 {
        return;
    }

    let tag: [u8; 16] = data[0..16].try_into().unwrap();
    let n1: [u8; 12] = data[16..28].try_into().unwrap();
    let n2: [u8; 28..40].try_into().unwrap();
    let k1: [u8; 32] = data[40..72].try_into().unwrap();
    let k2: [u8; 32] = data[72..104].try_into().unwrap();
    let ciphertext = &data[104..];

    // Must never panic on arbitrary malformed ciphertext or keys
    let _ = decrypt_cascade(ciphertext, &tag, &n1, &n2, &k1, &k2, None);
});
