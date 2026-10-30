#![no_main]

use libfuzzer_sys::fuzz_target;
use opke::core::decrypt_cascade;

fuzz_target!(|data: &[u8]| {
    // Need at least 1 (flags) + 16 (tag) + 12 (nonce1) + 12 (nonce2) + 32 (key1) + 32 (key2) = 105 bytes
    if data.len() < 105 {
        return;
    }

    let flags = data[0];
    let tag: [u8; 16] = data[1..17].try_into().unwrap();
    let n1: [u8; 12] = data[17..29].try_into().unwrap();
    let n2: [u8; 12] = data[29..41].try_into().unwrap();
    let k1: [u8; 32] = data[41..73].try_into().unwrap();
    let k2: [u8; 32] = data[73..105].try_into().unwrap();
    let rest = &data[105..];

    // Exercise both None AAD (v2) and Some(aad) (v3) paths
    let (aad, ciphertext) = if (flags & 1) != 0 && !rest.is_empty() {
        let aad_len = (rest[0] as usize).min(rest.len() - 1);
        (Some(&rest[1..1 + aad_len]), &rest[1 + aad_len..])
    } else {
        (None, rest)
    };

    // Must never panic on arbitrary malformed ciphertext, keys, or AAD
    let _ = decrypt_cascade(ciphertext, &tag, &n1, &n2, &k1, &k2, aad);
});
