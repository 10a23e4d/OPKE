#![no_main]

use libfuzzer_sys::fuzz_target;
use opke::envelope::{deserialize_envelope, pem, serialize_envelope};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // deserialize_envelope internally invokes pem::strip_pem, duplicate-key check, and field decoding
        if let Ok(env) = deserialize_envelope(s) {
            let _ = env.compute_aad();
            let _ = serialize_envelope(&env, true);
            let _ = serialize_envelope(&env, false);
        }
    } else {
        // Fuzz PEM extraction on arbitrary lossy strings when input is non-UTF-8
        let lossy_str = String::from_utf8_lossy(data);
        let _ = pem::strip_pem(&lossy_str);
    }
});
