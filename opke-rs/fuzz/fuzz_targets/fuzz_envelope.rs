#![no_main]

use libfuzzer_sys::fuzz_target;
use opke::envelope::{deserialize_envelope, pem};

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz envelope deserialization from UTF-8 strings
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = deserialize_envelope(s);
        let _ = pem::strip_pem(s);
    }

    // 2. Fuzz PEM parse directly from arbitrary lossy strings
    let lossy_str = String::from_utf8_lossy(data);
    let _ = pem::strip_pem(&lossy_str);
});
