#![no_main]
//! Fuzz ML-KEM-768 encapsulate with arbitrary pk.
//! Goal: no panics — garbage pk should return Err, not crash.

use libfuzzer_sys::fuzz_target;
use pqc_crypto_module::types::MlKemPublicKey;

fuzz_target!(|data: &[u8]| {
    if data.len() < 1184 {
        return;
    }
    let pk = MlKemPublicKey(data[..1184].to_vec());
    let _ = pqc_crypto_module::mlkem::encapsulate_raw(&pk);
});
