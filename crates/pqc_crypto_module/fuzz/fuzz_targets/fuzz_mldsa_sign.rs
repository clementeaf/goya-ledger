#![no_main]
//! Fuzz ML-DSA-65 sign with arbitrary sk/msg.
//! Goal: no panics — sign with garbage sk should return Err, not crash.

use libfuzzer_sys::fuzz_target;
use pqc_crypto_module::types::MldsaPrivateKey;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4033 {
        return;
    }
    let sk_bytes = &data[..4032];
    let msg = &data[4032..];

    let sk = MldsaPrivateKey(sk_bytes.to_vec());
    let _ = pqc_crypto_module::mldsa::sign_message_raw(&sk, msg);
});
