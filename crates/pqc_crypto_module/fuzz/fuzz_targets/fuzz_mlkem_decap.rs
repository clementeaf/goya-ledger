#![no_main]
//! Fuzz ML-KEM-768 decapsulate with arbitrary sk/ct.
//! Goal: no panics — garbage input should return Err or different shared secret.

use libfuzzer_sys::fuzz_target;
use pqc_crypto_module::types::{MlKemCiphertext, MlKemPrivateKey};

fuzz_target!(|data: &[u8]| {
    // sk=2400 + ct=1088 = 3488 minimum
    if data.len() < 3488 {
        return;
    }
    let sk = MlKemPrivateKey(data[..2400].to_vec());
    let ct = MlKemCiphertext(data[2400..2400 + 1088].to_vec());

    let _ = pqc_crypto_module::mlkem::decapsulate_raw(&sk, &ct);
});
