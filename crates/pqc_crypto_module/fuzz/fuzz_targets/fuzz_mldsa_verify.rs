#![no_main]
//! Fuzz ML-DSA-65 verify with arbitrary pk/msg/sig.
//! Goal: no panics, no UB — only Ok/Err.

use libfuzzer_sys::fuzz_target;
use pqc_crypto_module::types::{MldsaPublicKey, MldsaSignature};

fuzz_target!(|data: &[u8]| {
    // Need at least: 1952 (pk) + 1 (msg) + 3309 (sig) = 5262 bytes
    if data.len() < 5262 {
        return;
    }
    let pk_bytes = &data[..1952];
    let sig_bytes = &data[1952..1952 + 3309];
    let msg = &data[1952 + 3309..];

    let pk = MldsaPublicKey(pk_bytes.to_vec());
    let sig = MldsaSignature(sig_bytes.to_vec());

    // Must not panic — Ok or Err both fine
    let _ = pqc_crypto_module::mldsa::verify_signature_raw(&pk, msg, &sig);
});
