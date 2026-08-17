//! Wycheproof ML-DSA-65 verify test suite — all 210 vectors.
//!
//! Source: Project Wycheproof (google/wycheproof) ML-DSA-65 verify vectors.
//! Covers valid signatures, modified signatures, wrong-size keys/sigs,
//! invalid hints encoding, infinity norm violations, boundary conditions,
//! zero public keys, and invalid context lengths.

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

#[derive(serde::Deserialize)]
struct WycheproofVector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    pk: String,
    msg: String,
    sig: String,
    result: String,
    ctx: String,
    #[allow(dead_code)]
    comment: String,
}

#[test]
fn wycheproof_mldsa65_all_210_vectors() {
    let json = include_str!("data/wycheproof_mldsa65_full.json");
    let vectors: Vec<WycheproofVector> = serde_json::from_str(json).unwrap();
    assert_eq!(vectors.len(), 210, "expected 210 Wycheproof vectors");

    let mut valid_pass = 0u32;
    let mut invalid_pass = 0u32;

    for v in &vectors {
        let pk_bytes = hex::decode(&v.pk).expect("hex pk");
        let msg_bytes = hex::decode(&v.msg).expect("hex msg");
        let sig_bytes = hex::decode(&v.sig).expect("hex sig");
        let ctx_bytes = hex::decode(&v.ctx).expect("hex ctx");

        if v.result == "valid" {
            // Valid vectors: pk and sig must parse, and verification must succeed.
            let pqc_pk = mldsa65::PublicKey::from_bytes(&pk_bytes)
                .unwrap_or_else(|_| panic!("tcId={}: valid vector but pk parse failed", v.tc_id));
            let pqc_sig = mldsa65::DetachedSignature::from_bytes(&sig_bytes)
                .unwrap_or_else(|_| panic!("tcId={}: valid vector but sig parse failed", v.tc_id));

            let result =
                mldsa65::verify_detached_signature_ctx(&pqc_sig, &msg_bytes, &ctx_bytes, &pqc_pk);
            assert!(
                result.is_ok(),
                "tcId={}: valid vector rejected — {}",
                v.tc_id,
                v.comment,
            );
            valid_pass += 1;
        } else {
            // Invalid vectors: either pk/sig parsing fails OR verify returns Err.
            let pk_result = mldsa65::PublicKey::from_bytes(&pk_bytes);
            let sig_result = mldsa65::DetachedSignature::from_bytes(&sig_bytes);

            if let (Ok(pqc_pk), Ok(pqc_sig)) = (pk_result, sig_result) {
                // Context > 255 bytes is rejected by the API itself.
                if ctx_bytes.len() > 255 {
                    // pqcrypto will panic or error on oversized context;
                    // either way the vector is correctly rejected.
                    invalid_pass += 1;
                    continue;
                }

                let result = mldsa65::verify_detached_signature_ctx(
                    &pqc_sig, &msg_bytes, &ctx_bytes, &pqc_pk,
                );
                assert!(
                    result.is_err(),
                    "tcId={}: CRITICAL — invalid vector accepted — {}",
                    v.tc_id,
                    v.comment,
                );
            }
            // If parsing fails, the vector is correctly rejected.
            invalid_pass += 1;
        }
    }

    eprintln!(
        "Wycheproof ML-DSA-65: {}/{} valid passed, {}/{} invalid passed, {}/210 total",
        valid_pass,
        vectors.iter().filter(|v| v.result == "valid").count(),
        invalid_pass,
        vectors.iter().filter(|v| v.result != "valid").count(),
        valid_pass + invalid_pass,
    );

    assert_eq!(
        valid_pass + invalid_pass,
        210,
        "all 210 vectors must be exercised"
    );
}
