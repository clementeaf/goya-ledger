//! Cross-implementation validation — PQClean vs RustCrypto `ml-dsa`.
//!
//! Two independent ML-DSA-65 implementations must produce identical output
//! from the same seed. If they agree on NIST ACVP vectors AND on each other,
//! the probability of a shared bug is vanishingly small.

use ml_dsa::{Keypair, MlDsa65, SigningKey};
use pqc_crypto_module::mldsa::generate_keypair_from_seed;

fn rc_keygen(seed: &[u8; 32]) -> SigningKey<MlDsa65> {
    let s: ml_dsa::B32 = (*seed).into();
    SigningKey::<MlDsa65>::from_seed(&s)
}

// ═══════════════════════════════════════════════════════════════════
// 1. SAME SEED → SAME PUBLIC KEY
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cross_impl_keygen_same_pk() {
    let seeds: [[u8; 32]; 4] = [
        [0x42; 32],
        [0x00; 32],
        [0xFF; 32],
        core::array::from_fn(|i| i as u8),
    ];

    for (i, seed) in seeds.iter().enumerate() {
        let pqclean_pk = generate_keypair_from_seed(seed).unwrap().public_key;
        let rc_pk = rc_keygen(seed).verifying_key().encode();

        assert_eq!(
            pqclean_pk.as_bytes(),
            rc_pk.as_slice(),
            "seed[{i}]: PQClean pk != RustCrypto pk"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// 2. DETERMINISTIC SIGN MATCHES BYTE-FOR-BYTE
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cross_impl_deterministic_sign_matches() {
    use pqc_crypto_module::mldsa;

    let seed = [0x42; 32];
    let msg = b"cross-implementation deterministic sign test";

    let pqclean_kp = generate_keypair_from_seed(&seed).unwrap();
    let pqclean_sig = mldsa::sign_message_derand(&pqclean_kp.private_key, msg, &[0u8; 32]).unwrap();

    let rc_sk = rc_keygen(&seed);
    let rc_sig = rc_sk
        .expanded_key()
        .sign_internal(&[msg.as_slice()], &ml_dsa::B32::default());
    let rc_sig_bytes = rc_sig.encode();

    assert_eq!(
        pqclean_sig.as_bytes(),
        rc_sig_bytes.as_slice(),
        "Same seed + msg + rnd=zeros → signatures must be identical"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 3. MULTIPLE MESSAGES — CROSS-SIGN CONSISTENCY
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cross_impl_sign_multiple_messages() {
    use pqc_crypto_module::mldsa;

    let seed = [0xAB; 32];
    let messages: [&[u8]; 5] = [b"", b"a", b"Hello world", &[0xFF; 1000], &[0u8; 10000]];

    let pqclean_kp = generate_keypair_from_seed(&seed).unwrap();
    let rc_sk = rc_keygen(&seed);
    let rc_esk = rc_sk.expanded_key();

    for (i, msg) in messages.iter().enumerate() {
        let pq_sig = mldsa::sign_message_derand(&pqclean_kp.private_key, msg, &[0u8; 32]).unwrap();
        let rc_sig = rc_esk.sign_internal(&[*msg], &ml_dsa::B32::default());

        assert_eq!(
            pq_sig.as_bytes(),
            rc_sig.encode().as_slice(),
            "msg[{i}] (len={}): signatures diverge",
            msg.len()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// 4. ACVP VECTORS: BOTH MATCH NIST
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cross_impl_acvp_keygen_both_match_nist() {
    #[derive(serde::Deserialize)]
    struct VectorFile {
        vectors: Vec<Vector>,
    }
    #[derive(serde::Deserialize)]
    struct Vector {
        #[serde(rename = "tcId")]
        tc_id: u32,
        seed: String,
        pk: String,
    }

    let json = include_str!("data/acvp_mldsa65_keygen.json");
    let vf: VectorFile = serde_json::from_str(json).unwrap();

    for v in &vf.vectors {
        let seed: [u8; 32] = hex::decode(&v.seed).unwrap().try_into().unwrap();
        let expected_pk = hex::decode(&v.pk).unwrap();

        let pq_pk = generate_keypair_from_seed(&seed).unwrap().public_key;
        assert_eq!(
            pq_pk.as_bytes(),
            &expected_pk[..],
            "tcId={}: PQClean",
            v.tc_id
        );

        let rc_pk = rc_keygen(&seed).verifying_key().encode();
        assert_eq!(
            rc_pk.as_slice(),
            &expected_pk[..],
            "tcId={}: RustCrypto",
            v.tc_id
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// 5. PQCLEAN SIG VERIFIED BY RUSTCRYPTO VIA EXTERNAL MODE
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cross_impl_pqclean_sig_verified_by_rustcrypto() {
    let seed = [0x77; 32];
    let msg = b"cross-verify external mode";

    let pqclean_kp = generate_keypair_from_seed(&seed).unwrap();

    // Sign with PQClean external mode (empty context)
    let sig = pqc_crypto_module::mldsa::sign_message_external_derand(
        &pqclean_kp.private_key,
        msg,
        &[],
        &[0u8; 32],
    )
    .unwrap();

    // Verify with RustCrypto
    let rc_vk = rc_keygen(&seed).verifying_key().clone();
    let rc_sig_enc =
        ml_dsa::EncodedSignature::<MlDsa65>::try_from(sig.as_bytes()).expect("valid sig encoding");
    let rc_sig = ml_dsa::Signature::<MlDsa65>::decode(&rc_sig_enc).expect("sig decode");

    // verify_with_context(msg, ctx=empty)
    assert!(
        rc_vk.verify_with_context(msg, &[], &rc_sig),
        "RustCrypto rejected PQClean's external-mode signature"
    );
}
