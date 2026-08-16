//! Shared signature verification — dispatches Ed25519 and ML-DSA-65.
//!
//! All handlers that verify cryptographic signatures should use these
//! functions instead of implementing their own. This ensures consistent
//! behavior and makes algorithm upgrades a single-point change.

use crate::identity::signing::SigningAlgorithm;

/// Verify an Ed25519 signature over a message.
pub fn verify_ed25519(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let pub_bytes = match hex::decode(public_key_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    use pqc_crypto_module::legacy::ed25519::{Signature, Verifier, VerifyingKey};
    match (
        pub_bytes
            .as_slice()
            .try_into()
            .ok()
            .and_then(|b: &[u8; 32]| VerifyingKey::from_bytes(b).ok()),
        Signature::from_slice(&sig_bytes).ok(),
    ) {
        (Some(vk), Some(sig)) => vk.verify(message, &sig).is_ok(),
        _ => false,
    }
}

/// Verify an ML-DSA-65 (FIPS 204) signature over a message.
pub fn verify_mldsa65(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let pub_bytes = match hex::decode(public_key_hex) {
        Ok(b) if b.len() == 1952 => b,
        _ => return false,
    };
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) if b.len() == 3309 => b,
        _ => return false,
    };
    use pqc_crypto_module::legacy::mldsa_raw::{DetachedSignature, PublicKey};
    let pk = match pqc_crypto_module::legacy::mldsa_raw::mldsa65::PublicKey::from_bytes(&pub_bytes)
    {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match pqc_crypto_module::legacy::mldsa_raw::mldsa65::DetachedSignature::from_bytes(
        &sig_bytes,
    ) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    pqc_crypto_module::legacy::mldsa_raw::mldsa65::verify_detached_signature(&sig, message, &pk)
        .is_ok()
}

/// Verify an RSA PKCS#1 v1.5 SHA-256 signature over a message.
pub fn verify_rsa(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let pub_bytes = match hex::decode(public_key_hex) {
        Ok(b) if b.len() >= 128 => b,
        _ => return false,
    };
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) if !b.is_empty() => b,
        _ => return false,
    };
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    let pk = match rsa::RsaPublicKey::from_pkcs1_der(&pub_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<sha2::Sha256>::new(pk);
    let sig = match Signature::try_from(sig_bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(message, &sig).is_ok()
}

/// Verify an ECDSA P-256 (ES256) signature over a message.
pub fn verify_ecdsa_p256(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let pub_bytes = match hex::decode(public_key_hex) {
        Ok(b) if b.len() == 65 || b.len() == 33 => b,
        _ => return false,
    };
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let vk = match VerifyingKey::from_sec1_bytes(&pub_bytes) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig = match Signature::from_bytes((&sig_bytes[..]).into()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(message, &sig).is_ok()
}

/// Dispatch signature verification based on algorithm.
///
/// Returns `true` if the signature is valid for the given message and public key.
pub fn verify_signature(
    algorithm: SigningAlgorithm,
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> bool {
    match algorithm {
        SigningAlgorithm::Ed25519 => verify_ed25519(public_key_hex, message, signature_hex),
        SigningAlgorithm::MlDsa65 => verify_mldsa65(public_key_hex, message, signature_hex),
        SigningAlgorithm::Rsa => verify_rsa(public_key_hex, message, signature_hex),
        SigningAlgorithm::EcdsaP256 => verify_ecdsa_p256(public_key_hex, message, signature_hex),
    }
}

/// Infer signing algorithm from public key hex length.
pub fn infer_algorithm_from_key(public_key_hex: &str) -> Option<SigningAlgorithm> {
    match public_key_hex.len() {
        64 => Some(SigningAlgorithm::Ed25519),
        130 => Some(SigningAlgorithm::EcdsaP256), // 65 bytes uncompressed (0x04 || x || y)
        66 => Some(SigningAlgorithm::EcdsaP256),  // 33 bytes compressed
        3904 => Some(SigningAlgorithm::MlDsa65),
        n if n >= 256 => Some(SigningAlgorithm::Rsa),
        _ => None,
    }
}

/// Validate public key hex length for the given algorithm.
///
/// Ed25519: 64 hex chars (32 bytes). ML-DSA-65: 3904 hex chars (1952 bytes).
pub fn validate_public_key(
    algorithm: SigningAlgorithm,
    public_key_hex: &str,
) -> Result<(), String> {
    let expected_bytes = match algorithm {
        SigningAlgorithm::Ed25519 => 32,
        SigningAlgorithm::MlDsa65 => 1952,
        SigningAlgorithm::EcdsaP256 => {
            // P-256 SEC1: 65 bytes uncompressed or 33 bytes compressed.
            let len = public_key_hex.len();
            if (len == 130 || len == 66) && hex::decode(public_key_hex).is_ok() {
                return Ok(());
            }
            return Err(format!(
                "P-256 public_key must be 130 (uncompressed) or 66 (compressed) hex chars, got {len}"
            ));
        }
        SigningAlgorithm::Rsa => {
            // RSA public keys are DER-encoded, variable length.
            // Accept any length >= 128 bytes (RSA-1024 minimum).
            if public_key_hex.len() >= 256 && hex::decode(public_key_hex).is_ok() {
                return Ok(());
            }
            return Err(format!(
                "RSA public_key must be >= 256 hex characters, got {}",
                public_key_hex.len()
            ));
        }
    };
    let expected_hex = expected_bytes * 2;
    if public_key_hex.len() != expected_hex {
        return Err(format!(
            "public_key must be {expected_hex} hex characters ({expected_bytes} bytes {algorithm})"
        ));
    }
    if hex::decode(public_key_hex).is_err() {
        return Err("public_key is not valid hex".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{
        MlDsaSigningProvider, SigningProvider, SoftwareSigningProvider,
    };

    #[test]
    fn ed25519_sign_and_verify() {
        let provider = SoftwareSigningProvider::generate();
        let msg = b"test message";
        let sig = provider.sign(msg).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(verify_ed25519(&pk_hex, msg, &sig_hex));
    }

    #[test]
    fn ed25519_wrong_message_fails() {
        let provider = SoftwareSigningProvider::generate();
        let sig = provider.sign(b"correct").unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(!verify_ed25519(&pk_hex, b"wrong", &sig_hex));
    }

    #[test]
    fn ed25519_bad_pk_hex_fails() {
        assert!(!verify_ed25519("not_hex", b"msg", &"aa".repeat(32)));
    }

    #[test]
    fn ed25519_wrong_pk_length_fails() {
        assert!(!verify_ed25519(&"aa".repeat(16), b"msg", &"bb".repeat(32)));
    }

    #[test]
    fn mldsa65_sign_and_verify() {
        let provider = MlDsaSigningProvider::generate();
        let msg = b"post-quantum message";
        let sig = provider.sign(msg).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(verify_mldsa65(&pk_hex, msg, &sig_hex));
    }

    #[test]
    fn mldsa65_wrong_message_fails() {
        let provider = MlDsaSigningProvider::generate();
        let sig = provider.sign(b"correct").unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(!verify_mldsa65(&pk_hex, b"wrong", &sig_hex));
    }

    #[test]
    fn mldsa65_bad_pk_length_fails() {
        assert!(!verify_mldsa65(
            &"aa".repeat(32),
            b"msg",
            &"bb".repeat(3309)
        ));
    }

    #[test]
    fn dispatch_ed25519() {
        let provider = SoftwareSigningProvider::generate();
        let msg = b"dispatch test";
        let sig = provider.sign(msg).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(verify_signature(
            SigningAlgorithm::Ed25519,
            &pk_hex,
            msg,
            &sig_hex
        ));
    }

    #[test]
    fn dispatch_mldsa65() {
        let provider = MlDsaSigningProvider::generate();
        let msg = b"pqc dispatch";
        let sig = provider.sign(msg).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(verify_signature(
            SigningAlgorithm::MlDsa65,
            &pk_hex,
            msg,
            &sig_hex
        ));
    }

    #[test]
    fn dispatch_wrong_algorithm_fails() {
        let provider = SoftwareSigningProvider::generate();
        let msg = b"cross algo";
        let sig = provider.sign(msg).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        // Ed25519 sig verified as MlDsa65 → wrong pk length → false
        assert!(!verify_signature(
            SigningAlgorithm::MlDsa65,
            &pk_hex,
            msg,
            &sig_hex
        ));
    }

    // ── Ed25519 signature input rejection ──────────────────────────

    #[test]
    fn ed25519_bad_sig_hex_fails() {
        let pk = "aa".repeat(32);
        assert!(!verify_ed25519(&pk, b"msg", "not_valid_hex"));
    }

    #[test]
    fn ed25519_wrong_sig_length_fails() {
        let pk = "aa".repeat(32);
        assert!(!verify_ed25519(&pk, b"msg", &"bb".repeat(16)));
    }

    #[test]
    fn ed25519_structurally_invalid_pk_fails() {
        // 32 bytes of 0xff — valid hex, valid length, but not a valid Ed25519 point
        assert!(!verify_ed25519(&"ff".repeat(32), b"msg", &"aa".repeat(32)));
    }

    // ── ML-DSA-65 signature input rejection ─────────────────────────

    #[test]
    fn mldsa65_bad_sig_hex_fails() {
        let pk = "aa".repeat(1952);
        assert!(!verify_mldsa65(&pk, b"msg", "not_valid_hex"));
    }

    #[test]
    fn mldsa65_wrong_sig_length_fails() {
        let pk = "aa".repeat(1952);
        assert!(!verify_mldsa65(&pk, b"msg", &"bb".repeat(100)));
    }

    #[test]
    fn mldsa65_bad_pk_hex_fails() {
        assert!(!verify_mldsa65(
            "not_hex_at_all",
            b"msg",
            &"bb".repeat(3309)
        ));
    }

    // ── RSA signature verification ────────────────────────────────

    #[test]
    fn rsa_sign_and_verify() {
        use crate::identity::signing::{RsaSigningProvider, SigningProvider};
        let provider = RsaSigningProvider::generate();
        let msg = b"RSA test message";
        let sig = provider.sign(msg).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(verify_rsa(&pk_hex, msg, &sig_hex));
    }

    #[test]
    fn rsa_wrong_message_fails() {
        use crate::identity::signing::{RsaSigningProvider, SigningProvider};
        let provider = RsaSigningProvider::generate();
        let sig = provider.sign(b"correct").unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(!verify_rsa(&pk_hex, b"wrong", &sig_hex));
    }

    #[test]
    fn dispatch_rsa() {
        use crate::identity::signing::{RsaSigningProvider, SigningProvider};
        let provider = RsaSigningProvider::generate();
        let msg = b"rsa dispatch";
        let sig = provider.sign(msg).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(verify_signature(
            SigningAlgorithm::Rsa,
            &pk_hex,
            msg,
            &sig_hex
        ));
    }

    // ── ECDSA P-256 (ES256) verification ─────────────────────────

    #[test]
    fn es256_sign_and_verify_via_dispatcher() {
        use crate::identity::signing::{EcdsaP256SigningProvider, SigningProvider};
        let provider = EcdsaP256SigningProvider::generate();
        let msg = b"es256 dispatch test";
        let sig = provider.sign(msg).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(verify_ecdsa_p256(&pk_hex, msg, &sig_hex));
        assert!(verify_signature(
            SigningAlgorithm::EcdsaP256,
            &pk_hex,
            msg,
            &sig_hex
        ));
    }

    #[test]
    fn es256_wrong_message_fails() {
        use crate::identity::signing::{EcdsaP256SigningProvider, SigningProvider};
        let provider = EcdsaP256SigningProvider::generate();
        let sig = provider.sign(b"correct").unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(!verify_ecdsa_p256(&pk_hex, b"wrong", &sig_hex));
    }

    #[test]
    fn es256_bad_pk_hex_fails() {
        assert!(!verify_ecdsa_p256("not_hex", b"msg", &"aa".repeat(32)));
    }

    #[test]
    fn es256_wrong_pk_length_fails() {
        assert!(!verify_ecdsa_p256(
            &"aa".repeat(16),
            b"msg",
            &"bb".repeat(32)
        ));
    }

    #[test]
    fn es256_wrong_sig_length_fails() {
        let pk = "04".to_string() + &"aa".repeat(64); // 65-byte uncompressed prefix
        assert!(!verify_ecdsa_p256(&pk, b"msg", &"bb".repeat(16)));
    }

    #[test]
    fn es256_cross_algorithm_dispatch_fails() {
        use crate::identity::signing::{EcdsaP256SigningProvider, SigningProvider};
        let provider = EcdsaP256SigningProvider::generate();
        let msg = b"cross algo";
        let sig = provider.sign(msg).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(!verify_signature(
            SigningAlgorithm::Ed25519,
            &pk_hex,
            msg,
            &sig_hex
        ));
    }

    #[test]
    fn infer_algorithm_p256_uncompressed() {
        let pk_hex = "04".to_string() + &"ab".repeat(64); // 130 hex = 65 bytes
        assert_eq!(
            infer_algorithm_from_key(&pk_hex),
            Some(SigningAlgorithm::EcdsaP256)
        );
    }

    #[test]
    fn infer_algorithm_p256_compressed() {
        let pk_hex = "02".to_string() + &"ab".repeat(32); // 66 hex = 33 bytes
        assert_eq!(
            infer_algorithm_from_key(&pk_hex),
            Some(SigningAlgorithm::EcdsaP256)
        );
    }

    #[test]
    fn validate_pk_ecdsa_p256_correct() {
        let pk = "04".to_string() + &"aa".repeat(64);
        assert!(validate_public_key(SigningAlgorithm::EcdsaP256, &pk).is_ok());
    }

    #[test]
    fn validate_pk_ecdsa_p256_wrong_length() {
        let err = validate_public_key(SigningAlgorithm::EcdsaP256, &"aa".repeat(32)).unwrap_err();
        assert!(err.contains("P-256"));
    }

    #[test]
    fn validate_pk_ed25519_correct() {
        assert!(validate_public_key(SigningAlgorithm::Ed25519, &"aa".repeat(32)).is_ok());
    }

    #[test]
    fn validate_pk_ed25519_wrong_length() {
        let err = validate_public_key(SigningAlgorithm::Ed25519, &"aa".repeat(16)).unwrap_err();
        assert!(err.contains("64 hex"));
    }

    #[test]
    fn validate_pk_mldsa65_correct() {
        assert!(validate_public_key(SigningAlgorithm::MlDsa65, &"aa".repeat(1952)).is_ok());
    }

    #[test]
    fn validate_pk_mldsa65_wrong_length() {
        let err = validate_public_key(SigningAlgorithm::MlDsa65, &"aa".repeat(32)).unwrap_err();
        assert!(err.contains("3904 hex"));
    }

    #[test]
    fn validate_pk_non_hex() {
        let err = validate_public_key(SigningAlgorithm::Ed25519, &"zz".repeat(32)).unwrap_err();
        assert!(err.contains("not valid hex"));
    }
}
