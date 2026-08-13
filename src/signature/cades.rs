//! CAdES-BES (CMS Advanced Electronic Signatures — Basic).
//!
//! ETSI TS 101 733 — produces CMS-style signature envelopes from `SignedEnvelope`.
//! Structured representation of CMS SignedData with XAdES-equivalent signed attributes.

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::signing::SigningAlgorithm;
use crate::signature::{SignatureLevel, SignedEnvelope};
use serde::{Deserialize, Serialize};

/// CMS content type OID for signed data.
const CONTENT_TYPE_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
/// CMS content type OID for data.
const CONTENT_TYPE_DATA: &str = "1.2.840.113549.1.7.1";

/// CAdES-BES envelope — CMS SignedData with signed attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CadesEnvelope {
    /// CMS version (always 1 for CAdES-BES).
    pub version: u32,
    /// Content type OID.
    pub content_type: String,
    /// Digest algorithm identifier.
    pub digest_algorithm: String,
    /// The signer info block.
    pub signer_info: CadesSignerInfo,
    /// Signing certificate digest (SHA-256 of public key).
    pub certificate_digest: String,
}

/// CMS SignerInfo with CAdES signed attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CadesSignerInfo {
    /// Signer identifier (DID).
    pub signer_id: String,
    /// Digest algorithm used.
    pub digest_algorithm: String,
    /// Signed attributes.
    pub signed_attributes: CadesSignedAttributes,
    /// Signature algorithm OID/identifier.
    pub signature_algorithm: SigningAlgorithm,
    /// Signature value (hex-encoded).
    pub signature: String,
    /// Public key (hex-encoded).
    pub public_key: String,
}

/// CAdES signed attributes (ETSI TS 101 733 §5.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CadesSignedAttributes {
    /// Content type (always id-data).
    pub content_type: String,
    /// Message digest of the signed content (hex).
    pub message_digest: String,
    /// Signing time (ISO 8601).
    pub signing_time: String,
    /// Signing certificate v2 reference (digest of signer's key).
    pub signing_certificate_v2: String,
    /// Signature level (FES/FEA/FEQ).
    pub commitment_type: String,
}

/// Build a CAdES-BES envelope from a `SignedEnvelope`.
pub fn to_cades_bes(envelope: &SignedEnvelope) -> CadesEnvelope {
    let cert_digest = {
        let pk_bytes = hex::decode(&envelope.public_key).unwrap_or_default();
        hex::encode(hash_with(HashAlgorithm::Sha256, &pk_bytes))
    };

    let signing_time = crate::signature::xades::timestamp_to_iso8601(envelope.signed_at);

    let commitment = match envelope.level {
        SignatureLevel::Simple => "FES",
        SignatureLevel::Advanced => "FEA",
        SignatureLevel::Qualified => "FEQ",
        SignatureLevel::Seal => "SEAL",
    };

    let signed_attrs = CadesSignedAttributes {
        content_type: CONTENT_TYPE_DATA.to_string(),
        message_digest: envelope.content_hash.clone(),
        signing_time,
        signing_certificate_v2: cert_digest.clone(),
        commitment_type: commitment.to_string(),
    };

    let signer_info = CadesSignerInfo {
        signer_id: envelope.signer.clone(),
        digest_algorithm: "SHA-256".to_string(),
        signed_attributes: signed_attrs,
        signature_algorithm: envelope.signature_algorithm,
        signature: envelope.signature.clone(),
        public_key: envelope.public_key.clone(),
    };

    CadesEnvelope {
        version: 1,
        content_type: CONTENT_TYPE_SIGNED_DATA.to_string(),
        digest_algorithm: "SHA-256".to_string(),
        signer_info,
        certificate_digest: cert_digest,
    }
}

/// Extract core fields from a CAdES envelope for verification.
pub fn extract_cades_fields(env: &CadesEnvelope) -> CadesFields {
    CadesFields {
        signer_id: env.signer_info.signer_id.clone(),
        message_digest: env.signer_info.signed_attributes.message_digest.clone(),
        signing_time: env.signer_info.signed_attributes.signing_time.clone(),
        commitment_type: env.signer_info.signed_attributes.commitment_type.clone(),
        signature: env.signer_info.signature.clone(),
        public_key: env.signer_info.public_key.clone(),
        algorithm: env.signer_info.signature_algorithm,
    }
}

/// Extracted fields for verification.
#[derive(Debug, Clone)]
pub struct CadesFields {
    pub signer_id: String,
    pub message_digest: String,
    pub signing_time: String,
    pub commitment_type: String,
    pub signature: String,
    pub public_key: String,
    pub algorithm: SigningAlgorithm,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};

    fn make_envelope() -> SignedEnvelope {
        let provider = SoftwareSigningProvider::generate();
        let content_hash = hex::encode(hash_with(HashAlgorithm::Sha256, b"cades test document"));
        let payload = format!("fes:did:goya:test:{content_hash}");
        let signature = hex::encode(provider.sign(payload.as_bytes()).unwrap());
        let public_key = hex::encode(provider.public_key());
        SignedEnvelope {
            level: SignatureLevel::Simple,
            signer: "did:goya:test".to_string(),
            content_hash,
            signature,
            public_key,
            signature_algorithm: SigningAlgorithm::Ed25519,
            biometric_evidence: vec![],
            signed_at: 1700000000,
        }
    }

    #[test]
    fn produces_version_1() {
        let env = make_envelope();
        let cades = to_cades_bes(&env);
        assert_eq!(cades.version, 1);
    }

    #[test]
    fn content_type_is_signed_data() {
        let env = make_envelope();
        let cades = to_cades_bes(&env);
        assert_eq!(cades.content_type, CONTENT_TYPE_SIGNED_DATA);
    }

    #[test]
    fn signer_info_contains_did() {
        let env = make_envelope();
        let cades = to_cades_bes(&env);
        assert_eq!(cades.signer_info.signer_id, "did:goya:test");
    }

    #[test]
    fn signed_attributes_contain_message_digest() {
        let env = make_envelope();
        let cades = to_cades_bes(&env);
        assert_eq!(
            cades.signer_info.signed_attributes.message_digest,
            env.content_hash
        );
    }

    #[test]
    fn signed_attributes_contain_signing_time() {
        let env = make_envelope();
        let cades = to_cades_bes(&env);
        assert_eq!(
            cades.signer_info.signed_attributes.signing_time,
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn signed_attributes_contain_cert_v2() {
        let env = make_envelope();
        let cades = to_cades_bes(&env);
        assert!(!cades
            .signer_info
            .signed_attributes
            .signing_certificate_v2
            .is_empty());
        assert_eq!(
            cades.signer_info.signed_attributes.signing_certificate_v2,
            cades.certificate_digest
        );
    }

    #[test]
    fn fes_commitment_type() {
        let env = make_envelope();
        let cades = to_cades_bes(&env);
        assert_eq!(cades.signer_info.signed_attributes.commitment_type, "FES");
    }

    #[test]
    fn fea_commitment_type() {
        let mut env = make_envelope();
        env.level = SignatureLevel::Advanced;
        let cades = to_cades_bes(&env);
        assert_eq!(cades.signer_info.signed_attributes.commitment_type, "FEA");
    }

    #[test]
    fn signature_preserved() {
        let env = make_envelope();
        let cades = to_cades_bes(&env);
        assert_eq!(cades.signer_info.signature, env.signature);
    }

    #[test]
    fn extract_fields_roundtrip() {
        let env = make_envelope();
        let cades = to_cades_bes(&env);
        let fields = extract_cades_fields(&cades);
        assert_eq!(fields.signer_id, "did:goya:test");
        assert_eq!(fields.message_digest, env.content_hash);
        assert_eq!(fields.algorithm, SigningAlgorithm::Ed25519);
    }

    #[test]
    fn deterministic_output() {
        let env = make_envelope();
        let c1 = to_cades_bes(&env);
        let c2 = to_cades_bes(&env);
        let j1 = serde_json::to_string(&c1).unwrap();
        let j2 = serde_json::to_string(&c2).unwrap();
        assert_eq!(j1, j2);
    }

    #[test]
    fn serialization_roundtrip() {
        let env = make_envelope();
        let cades = to_cades_bes(&env);
        let json = serde_json::to_string(&cades).unwrap();
        let parsed: CadesEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.signer_info.signer_id, "did:goya:test");
    }
}
