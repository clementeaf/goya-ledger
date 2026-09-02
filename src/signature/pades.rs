//! PAdES-BES (PDF Advanced Electronic Signatures — Basic).
//!
//! ETSI TS 102 778 — produces PDF signature metadata from `SignedEnvelope`.
//! Represents the signature dictionary fields that would be embedded in a PDF.

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::signing::SigningAlgorithm;
use crate::signature::{SignatureLevel, SignedEnvelope};
use serde::{Deserialize, Serialize};

/// PAdES signature dictionary — represents /Sig entry in a PDF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PadesSignature {
    /// Signature filter (always "Adobe.PPKLite" for interoperability).
    pub filter: String,
    /// Sub-filter identifying the encoding.
    pub sub_filter: String,
    /// Signer's name / DID.
    pub name: String,
    /// Signing time (ISO 8601).
    pub signing_time: String,
    /// Location of signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Reason for signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Contact info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_info: Option<String>,
    /// SHA-256 digest of the signed PDF byte range (hex).
    pub document_digest: String,
    /// Signature value (hex-encoded).
    pub signature: String,
    /// Public key (hex-encoded).
    pub public_key: String,
    /// Signing algorithm.
    pub signature_algorithm: SigningAlgorithm,
    /// Certificate digest (SHA-256 of public key, hex).
    pub certificate_digest: String,
    /// Signature level (FES/FEA/FEQ).
    pub signature_level: SignatureLevel,
}

/// Options for building a PAdES signature.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PadesOptions {
    pub location: Option<String>,
    pub reason: Option<String>,
    pub contact_info: Option<String>,
}

/// Build a PAdES-BES signature dictionary from a `SignedEnvelope`.
pub fn to_pades_bes(envelope: &SignedEnvelope, options: &PadesOptions) -> PadesSignature {
    let cert_digest = {
        let pk_bytes = hex::decode(&envelope.public_key).unwrap_or_default();
        hex::encode(hash_with(HashAlgorithm::Sha256, &pk_bytes))
    };

    let signing_time = crate::signature::xades::timestamp_to_iso8601(envelope.signed_at);

    let sub_filter = match envelope.signature_algorithm {
        SigningAlgorithm::Ed25519
        | SigningAlgorithm::MlDsa65
        | SigningAlgorithm::Rsa
        | SigningAlgorithm::EcdsaP256
        | SigningAlgorithm::SlhDsa128s => "adbe.pkcs7.detached",
    };

    PadesSignature {
        filter: "Adobe.PPKLite".to_string(),
        sub_filter: sub_filter.to_string(),
        name: envelope.signer.clone(),
        signing_time,
        location: options.location.clone(),
        reason: options.reason.clone(),
        contact_info: options.contact_info.clone(),
        document_digest: envelope.content_hash.clone(),
        signature: envelope.signature.clone(),
        public_key: envelope.public_key.clone(),
        signature_algorithm: envelope.signature_algorithm,
        certificate_digest: cert_digest,
        signature_level: envelope.level,
    }
}

/// Build a CMS PKCS#7 detached signature for PDF byte range (PAdES-BES).
///
/// This produces the DER bytes that go into the PDF `/Contents` field.
/// The `pdf_byte_range` is the data covered by the signature (everything
/// in the PDF except the `/Contents` hex placeholder).
pub fn build_pades_cms(
    pdf_byte_range: &[u8],
    provider: &dyn crate::identity::signing::SigningProvider,
    signing_time: u64,
) -> Result<Vec<u8>, crate::signature::cades_der::CadesDerError> {
    crate::signature::cades_der::build_cades_bes_der(pdf_byte_range, provider, signing_time)
}

/// Verify a PAdES CMS signature against PDF byte range data.
pub fn verify_pades_cms(
    cms_der: &[u8],
    pdf_byte_range: &[u8],
    public_key_hex: &str,
) -> Result<bool, String> {
    match crate::signature::cades_der::verify_cades_bes_der(cms_der, pdf_byte_range, public_key_hex)
    {
        Ok(_) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

/// Extract core fields from a PAdES signature for verification.
pub fn extract_pades_fields(sig: &PadesSignature) -> PadesFields {
    PadesFields {
        name: sig.name.clone(),
        document_digest: sig.document_digest.clone(),
        signing_time: sig.signing_time.clone(),
        signature: sig.signature.clone(),
        public_key: sig.public_key.clone(),
        algorithm: sig.signature_algorithm,
        level: sig.signature_level,
    }
}

/// Extracted fields for verification.
#[derive(Debug, Clone)]
pub struct PadesFields {
    pub name: String,
    pub document_digest: String,
    pub signing_time: String,
    pub signature: String,
    pub public_key: String,
    pub algorithm: SigningAlgorithm,
    pub level: SignatureLevel,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};

    fn make_envelope() -> SignedEnvelope {
        let provider = SoftwareSigningProvider::generate();
        let content_hash = hex::encode(hash_with(HashAlgorithm::Sha256, b"pades test pdf content"));
        let payload = format!("fes:did:goya:signer:{content_hash}");
        let signature = hex::encode(provider.sign(payload.as_bytes()).unwrap());
        let public_key = hex::encode(provider.public_key());
        SignedEnvelope {
            level: SignatureLevel::Simple,
            signer: "did:goya:signer".to_string(),
            content_hash,
            signature,
            public_key,
            signature_algorithm: SigningAlgorithm::Ed25519,
            biometric_evidence: vec![],
            signed_at: 1700000000,
            secondary_signature: None,
            secondary_public_key: None,
            secondary_algorithm: None,
        }
    }

    #[test]
    fn filter_is_adobe_ppklite() {
        let env = make_envelope();
        let pades = to_pades_bes(&env, &PadesOptions::default());
        assert_eq!(pades.filter, "Adobe.PPKLite");
    }

    #[test]
    fn sub_filter_is_pkcs7_detached() {
        let env = make_envelope();
        let pades = to_pades_bes(&env, &PadesOptions::default());
        assert_eq!(pades.sub_filter, "adbe.pkcs7.detached");
    }

    #[test]
    fn name_is_signer_did() {
        let env = make_envelope();
        let pades = to_pades_bes(&env, &PadesOptions::default());
        assert_eq!(pades.name, "did:goya:signer");
    }

    #[test]
    fn signing_time_iso8601() {
        let env = make_envelope();
        let pades = to_pades_bes(&env, &PadesOptions::default());
        assert_eq!(pades.signing_time, "2023-11-14T22:13:20Z");
    }

    #[test]
    fn document_digest_matches() {
        let env = make_envelope();
        let pades = to_pades_bes(&env, &PadesOptions::default());
        assert_eq!(pades.document_digest, env.content_hash);
    }

    #[test]
    fn signature_preserved() {
        let env = make_envelope();
        let pades = to_pades_bes(&env, &PadesOptions::default());
        assert_eq!(pades.signature, env.signature);
    }

    #[test]
    fn certificate_digest_computed() {
        let env = make_envelope();
        let pades = to_pades_bes(&env, &PadesOptions::default());
        assert!(!pades.certificate_digest.is_empty());
        assert_eq!(pades.certificate_digest.len(), 64);
    }

    #[test]
    fn options_location_reason() {
        let env = make_envelope();
        let opts = PadesOptions {
            location: Some("Santiago, Chile".into()),
            reason: Some("Firma de contrato".into()),
            contact_info: Some("contacto@goya.cl".into()),
        };
        let pades = to_pades_bes(&env, &opts);
        assert_eq!(pades.location.as_deref(), Some("Santiago, Chile"));
        assert_eq!(pades.reason.as_deref(), Some("Firma de contrato"));
        assert_eq!(pades.contact_info.as_deref(), Some("contacto@goya.cl"));
    }

    #[test]
    fn options_none_by_default() {
        let env = make_envelope();
        let pades = to_pades_bes(&env, &PadesOptions::default());
        assert!(pades.location.is_none());
        assert!(pades.reason.is_none());
        assert!(pades.contact_info.is_none());
    }

    #[test]
    fn fes_level() {
        let env = make_envelope();
        let pades = to_pades_bes(&env, &PadesOptions::default());
        assert_eq!(pades.signature_level, SignatureLevel::Simple);
    }

    #[test]
    fn fea_level() {
        let mut env = make_envelope();
        env.level = SignatureLevel::Advanced;
        let pades = to_pades_bes(&env, &PadesOptions::default());
        assert_eq!(pades.signature_level, SignatureLevel::Advanced);
    }

    #[test]
    fn extract_fields_roundtrip() {
        let env = make_envelope();
        let pades = to_pades_bes(&env, &PadesOptions::default());
        let fields = extract_pades_fields(&pades);
        assert_eq!(fields.name, "did:goya:signer");
        assert_eq!(fields.document_digest, env.content_hash);
        assert_eq!(fields.algorithm, SigningAlgorithm::Ed25519);
        assert_eq!(fields.level, SignatureLevel::Simple);
    }

    #[test]
    fn deterministic_output() {
        let env = make_envelope();
        let opts = PadesOptions::default();
        let j1 = serde_json::to_string(&to_pades_bes(&env, &opts)).unwrap();
        let j2 = serde_json::to_string(&to_pades_bes(&env, &opts)).unwrap();
        assert_eq!(j1, j2);
    }

    #[test]
    fn serialization_roundtrip() {
        let env = make_envelope();
        let pades = to_pades_bes(&env, &PadesOptions::default());
        let json = serde_json::to_string(&pades).unwrap();
        let parsed: PadesSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "did:goya:signer");
        assert_eq!(parsed.filter, "Adobe.PPKLite");
    }

    #[test]
    fn none_fields_skipped_in_json() {
        let env = make_envelope();
        let pades = to_pades_bes(&env, &PadesOptions::default());
        let json = serde_json::to_string(&pades).unwrap();
        assert!(!json.contains("location"));
        assert!(!json.contains("reason"));
        assert!(!json.contains("contact_info"));
    }

    #[test]
    fn pades_cms_roundtrip() {
        let provider = SoftwareSigningProvider::generate();
        let pdf_bytes = b"fake PDF byte range content";
        let cms = build_pades_cms(pdf_bytes, &provider, 1700000000).unwrap();
        assert_eq!(cms[0], 0x30, "CMS must start with SEQUENCE");
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_pades_cms(&cms, pdf_bytes, &pk_hex).unwrap());
    }

    #[test]
    fn pades_cms_wrong_key_fails() {
        let provider = SoftwareSigningProvider::generate();
        let other = SoftwareSigningProvider::generate();
        let pdf_data = b"pdf data";
        let cms = build_pades_cms(pdf_data, &provider, 1700000000).unwrap();
        let wrong_pk = hex::encode(other.public_key());
        assert!(verify_pades_cms(&cms, pdf_data, &wrong_pk).is_err());
    }

    #[test]
    fn pades_cms_interop_x509_parser() {
        let provider = SoftwareSigningProvider::generate();
        let cms = build_pades_cms(b"pdf content", &provider, 1700000000).unwrap();
        let (rem, parsed) =
            x509_parser::der_parser::parse_der(&cms).expect("x509-parser must parse PAdES CMS");
        assert!(rem.is_empty());
        let seq = parsed.as_sequence().unwrap();
        let oid = seq[0].as_oid().unwrap();
        assert_eq!(oid.to_string(), "1.2.840.113549.1.7.2"); // id-signedData
    }
}
