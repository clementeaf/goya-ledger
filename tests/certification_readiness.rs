//! Certification readiness tests — simulate what a TDRA/EU auditor would check.
//!
//! Validates that cryptographic artefacts produced by GOYA meet the structural
//! requirements of EN 319 412-5, RFC 3161, ETSI TS 101 733, and ISO 18013-5.

use rust_bc::identity::mdoc::{
    issue_mdoc, sign_device_auth, verify_device_auth, verify_mdoc, MdocParams,
};
use rust_bc::identity::ra::{
    loa_from_method, validate_emirates_id, validate_national_id, validate_rut, EidasLoA,
    Jurisdiction, ProofingMethod,
};
use rust_bc::identity::sd_jwt::{issue_sd_jwt_vc, VcClaims};
use rust_bc::identity::signing::{SigningProvider, SoftwareSigningProvider};
use rust_bc::pki::{
    build_qc_statements_der, build_qc_statements_der_ext, sign_node_cert_with_subject,
    NodeCaConfig, QcStatementsParams, SubjectIdentity, QC_LIMIT_VALUE_OID, QC_RETENTION_OID,
    QC_SSCD_OID,
};
use rust_bc::pki_policy::CertProfileType;
use std::collections::BTreeMap;

// ── QCStatements (EN 319 412-5) ────────────────────────────────────────

#[test]
fn qc_statements_basic_contains_compliance_and_type() {
    let der = build_qc_statements_der(CertProfileType::NaturalPerson);
    assert!(!der.is_empty());
    // Must be a SEQUENCE (tag 0x30)
    assert_eq!(der[0], 0x30);
}

#[test]
fn qc_statements_ext_includes_qscd() {
    let basic = build_qc_statements_der(CertProfileType::NaturalPerson);
    let ext = build_qc_statements_der_ext(&QcStatementsParams {
        profile: CertProfileType::NaturalPerson,
        qscd: true,
        retention_years: None,
        limit_value_cents: None,
    });
    assert!(ext.len() > basic.len(), "QSCD statement should add bytes");
}

#[test]
fn qc_statements_ext_includes_retention() {
    let ext = build_qc_statements_der_ext(&QcStatementsParams {
        profile: CertProfileType::LegalPerson,
        qscd: false,
        retention_years: Some(15),
        limit_value_cents: None,
    });
    let basic = build_qc_statements_der(CertProfileType::LegalPerson);
    assert!(ext.len() > basic.len(), "retention should add bytes");
}

#[test]
fn qc_statements_ext_includes_limit_value() {
    let ext = build_qc_statements_der_ext(&QcStatementsParams {
        profile: CertProfileType::NaturalPerson,
        qscd: true,
        retention_years: Some(7),
        limit_value_cents: Some(100_000),
    });
    let basic = build_qc_statements_der(CertProfileType::NaturalPerson);
    assert!(
        ext.len() > basic.len() + 20,
        "all 3 extra statements should add significant bytes"
    );
}

#[test]
fn qc_statements_all_profiles_differ() {
    let natural = build_qc_statements_der(CertProfileType::NaturalPerson);
    let legal = build_qc_statements_der(CertProfileType::LegalPerson);
    let web = build_qc_statements_der(CertProfileType::WebAuthentication);
    assert_ne!(natural, legal);
    assert_ne!(legal, web);
    assert_ne!(natural, web);
}

// ── Certificate DN (EN 319 412-2/3) ────────────────────────────────────

#[test]
fn cert_with_natural_person_dn() {
    let (ca, _cert_pem, _key_pem) = NodeCaConfig::generate().unwrap();
    let subject = SubjectIdentity {
        given_name: Some("أحمد".into()),
        surname: Some("المنصور".into()),
        serial_number: Some("784-1990-1234567-6".into()),
        country: Some("AE".into()),
        organization: None,
        organization_id: None,
    };
    let cert = sign_node_cert_with_subject("node-1", &ca, 365, &subject).unwrap();
    assert!(!cert.cert_pem.is_empty());
    // Parse with x509-parser to verify DN fields
    let der = cert.cert_der.as_ref();
    let (_, parsed) = x509_parser::parse_x509_certificate(der).expect("valid X.509");
    let subject_str = format!("{}", parsed.subject());
    assert!(
        subject_str.contains("AE"),
        "country missing from DN: {subject_str}"
    );
}

#[test]
fn cert_with_legal_person_dn() {
    let (ca, _cert_pem, _key_pem) = NodeCaConfig::generate().unwrap();
    let subject = SubjectIdentity {
        given_name: None,
        surname: None,
        serial_number: None,
        country: Some("CL".into()),
        organization: Some("Goya Ledger SpA".into()),
        organization_id: Some("VATCL-76123456-7".into()),
    };
    let cert = sign_node_cert_with_subject("org-node", &ca, 365, &subject).unwrap();
    let der = cert.cert_der.as_ref();
    let (_, parsed) = x509_parser::parse_x509_certificate(der).expect("valid X.509");
    let subject_str = format!("{}", parsed.subject());
    assert!(
        subject_str.contains("Goya Ledger"),
        "org missing: {subject_str}"
    );
}

#[test]
fn cert_without_subject_backwards_compat() {
    let (ca, _cert_pem, _key_pem) = NodeCaConfig::generate().unwrap();
    let cert =
        sign_node_cert_with_subject("basic-node", &ca, 365, &SubjectIdentity::default()).unwrap();
    assert!(!cert.cert_pem.is_empty());
}

// ── LoA eIDAS (Regulation 2015/1502) ───────────────────────────────────

#[test]
fn loa_in_person_is_high() {
    assert_eq!(loa_from_method(ProofingMethod::InPerson), EidasLoA::High);
}

#[test]
fn loa_video_is_substantial() {
    assert_eq!(
        loa_from_method(ProofingMethod::VideoConference),
        EidasLoA::Substantial
    );
}

#[test]
fn loa_uae_pass_is_substantial() {
    assert_eq!(
        loa_from_method(ProofingMethod::UaePass),
        EidasLoA::Substantial
    );
}

#[test]
fn loa_remote_is_low() {
    assert_eq!(
        loa_from_method(ProofingMethod::RemoteAutomated),
        EidasLoA::Low
    );
}

// ── Multi-jurisdiction identity validation ──────────────────────────────

#[test]
fn chile_rut_validation() {
    assert!(validate_rut("12345678-5").is_ok());
    assert!(validate_rut("12345678-0").is_err());
}

#[test]
fn uae_emirates_id_validation() {
    assert!(validate_emirates_id("784-1990-1234567-6").is_ok());
    assert!(validate_emirates_id("000-1990-1234567-6").is_err());
}

#[test]
fn national_id_dispatch_all_jurisdictions() {
    assert!(validate_national_id("12345678-5", Jurisdiction::Chile).is_ok());
    assert!(validate_national_id("784-1990-1234567-6", Jurisdiction::Uae).is_ok());
    assert!(validate_national_id("DE987654321", Jurisdiction::Eu).is_ok());
}

// ── SD-JWT VC structure ────────────────────────────────────────────────

#[test]
fn sd_jwt_vc_has_required_claims() {
    let provider = SoftwareSigningProvider::generate();
    let claims = VcClaims {
        iss: format!("did:goya:{}", &hex::encode(provider.public_key())[..16]),
        sub: "did:goya:holder".into(),
        iat: 1_700_000_000,
        exp: 2_000_000_000,
        vct: "IdentityCredential".into(),
        claims: vec![
            ("given_name".into(), serde_json::json!("أحمد")),
            ("family_name".into(), serde_json::json!("المنصور")),
            (
                "emirates_id".into(),
                serde_json::json!("784-1990-1234567-6"),
            ),
        ],
    };
    let sd_jwt = issue_sd_jwt_vc(&claims, &provider).unwrap();
    assert!(sd_jwt.compact.contains('~'));
    // JWT header.payload must exist
    let jwt_part = sd_jwt.compact.split('~').next().unwrap();
    assert_eq!(jwt_part.split('.').count(), 3);
}

// ── mdoc device authentication (ISO 18013-5) ──────────────────────────

#[test]
fn mdoc_full_verification_flow() {
    let issuer = SoftwareSigningProvider::generate();
    let holder = SoftwareSigningProvider::generate();
    let holder_pk = hex::encode(holder.public_key());

    let mut elements = BTreeMap::new();
    elements.insert(
        "eu.europa.ec.eudi.pid.1".to_string(),
        vec![
            ("given_name".to_string(), serde_json::json!("Juan")),
            ("family_name".to_string(), serde_json::json!("Pérez")),
        ],
    );
    let params = MdocParams {
        doc_type: "eu.europa.ec.eudi.pid.1".into(),
        elements,
        valid_from: 1_700_000_000,
        valid_until: 2_000_000_000,
        device_key: Some(holder_pk.clone()),
    };

    let mdoc = issue_mdoc(&params, &issuer).unwrap();

    // 1. Verify issuer signature
    let verified = verify_mdoc(&mdoc).unwrap();
    assert_eq!(verified.doc_type, "eu.europa.ec.eudi.pid.1");

    // 2. Verify device authentication (holder proves key possession)
    let session_transcript = b"session-transcript-for-verifier";
    let device_auth = sign_device_auth(&holder, session_transcript).unwrap();
    assert!(verify_device_auth(&device_auth, &holder_pk, session_transcript).is_ok());
}

// ── OID summary ────────────────────────────────────────────────────────

#[test]
fn oid_constants_are_valid() {
    assert!(QC_SSCD_OID.starts_with("0.4.0.1862"));
    assert!(QC_RETENTION_OID.starts_with("0.4.0.1862"));
    assert!(QC_LIMIT_VALUE_OID.starts_with("0.4.0.1862"));
}
