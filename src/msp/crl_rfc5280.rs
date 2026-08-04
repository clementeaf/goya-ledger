//! RFC 5280 CRL generation via rcgen.
//!
//! Converts the internal `Vec<String>` serial list into a proper
//! DER-encoded X.509 CRL signed by the node's CA.

use rcgen::{CertificateRevocationListParams, RevocationReason, RevokedCertParams, SerialNumber};
use time::OffsetDateTime;

use crate::pki::NodeCaConfig;

/// Generate a DER-encoded RFC 5280 CRL from a list of revoked serials.
///
/// Each serial is a hex-encoded string (as stored by `CrlStore`).
/// The CRL is signed by the CA in `ca_config`.
pub fn generate_crl_der(
    revoked_serials: &[String],
    ca_config: &NodeCaConfig,
    crl_number: u64,
    validity_days: u32,
) -> Result<Vec<u8>, CrlError> {
    let now = OffsetDateTime::now_utc();
    let next_update = now + time::Duration::days(i64::from(validity_days));

    let revoked_certs: Vec<RevokedCertParams> = revoked_serials
        .iter()
        .filter_map(|serial_hex| {
            let bytes = hex::decode(serial_hex).ok()?;
            Some(RevokedCertParams {
                serial_number: SerialNumber::from(bytes),
                revocation_time: now,
                reason_code: Some(RevocationReason::Unspecified),
                invalidity_date: None,
            })
        })
        .collect();

    let params = CertificateRevocationListParams {
        this_update: now,
        next_update,
        crl_number: SerialNumber::from(crl_number.to_be_bytes().to_vec()),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let crl = params
        .signed_by(ca_config.cert(), ca_config.key())
        .map_err(|e| CrlError::Generation(e.to_string()))?;

    Ok(crl.der().to_vec())
}

/// Generate a PEM-encoded RFC 5280 CRL.
pub fn generate_crl_pem(
    revoked_serials: &[String],
    ca_config: &NodeCaConfig,
    crl_number: u64,
    validity_days: u32,
) -> Result<String, CrlError> {
    let now = OffsetDateTime::now_utc();
    let next_update = now + time::Duration::days(i64::from(validity_days));

    let revoked_certs: Vec<RevokedCertParams> = revoked_serials
        .iter()
        .filter_map(|serial_hex| {
            let bytes = hex::decode(serial_hex).ok()?;
            Some(RevokedCertParams {
                serial_number: SerialNumber::from(bytes),
                revocation_time: now,
                reason_code: Some(RevocationReason::Unspecified),
                invalidity_date: None,
            })
        })
        .collect();

    let params = CertificateRevocationListParams {
        this_update: now,
        next_update,
        crl_number: SerialNumber::from(crl_number.to_be_bytes().to_vec()),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let crl = params
        .signed_by(ca_config.cert(), ca_config.key())
        .map_err(|e| CrlError::Generation(e.to_string()))?;

    crl.pem().map_err(|e| CrlError::Generation(e.to_string()))
}

#[derive(Debug)]
pub enum CrlError {
    Generation(String),
}

impl std::fmt::Display for CrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generation(msg) => write!(f, "CRL generation failed: {msg}"),
        }
    }
}

impl std::error::Error for CrlError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ca() -> NodeCaConfig {
        let (ca, _cert_pem, _key_pem) = NodeCaConfig::generate().unwrap();
        ca
    }

    #[test]
    fn generate_empty_crl() {
        let ca = test_ca();
        let der = generate_crl_der(&[], &ca, 1, 7).unwrap();
        assert!(!der.is_empty());
        // DER starts with SEQUENCE tag (0x30)
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn generate_crl_with_revoked_serials() {
        let ca = test_ca();
        let serials = vec![hex::encode([1u8; 8]), hex::encode([2u8; 8])];
        let der = generate_crl_der(&serials, &ca, 1, 7).unwrap();
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn two_sequential_crl_generations_both_valid() {
        let ca = test_ca();
        let serials = vec![hex::encode([1u8; 4])];
        let der1 = generate_crl_der(&serials, &ca, 1, 7).unwrap();
        let der2 = generate_crl_der(&serials, &ca, 1, 7).unwrap();
        assert_eq!(der1[0], 0x30);
        assert_eq!(der2[0], 0x30);
    }

    #[test]
    fn different_crl_numbers_produce_different_output() {
        let ca = test_ca();
        let der1 = generate_crl_der(&[], &ca, 1, 7).unwrap();
        let der2 = generate_crl_der(&[], &ca, 2, 7).unwrap();
        assert_ne!(der1, der2);
    }

    #[test]
    fn pem_output_has_correct_markers() {
        let ca = test_ca();
        let pem = generate_crl_pem(&[], &ca, 1, 7).unwrap();
        assert!(pem.contains("-----BEGIN X509 CRL-----"));
        assert!(pem.contains("-----END X509 CRL-----"));
    }

    #[test]
    fn pem_with_revoked_certs() {
        let ca = test_ca();
        let serials = vec![hex::encode([0xAB; 16]), hex::encode([0xCD; 16])];
        let pem = generate_crl_pem(&serials, &ca, 42, 30).unwrap();
        assert!(pem.contains("-----BEGIN X509 CRL-----"));
    }

    #[test]
    fn invalid_hex_serial_skipped() {
        let ca = test_ca();
        let serials = vec!["not_hex".to_string(), hex::encode([1u8; 4])];
        let der = generate_crl_der(&serials, &ca, 1, 7).unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn large_crl() {
        let ca = test_ca();
        let serials: Vec<String> = (0..100u64).map(|i| hex::encode(i.to_be_bytes())).collect();
        let der = generate_crl_der(&serials, &ca, 1, 7).unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn x509_parser_can_parse_generated_crl() {
        use x509_parser::prelude::FromDer;
        let ca = test_ca();
        let serials = vec![hex::encode([1u8; 8])];
        let der = generate_crl_der(&serials, &ca, 1, 7).unwrap();
        let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(&der)
            .expect("generated CRL should be parseable by x509-parser");
        assert_eq!(
            crl.iter_revoked_certificates().count(),
            1,
            "CRL should contain 1 revoked cert"
        );
    }
}
