//! X.509 certificate chain validation.
//!
//! Validates a leaf certificate against a trust store of root CAs:
//! - Parses DER/PEM certificates
//! - Checks validity period (notBefore/notAfter)
//! - Verifies issuer→subject chain linking
//! - Walks the chain to a trusted root

use x509_parser::prelude::*;

/// Result of chain validation.
#[derive(Debug, Clone)]
pub struct ChainValidationResult {
    pub valid: bool,
    pub chain_length: usize,
    pub leaf_subject: String,
    pub root_subject: String,
    pub error: Option<String>,
}

/// Extracted cert fields (owned, no lifetime issues).
#[derive(Debug, Clone)]
struct CertInfo {
    subject: String,
    issuer: String,
    not_before: u64,
    not_after: u64,
    is_ca: bool,
}

fn extract_cert_info(der: &[u8]) -> Result<CertInfo, String> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| format!("DER parse error: {e}"))?;
    let validity = cert.validity();
    Ok(CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: validity.not_before.timestamp() as u64,
        not_after: validity.not_after.timestamp() as u64,
        is_ca: cert
            .basic_constraints()
            .ok()
            .flatten()
            .map(|bc| bc.value.ca)
            .unwrap_or(false),
    })
}

fn pem_to_der_chain(pem_str: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut ders = Vec::new();
    for pem in Pem::iter_from_buffer(pem_str.as_bytes()) {
        let pem = pem.map_err(|e| format!("PEM parse error: {e}"))?;
        if pem.label == "CERTIFICATE" {
            ders.push(pem.contents);
        }
    }
    Ok(ders)
}

/// Validate a certificate chain from leaf to root.
pub fn validate_chain(
    chain_pem: &str,
    trusted_roots_pem: &[&str],
    now_secs: u64,
) -> ChainValidationResult {
    let ders = match pem_to_der_chain(chain_pem) {
        Ok(d) if !d.is_empty() => d,
        Ok(_) => {
            return ChainValidationResult {
                valid: false,
                chain_length: 0,
                leaf_subject: String::new(),
                root_subject: String::new(),
                error: Some("empty certificate chain".into()),
            };
        }
        Err(e) => {
            return ChainValidationResult {
                valid: false,
                chain_length: 0,
                leaf_subject: String::new(),
                root_subject: String::new(),
                error: Some(format!("chain parse error: {e}")),
            };
        }
    };

    let certs: Vec<CertInfo> = match ders.iter().map(|d| extract_cert_info(d)).collect() {
        Ok(c) => c,
        Err(e) => {
            return ChainValidationResult {
                valid: false,
                chain_length: ders.len(),
                leaf_subject: String::new(),
                root_subject: String::new(),
                error: Some(e),
            };
        }
    };

    let leaf_subject = certs[0].subject.clone();
    let root_subject = certs.last().map(|c| c.subject.clone()).unwrap_or_default();

    // Check validity periods
    for (i, cert) in certs.iter().enumerate() {
        if now_secs < cert.not_before || now_secs > cert.not_after {
            return ChainValidationResult {
                valid: false,
                chain_length: certs.len(),
                leaf_subject,
                root_subject,
                error: Some(format!("certificate {i} expired or not yet valid")),
            };
        }
    }

    // Verify issuer chain linking
    for i in 0..certs.len() - 1 {
        if certs[i].issuer != certs[i + 1].subject {
            return ChainValidationResult {
                valid: false,
                chain_length: certs.len(),
                leaf_subject,
                root_subject,
                error: Some(format!(
                    "chain break: cert {i} issuer does not match cert {} subject",
                    i + 1
                )),
            };
        }
    }

    // Check root is self-signed or chains to trusted root
    let root = certs.last().unwrap();
    if root.issuer != root.subject {
        let mut found_trust = false;
        for trust_pem in trusted_roots_pem {
            if let Ok(trust_ders) = pem_to_der_chain(trust_pem) {
                for td in &trust_ders {
                    if let Ok(tc) = extract_cert_info(td) {
                        if root.issuer == tc.subject {
                            found_trust = true;
                            break;
                        }
                    }
                }
            }
            if found_trust {
                break;
            }
        }
        if !found_trust {
            return ChainValidationResult {
                valid: false,
                chain_length: certs.len(),
                leaf_subject,
                root_subject,
                error: Some("root certificate not found in trust store".into()),
            };
        }
    }

    // Check CA basic constraints on non-leaf certs
    for (i, cert) in certs.iter().enumerate().skip(1) {
        if !cert.is_ca {
            return ChainValidationResult {
                valid: false,
                chain_length: certs.len(),
                leaf_subject,
                root_subject,
                error: Some(format!("certificate {i} missing CA basic constraint")),
            };
        }
    }

    ChainValidationResult {
        valid: true,
        chain_length: certs.len(),
        leaf_subject,
        root_subject,
        error: None,
    }
}

/// Validate a single DER certificate's validity period.
pub fn validate_cert_der(der: &[u8], now_secs: u64) -> Result<String, String> {
    let info = extract_cert_info(der)?;
    if now_secs < info.not_before || now_secs > info.not_after {
        return Err("certificate expired or not yet valid".into());
    }
    Ok(info.subject)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_chain() -> (String, String) {
        use rcgen::{CertificateParams, DnType, IsCa, KeyPair};

        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(vec![]).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root CA");
        root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["node-1".into()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Test Node 1");
        leaf_params.is_ca = IsCa::NoCa;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let chain_pem = format!("{}{}", leaf_cert.pem(), root_cert.pem());
        let root_pem = root_cert.pem();
        (chain_pem, root_pem)
    }

    #[test]
    fn valid_chain_validates() {
        let (chain, root) = generate_test_chain();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let result = validate_chain(&chain, &[&root], now);
        assert!(result.valid, "error: {:?}", result.error);
        assert_eq!(result.chain_length, 2);
        assert!(result.leaf_subject.contains("Test Node 1"));
    }

    #[test]
    fn not_yet_valid_cert_rejected() {
        let (chain, root) = generate_test_chain();
        // Before notBefore — cert not yet valid
        let past = 1_000_000u64;
        let result = validate_chain(&chain, &[&root], past);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("expired or not yet valid"));
    }

    #[test]
    fn empty_chain_rejected() {
        let result = validate_chain("", &[], 1_700_000_000);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("empty"));
    }

    #[test]
    fn self_signed_root_validates() {
        use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "Self Signed");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let result = validate_chain(&pem, &[], now);
        assert!(result.valid, "error: {:?}", result.error);
        assert_eq!(result.chain_length, 1);
    }

    #[test]
    fn validate_cert_der_valid() {
        use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "DER Test");
        params.is_ca = IsCa::NoCa;
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().to_vec();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let subject = validate_cert_der(&der, now).unwrap();
        assert!(subject.contains("DER Test"));
    }

    #[test]
    fn validate_cert_der_expired() {
        use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "Expired");
        params.is_ca = IsCa::NoCa;
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().to_vec();
        assert!(validate_cert_der(&der, 1_000_000).is_err());
    }

    #[test]
    fn three_level_hierarchy() {
        use rcgen::{CertificateParams, DnType, IsCa, KeyPair};

        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(vec![]).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Root CA");
        root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = root_params.self_signed(&root_key).unwrap();

        let inter_key = KeyPair::generate().unwrap();
        let mut inter_params = CertificateParams::new(vec![]).unwrap();
        inter_params
            .distinguished_name
            .push(DnType::CommonName, "Intermediate CA");
        inter_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let inter = inter_params
            .signed_by(&inter_key, &root, &root_key)
            .unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["leaf".into()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Leaf");
        leaf_params.is_ca = IsCa::NoCa;
        let leaf = leaf_params
            .signed_by(&leaf_key, &inter, &inter_key)
            .unwrap();

        let chain = format!("{}{}{}", leaf.pem(), inter.pem(), root.pem());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let result = validate_chain(&chain, &[&root.pem()], now);
        assert!(result.valid, "error: {:?}", result.error);
        assert_eq!(result.chain_length, 3);
    }
}
