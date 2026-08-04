//! Certificate Policy (CP) and Certification Practice Statement (CPS).
//!
//! ETSI TS 102 042 / RFC 3647 — defines the policy framework for
//! certificate issuance, management, and revocation.
//!
//! This module provides:
//! - OID namespace under Goya's Private Enterprise Number
//! - Structured policy metadata servable via API
//! - Policy references for embedding in X.509 certificate extensions

use serde::{Deserialize, Serialize};

// ── OID namespace (1.3.6.1.4.1.99999 = Goya PEN placeholder) ───────────────

/// Root OID arc for Goya certificate policies.
pub const GOYA_OID_ROOT: &str = "1.3.6.1.4.1.99999";

/// Certificate Policy OID — referenced in X.509 certificatePolicies extension.
pub const CP_OID: &str = "1.3.6.1.4.1.99999.2.1";

/// Certification Practice Statement OID.
pub const CPS_OID: &str = "1.3.6.1.4.1.99999.2.2";

/// TSA Policy OID (mirrors tsa::TSA_POLICY_OID for consistency).
pub const TSA_POLICY_OID: &str = "1.3.6.1.4.1.99999.1.1";

/// Signature Policy OID for XAdES signed envelopes.
pub const SIGNATURE_POLICY_OID: &str = "1.3.6.1.4.1.99999.3.1";

/// Current CP/CPS document version.
pub const CP_CPS_VERSION: &str = "1.0.0";

/// Assurance levels for issued certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    /// Self-asserted identity, no RA verification.
    Low,
    /// RA-verified identity via remote automated check.
    Medium,
    /// RA-verified identity via video conference or in-person.
    High,
}

impl std::fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

/// Certificate Policy metadata — RFC 3647 structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificatePolicy {
    pub oid: String,
    pub version: String,
    pub name: String,
    pub status: PolicyStatus,
    pub publication_url: String,
    pub legal_framework: LegalFramework,
    pub subscriber_obligations: Vec<String>,
    pub ca_obligations: Vec<String>,
    pub ra_obligations: Vec<String>,
    pub supported_algorithms: Vec<String>,
    pub assurance_levels: Vec<AssuranceLevel>,
    pub certificate_lifetime_days: u32,
    pub revocation_mechanisms: Vec<String>,
    pub private_key_protection: String,
    pub audit_requirements: String,
}

/// CPS metadata — operational practices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationPracticeStatement {
    pub oid: String,
    pub version: String,
    pub name: String,
    pub status: PolicyStatus,
    pub publication_url: String,
    pub ca_name: String,
    pub ca_jurisdiction: String,
    pub identity_proofing: IdentityProofingPolicy,
    pub key_management: KeyManagementPolicy,
    pub certificate_profiles: Vec<CertificateProfile>,
    pub audit_logging: AuditPolicy,
    pub disaster_recovery: String,
    pub compliance_references: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Draft,
    Active,
    Superseded,
    Retired,
}

impl std::fmt::Display for PolicyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => write!(f, "draft"),
            Self::Active => write!(f, "active"),
            Self::Superseded => write!(f, "superseded"),
            Self::Retired => write!(f, "retired"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalFramework {
    pub primary_law: String,
    pub regulation: String,
    pub technical_standard: String,
    pub jurisdiction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProofingPolicy {
    pub methods: Vec<String>,
    pub rut_validation_required: bool,
    pub document_retention_years: u32,
    pub re_verification_interval_months: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManagementPolicy {
    pub algorithms: Vec<String>,
    pub min_key_sizes: Vec<String>,
    pub key_generation: String,
    pub private_key_storage: String,
    pub key_ceremony_required: bool,
    pub key_backup: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateProfile {
    pub name: String,
    pub assurance_level: AssuranceLevel,
    pub lifetime_days: u32,
    pub key_usage: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicy {
    pub log_retention_years: u32,
    pub tamper_evidence: String,
    pub review_frequency: String,
}

/// Build the default Goya Certificate Policy.
pub fn default_cp() -> CertificatePolicy {
    CertificatePolicy {
        oid: CP_OID.to_string(),
        version: CP_CPS_VERSION.to_string(),
        name: "Goya Ledger Certificate Policy".to_string(),
        status: PolicyStatus::Draft,
        publication_url: "https://goya.cl/pki/cp".to_string(),
        legal_framework: LegalFramework {
            primary_law: "Ley 19.799 — Firma Electrónica (Chile)".to_string(),
            regulation: "DS 181/2002 — Reglamento Ley 19.799".to_string(),
            technical_standard: "ETSI TS 102 042 — Policy requirements for CAs".to_string(),
            jurisdiction: "Chile".to_string(),
        },
        subscriber_obligations: vec![
            "Protect private key from unauthorized access".to_string(),
            "Report key compromise within 24 hours".to_string(),
            "Provide accurate identity information to the RA".to_string(),
            "Use certificate only for authorized purposes".to_string(),
        ],
        ca_obligations: vec![
            "Issue certificates only after RA verification".to_string(),
            "Publish CRL within 1 hour of revocation".to_string(),
            "Maintain audit logs for 7 years".to_string(),
            "Undergo annual inspection per Entidad Acreditadora guide".to_string(),
        ],
        ra_obligations: vec![
            "Verify subscriber identity per Ley 19.799 Art. 15".to_string(),
            "Validate Chilean RUT via modulo 11 algorithm".to_string(),
            "Retain identity proofing records for 7 years".to_string(),
            "Report suspicious identity claims within 24 hours".to_string(),
        ],
        supported_algorithms: vec![
            "Ed25519 (FIPS 186-5)".to_string(),
            "ML-DSA-65 (FIPS 204)".to_string(),
        ],
        assurance_levels: vec![
            AssuranceLevel::Low,
            AssuranceLevel::Medium,
            AssuranceLevel::High,
        ],
        certificate_lifetime_days: 365,
        revocation_mechanisms: vec![
            "CRL (internal store, RFC 5280 format planned)".to_string(),
            "OCSP stapling (responder planned)".to_string(),
        ],
        private_key_protection: "ZeroizeOnDrop + mlock; HSM via PKCS#11 (planned)".to_string(),
        audit_requirements: "Append-only audit log, 7-year retention, annual review".to_string(),
    }
}

/// Build the default Goya Certification Practice Statement.
pub fn default_cps() -> CertificationPracticeStatement {
    CertificationPracticeStatement {
        oid: CPS_OID.to_string(),
        version: CP_CPS_VERSION.to_string(),
        name: "Goya Ledger Certification Practice Statement".to_string(),
        status: PolicyStatus::Draft,
        publication_url: "https://goya.cl/pki/cps".to_string(),
        ca_name: "Goya Ledger CA".to_string(),
        ca_jurisdiction: "Chile".to_string(),
        identity_proofing: IdentityProofingPolicy {
            methods: vec![
                "In-person with government-issued ID".to_string(),
                "Video conference with document presentation".to_string(),
                "Remote automated via trusted service".to_string(),
            ],
            rut_validation_required: true,
            document_retention_years: 7,
            re_verification_interval_months: 36,
        },
        key_management: KeyManagementPolicy {
            algorithms: vec!["Ed25519".to_string(), "ML-DSA-65".to_string()],
            min_key_sizes: vec![
                "Ed25519: 256-bit".to_string(),
                "ML-DSA-65: NIST security level 3".to_string(),
            ],
            key_generation: "OS-backed CSPRNG (OsRng) with continuous health test".to_string(),
            private_key_storage: "In-memory with ZeroizeOnDrop; never persisted to disk"
                .to_string(),
            key_ceremony_required: true,
            key_backup: "HSM-based backup required for CA keys (planned)".to_string(),
        },
        certificate_profiles: vec![
            CertificateProfile {
                name: "FES Subscriber".to_string(),
                assurance_level: AssuranceLevel::Low,
                lifetime_days: 365,
                key_usage: vec!["digitalSignature".to_string()],
            },
            CertificateProfile {
                name: "FEA Subscriber".to_string(),
                assurance_level: AssuranceLevel::High,
                lifetime_days: 365,
                key_usage: vec!["digitalSignature".to_string(), "nonRepudiation".to_string()],
            },
            CertificateProfile {
                name: "TSA Signing".to_string(),
                assurance_level: AssuranceLevel::High,
                lifetime_days: 730,
                key_usage: vec!["digitalSignature".to_string(), "timeStamping".to_string()],
            },
        ],
        audit_logging: AuditPolicy {
            log_retention_years: 7,
            tamper_evidence: "Append-only store; hash chain tamper evidence (planned)".to_string(),
            review_frequency: "Annual per Entidad Acreditadora inspection guide".to_string(),
        },
        disaster_recovery:
            "Checkpoint/snapshot mechanism with Raft persistent log; formal BC/DR plan (planned)"
                .to_string(),
        compliance_references: vec![
            "Ley 19.799 (Chile)".to_string(),
            "DS 181/2002 (Chile)".to_string(),
            "Decreto 24/2019 — Norma Técnica FEA (Chile)".to_string(),
            "ETSI TS 102 042 — CA Policy Requirements".to_string(),
            "ETSI TS 101 903 — XAdES".to_string(),
            "RFC 3647 — Certificate Policy and CPS Framework".to_string(),
            "RFC 3161 — Time-Stamp Protocol".to_string(),
            "FIPS 140-3 Level 1 (module prepared, not validated)".to_string(),
            "FIPS 186-5 — Digital Signatures (Ed25519)".to_string(),
            "FIPS 204 — ML-DSA (post-quantum)".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cp_oid_under_goya_root() {
        assert!(CP_OID.starts_with(GOYA_OID_ROOT));
    }

    #[test]
    fn cps_oid_under_goya_root() {
        assert!(CPS_OID.starts_with(GOYA_OID_ROOT));
    }

    #[test]
    fn tsa_oid_under_goya_root() {
        assert!(TSA_POLICY_OID.starts_with(GOYA_OID_ROOT));
    }

    #[test]
    fn all_oids_distinct() {
        let oids = [CP_OID, CPS_OID, TSA_POLICY_OID, SIGNATURE_POLICY_OID];
        for i in 0..oids.len() {
            for j in (i + 1)..oids.len() {
                assert_ne!(
                    oids[i], oids[j],
                    "OID collision: {} == {}",
                    oids[i], oids[j]
                );
            }
        }
    }

    #[test]
    fn default_cp_has_required_fields() {
        let cp = default_cp();
        assert_eq!(cp.oid, CP_OID);
        assert_eq!(cp.status, PolicyStatus::Draft);
        assert!(!cp.subscriber_obligations.is_empty());
        assert!(!cp.ca_obligations.is_empty());
        assert!(!cp.ra_obligations.is_empty());
        assert!(!cp.supported_algorithms.is_empty());
        assert!(cp.certificate_lifetime_days > 0);
    }

    #[test]
    fn default_cps_has_required_fields() {
        let cps = default_cps();
        assert_eq!(cps.oid, CPS_OID);
        assert_eq!(cps.status, PolicyStatus::Draft);
        assert!(cps.identity_proofing.rut_validation_required);
        assert!(!cps.key_management.algorithms.is_empty());
        assert!(!cps.certificate_profiles.is_empty());
        assert!(!cps.compliance_references.is_empty());
    }

    #[test]
    fn cp_references_ley_19799() {
        let cp = default_cp();
        assert!(cp.legal_framework.primary_law.contains("19.799"));
    }

    #[test]
    fn cps_references_ds_181() {
        let cps = default_cps();
        assert!(cps
            .compliance_references
            .iter()
            .any(|r| r.contains("DS 181")));
    }

    #[test]
    fn cps_has_fea_profile() {
        let cps = default_cps();
        let fea = cps
            .certificate_profiles
            .iter()
            .find(|p| p.name.contains("FEA"));
        assert!(fea.is_some());
        let fea = fea.unwrap();
        assert_eq!(fea.assurance_level, AssuranceLevel::High);
        assert!(fea.key_usage.contains(&"nonRepudiation".to_string()));
    }

    #[test]
    fn cps_retention_7_years() {
        let cps = default_cps();
        assert_eq!(cps.identity_proofing.document_retention_years, 7);
        assert_eq!(cps.audit_logging.log_retention_years, 7);
    }

    #[test]
    fn assurance_level_display() {
        assert_eq!(format!("{}", AssuranceLevel::Low), "low");
        assert_eq!(format!("{}", AssuranceLevel::High), "high");
    }

    #[test]
    fn policy_status_display() {
        assert_eq!(format!("{}", PolicyStatus::Draft), "draft");
        assert_eq!(format!("{}", PolicyStatus::Active), "active");
    }

    #[test]
    fn cp_serialization_roundtrip() {
        let cp = default_cp();
        let json = serde_json::to_string(&cp).unwrap();
        let parsed: CertificatePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.oid, cp.oid);
        assert_eq!(parsed.version, cp.version);
    }

    #[test]
    fn cps_serialization_roundtrip() {
        let cps = default_cps();
        let json = serde_json::to_string(&cps).unwrap();
        let parsed: CertificationPracticeStatement = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.oid, cps.oid);
        assert_eq!(
            parsed.certificate_profiles.len(),
            cps.certificate_profiles.len()
        );
    }
}
