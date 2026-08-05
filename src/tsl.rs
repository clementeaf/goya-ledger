//! Trust Service List (TSL) — ETSI TS 119 612.
//!
//! Publishes the list of trust services offered by this node:
//! which services are active, their policies, algorithms, and status.

use crate::pki_policy;
use serde::{Deserialize, Serialize};

/// Status of a trust service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Active,
    Suspended,
    Revoked,
    Planned,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Suspended => write!(f, "suspended"),
            Self::Revoked => write!(f, "revoked"),
            Self::Planned => write!(f, "planned"),
        }
    }
}

/// Type of trust service per ETSI classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceType {
    /// Certificate Authority — issues subscriber certificates.
    CertificateAuthority,
    /// Time Stamping Authority — RFC 3161 timestamps.
    TimeStampAuthority,
    /// OCSP Responder — certificate status.
    OcspResponder,
    /// Registration Authority — identity proofing.
    RegistrationAuthority,
    /// Electronic Signature — FES/FEA signing.
    ElectronicSignature,
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertificateAuthority => write!(f, "certificate_authority"),
            Self::TimeStampAuthority => write!(f, "time_stamp_authority"),
            Self::OcspResponder => write!(f, "ocsp_responder"),
            Self::RegistrationAuthority => write!(f, "registration_authority"),
            Self::ElectronicSignature => write!(f, "electronic_signature"),
        }
    }
}

/// A single trust service entry in the TSL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustService {
    pub service_type: ServiceType,
    pub name: String,
    pub status: ServiceStatus,
    pub policy_oid: String,
    pub algorithms: Vec<String>,
    pub formats: Vec<String>,
    pub endpoint: Option<String>,
}

/// The complete Trust Service List for this node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustServiceList {
    /// TSL version.
    pub version: u32,
    /// Operator name.
    pub operator: String,
    /// Operator jurisdiction.
    pub jurisdiction: String,
    /// When this TSL was generated (UNIX seconds).
    pub issued_at: u64,
    /// Next scheduled update (UNIX seconds).
    pub next_update: u64,
    /// All trust services.
    pub services: Vec<TrustService>,
}

/// Build the default Goya TSL from the current node configuration.
pub fn build_tsl(operator: &str, jurisdiction: &str, now_secs: u64) -> TrustServiceList {
    let update_interval = 30 * 24 * 3600; // 30 days

    TrustServiceList {
        version: 1,
        operator: operator.to_string(),
        jurisdiction: jurisdiction.to_string(),
        issued_at: now_secs,
        next_update: now_secs + update_interval,
        services: vec![
            TrustService {
                service_type: ServiceType::CertificateAuthority,
                name: "Goya Ledger CA".into(),
                status: ServiceStatus::Active,
                policy_oid: pki_policy::CP_OID.to_string(),
                algorithms: vec!["Ed25519".into(), "ML-DSA-65".into(), "ECDSA-P256".into()],
                formats: vec!["X.509v3".into()],
                endpoint: Some("/api/v1/policy/cp".into()),
            },
            TrustService {
                service_type: ServiceType::TimeStampAuthority,
                name: "Goya Ledger TSA".into(),
                status: ServiceStatus::Active,
                policy_oid: pki_policy::TSA_POLICY_OID.to_string(),
                algorithms: vec!["Ed25519".into(), "ML-DSA-65".into()],
                formats: vec!["RFC 3161".into()],
                endpoint: Some("/api/v1/tsa/timestamp".into()),
            },
            TrustService {
                service_type: ServiceType::OcspResponder,
                name: "Goya Ledger OCSP".into(),
                status: ServiceStatus::Active,
                policy_oid: pki_policy::CP_OID.to_string(),
                algorithms: vec!["Ed25519".into(), "ML-DSA-65".into()],
                formats: vec!["RFC 6960".into()],
                endpoint: Some("/api/v1/ocsp/query".into()),
            },
            TrustService {
                service_type: ServiceType::RegistrationAuthority,
                name: "Goya Ledger RA".into(),
                status: ServiceStatus::Active,
                policy_oid: pki_policy::CPS_OID.to_string(),
                algorithms: vec![],
                formats: vec!["Ley 19.799 Art. 15".into()],
                endpoint: Some("/api/v1/identity/proof".into()),
            },
            TrustService {
                service_type: ServiceType::ElectronicSignature,
                name: "Goya Ledger Signatures".into(),
                status: ServiceStatus::Active,
                policy_oid: pki_policy::SIGNATURE_POLICY_OID.to_string(),
                algorithms: vec!["Ed25519".into(), "ML-DSA-65".into()],
                formats: vec!["XAdES-BES".into(), "CAdES-BES".into(), "PAdES-BES".into()],
                endpoint: Some("/api/v1/notarize".into()),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tsl() -> TrustServiceList {
        build_tsl("Goya Ledger", "Chile", 1_700_000_000)
    }

    #[test]
    fn tsl_has_5_services() {
        let tsl = sample_tsl();
        assert_eq!(tsl.services.len(), 5);
    }

    #[test]
    fn tsl_has_ca_service() {
        let tsl = sample_tsl();
        let ca = tsl
            .services
            .iter()
            .find(|s| s.service_type == ServiceType::CertificateAuthority);
        assert!(ca.is_some());
        assert_eq!(ca.unwrap().status, ServiceStatus::Active);
    }

    #[test]
    fn tsl_has_tsa_service() {
        let tsl = sample_tsl();
        let tsa = tsl
            .services
            .iter()
            .find(|s| s.service_type == ServiceType::TimeStampAuthority);
        assert!(tsa.is_some());
        assert_eq!(tsa.unwrap().policy_oid, pki_policy::TSA_POLICY_OID);
    }

    #[test]
    fn tsl_has_ocsp_service() {
        let tsl = sample_tsl();
        let ocsp = tsl
            .services
            .iter()
            .find(|s| s.service_type == ServiceType::OcspResponder);
        assert!(ocsp.is_some());
    }

    #[test]
    fn tsl_has_ra_service() {
        let tsl = sample_tsl();
        let ra = tsl
            .services
            .iter()
            .find(|s| s.service_type == ServiceType::RegistrationAuthority);
        assert!(ra.is_some());
    }

    #[test]
    fn tsl_has_signature_service() {
        let tsl = sample_tsl();
        let sig = tsl
            .services
            .iter()
            .find(|s| s.service_type == ServiceType::ElectronicSignature);
        assert!(sig.is_some());
        let formats = &sig.unwrap().formats;
        assert!(formats.contains(&"XAdES-BES".to_string()));
        assert!(formats.contains(&"CAdES-BES".to_string()));
        assert!(formats.contains(&"PAdES-BES".to_string()));
    }

    #[test]
    fn tsl_next_update_is_30_days() {
        let tsl = sample_tsl();
        assert_eq!(tsl.next_update - tsl.issued_at, 30 * 24 * 3600);
    }

    #[test]
    fn tsl_version_is_1() {
        let tsl = sample_tsl();
        assert_eq!(tsl.version, 1);
    }

    #[test]
    fn tsl_operator_and_jurisdiction() {
        let tsl = sample_tsl();
        assert_eq!(tsl.operator, "Goya Ledger");
        assert_eq!(tsl.jurisdiction, "Chile");
    }

    #[test]
    fn all_services_have_endpoints() {
        let tsl = sample_tsl();
        for svc in &tsl.services {
            assert!(
                svc.endpoint.is_some(),
                "service {} has no endpoint",
                svc.name
            );
        }
    }

    #[test]
    fn service_status_display() {
        assert_eq!(ServiceStatus::Active.to_string(), "active");
        assert_eq!(ServiceStatus::Suspended.to_string(), "suspended");
        assert_eq!(ServiceStatus::Planned.to_string(), "planned");
    }

    #[test]
    fn service_type_display() {
        assert_eq!(
            ServiceType::CertificateAuthority.to_string(),
            "certificate_authority"
        );
        assert_eq!(
            ServiceType::TimeStampAuthority.to_string(),
            "time_stamp_authority"
        );
    }

    #[test]
    fn serialization_roundtrip() {
        let tsl = sample_tsl();
        let json = serde_json::to_string(&tsl).unwrap();
        let parsed: TrustServiceList = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.services.len(), 5);
        assert_eq!(parsed.operator, "Goya Ledger");
    }

    #[test]
    fn all_policy_oids_are_under_goya_root() {
        let tsl = sample_tsl();
        for svc in &tsl.services {
            assert!(
                svc.policy_oid.starts_with(pki_policy::GOYA_OID_ROOT),
                "service {} has OID {} not under Goya root",
                svc.name,
                svc.policy_oid,
            );
        }
    }
}
