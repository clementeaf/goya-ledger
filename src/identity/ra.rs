//! Registration Authority (RA) — identity proofing for Ley 19.799 Art. 15.
//!
//! A PSC must verify subscriber identity before issuing certificates.
//! This module manages the proofing lifecycle: request → verify → approve/reject.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Identity proofing status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofingStatus {
    Pending,
    Verified,
    Rejected,
}

impl std::fmt::Display for ProofingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Verified => write!(f, "verified"),
            Self::Rejected => write!(f, "rejected"),
        }
    }
}

/// Method used to verify identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofingMethod {
    /// In-person verification with physical document.
    InPerson,
    /// Video conference with document presentation.
    VideoConference,
    /// Automated remote verification via trusted service.
    RemoteAutomated,
}

impl std::fmt::Display for ProofingMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InPerson => write!(f, "in_person"),
            Self::VideoConference => write!(f, "video_conference"),
            Self::RemoteAutomated => write!(f, "remote_automated"),
        }
    }
}

/// Identity proofing request submitted by a subscriber.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProofing {
    /// DID of the subscriber requesting proofing.
    pub did: String,
    /// Chilean RUT (Rol Unico Tributario), e.g. "12.345.678-5".
    pub rut: String,
    /// Legal name as it appears on official documents.
    pub legal_name: String,
    /// Verification method used or requested.
    pub method: ProofingMethod,
    /// Current status.
    pub status: ProofingStatus,
    /// Unix timestamp when the request was submitted.
    pub requested_at: u64,
    /// Unix timestamp when verified/rejected (None if pending).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<u64>,
    /// DID of the RA officer who verified/rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<String>,
    /// Rejection reason (None if not rejected).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

/// Validate a Chilean RUT format and check digit (modulo 11).
///
/// Accepts formats: "12345678-5", "12.345.678-5", "123456785".
/// Returns the normalized RUT (no dots, with hyphen) or an error.
pub fn validate_rut(rut: &str) -> Result<String, String> {
    let cleaned: String = rut.chars().filter(|c| *c != '.' && *c != ' ').collect();

    let (body_str, check_char) = if let Some(pos) = cleaned.find('-') {
        let body = &cleaned[..pos];
        let check = &cleaned[pos + 1..];
        if check.len() != 1 {
            return Err("RUT check digit must be a single character".into());
        }
        (body.to_string(), check.to_uppercase())
    } else if cleaned.len() >= 2 {
        let body = &cleaned[..cleaned.len() - 1];
        let check = &cleaned[cleaned.len() - 1..];
        (body.to_string(), check.to_uppercase())
    } else {
        return Err("RUT too short".into());
    };

    let body: u64 = body_str
        .parse()
        .map_err(|_| "RUT body must be numeric".to_string())?;

    if body == 0 {
        return Err("RUT body cannot be zero".into());
    }

    let expected = compute_rut_check_digit(body);
    if check_char != expected {
        return Err(format!(
            "RUT check digit mismatch: expected {expected}, got {check_char}"
        ));
    }

    Ok(format!("{body}-{expected}"))
}

/// Compute the check digit for a Chilean RUT using modulo 11.
fn compute_rut_check_digit(mut body: u64) -> String {
    let multipliers = [2, 3, 4, 5, 6, 7];
    let mut sum = 0u64;
    let mut idx = 0;

    while body > 0 {
        sum += (body % 10) * multipliers[idx % 6];
        body /= 10;
        idx += 1;
    }

    let remainder = 11 - (sum % 11);
    match remainder {
        11 => "0".to_string(),
        10 => "K".to_string(),
        d => d.to_string(),
    }
}

/// In-memory Registration Authority store.
pub struct RaStore {
    records: RwLock<HashMap<String, IdentityProofing>>,
}

impl RaStore {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }

    /// Submit a new identity proofing request.
    pub fn submit(
        &self,
        did: String,
        rut: String,
        legal_name: String,
        method: ProofingMethod,
        requested_at: u64,
    ) -> Result<IdentityProofing, String> {
        let normalized_rut = validate_rut(&rut)?;

        let proofing = IdentityProofing {
            did: did.clone(),
            rut: normalized_rut,
            legal_name,
            method,
            status: ProofingStatus::Pending,
            requested_at,
            resolved_at: None,
            resolved_by: None,
            rejection_reason: None,
        };

        let mut records = self.records.write().map_err(|e| e.to_string())?;
        if records.contains_key(&did) {
            return Err("proofing request already exists for this DID".into());
        }
        records.insert(did, proofing.clone());
        Ok(proofing)
    }

    /// Approve a pending proofing request.
    pub fn approve(
        &self,
        did: &str,
        officer_did: &str,
        resolved_at: u64,
    ) -> Result<IdentityProofing, String> {
        let mut records = self.records.write().map_err(|e| e.to_string())?;
        let record = records
            .get_mut(did)
            .ok_or_else(|| "no proofing request found for this DID".to_string())?;

        if record.status != ProofingStatus::Pending {
            return Err(format!("cannot approve: status is {}", record.status));
        }

        record.status = ProofingStatus::Verified;
        record.resolved_at = Some(resolved_at);
        record.resolved_by = Some(officer_did.to_string());
        Ok(record.clone())
    }

    /// Approve and issue a certificate signed by the CA.
    pub fn approve_and_issue_cert(
        &self,
        did: &str,
        officer_did: &str,
        resolved_at: u64,
        ca: &crate::pki::NodeCaConfig,
        cert_ttl_days: u32,
    ) -> Result<(IdentityProofing, crate::pki::IssuedNodeCert), String> {
        let proofing = self.approve(did, officer_did, resolved_at)?;
        let cert = crate::pki::sign_node_cert(did, ca, cert_ttl_days)
            .map_err(|e| format!("certificate issuance failed: {e}"))?;
        Ok((proofing, cert))
    }

    /// Reject a pending proofing request.
    pub fn reject(
        &self,
        did: &str,
        officer_did: &str,
        reason: &str,
        resolved_at: u64,
    ) -> Result<IdentityProofing, String> {
        let mut records = self.records.write().map_err(|e| e.to_string())?;
        let record = records
            .get_mut(did)
            .ok_or_else(|| "no proofing request found for this DID".to_string())?;

        if record.status != ProofingStatus::Pending {
            return Err(format!("cannot reject: status is {}", record.status));
        }

        record.status = ProofingStatus::Rejected;
        record.resolved_at = Some(resolved_at);
        record.resolved_by = Some(officer_did.to_string());
        record.rejection_reason = Some(reason.to_string());
        Ok(record.clone())
    }

    /// Get a proofing record by DID.
    pub fn get(&self, did: &str) -> Option<IdentityProofing> {
        self.records.read().ok()?.get(did).cloned()
    }

    /// Check if a DID has been verified.
    pub fn is_verified(&self, did: &str) -> bool {
        self.get(did)
            .is_some_and(|r| r.status == ProofingStatus::Verified)
    }
}

impl Default for RaStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RUT validation ──────────────────────────────────────────────

    #[test]
    fn valid_rut_with_hyphen() {
        assert_eq!(validate_rut("12345678-5").unwrap(), "12345678-5");
    }

    #[test]
    fn valid_rut_with_dots_and_hyphen() {
        assert_eq!(validate_rut("12.345.678-5").unwrap(), "12345678-5");
    }

    #[test]
    fn valid_rut_without_separator() {
        assert_eq!(validate_rut("123456785").unwrap(), "12345678-5");
    }

    #[test]
    fn valid_rut_with_k() {
        assert_eq!(validate_rut("10000013-K").unwrap(), "10000013-K");
    }

    #[test]
    fn valid_rut_lowercase_k() {
        assert_eq!(validate_rut("10000013-k").unwrap(), "10000013-K");
    }

    #[test]
    fn invalid_rut_wrong_check_digit() {
        let err = validate_rut("12345678-0").unwrap_err();
        assert!(err.contains("mismatch"));
    }

    #[test]
    fn invalid_rut_too_short() {
        assert!(validate_rut("1").is_err());
    }

    #[test]
    fn invalid_rut_non_numeric_body() {
        assert!(validate_rut("abcdefgh-1").is_err());
    }

    #[test]
    fn invalid_rut_zero_body() {
        assert!(validate_rut("0-0").is_err());
    }

    #[test]
    fn rut_check_digit_known_values() {
        assert_eq!(compute_rut_check_digit(12345678), "5");
        assert_eq!(compute_rut_check_digit(10000013), "K");
        assert_eq!(compute_rut_check_digit(11111111), "1");
    }

    // ── RaStore lifecycle ───────────────────────────────────────────

    #[test]
    fn submit_and_get() {
        let store = RaStore::new();
        let result = store
            .submit(
                "did:goya:test".into(),
                "12345678-5".into(),
                "Juan Pérez".into(),
                ProofingMethod::InPerson,
                1700000000,
            )
            .unwrap();
        assert_eq!(result.status, ProofingStatus::Pending);
        assert_eq!(result.rut, "12345678-5");

        let fetched = store.get("did:goya:test").unwrap();
        assert_eq!(fetched.legal_name, "Juan Pérez");
    }

    #[test]
    fn submit_validates_rut() {
        let store = RaStore::new();
        let err = store
            .submit(
                "did:goya:test".into(),
                "12345678-0".into(),
                "Name".into(),
                ProofingMethod::InPerson,
                1700000000,
            )
            .unwrap_err();
        assert!(err.contains("mismatch"));
    }

    #[test]
    fn submit_rejects_duplicate() {
        let store = RaStore::new();
        store
            .submit(
                "did:goya:test".into(),
                "12345678-5".into(),
                "Name".into(),
                ProofingMethod::InPerson,
                1700000000,
            )
            .unwrap();
        let err = store
            .submit(
                "did:goya:test".into(),
                "12345678-5".into(),
                "Name".into(),
                ProofingMethod::InPerson,
                1700000001,
            )
            .unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn approve_flow() {
        let store = RaStore::new();
        store
            .submit(
                "did:goya:sub".into(),
                "12345678-5".into(),
                "Name".into(),
                ProofingMethod::VideoConference,
                1700000000,
            )
            .unwrap();

        let result = store
            .approve("did:goya:sub", "did:goya:officer", 1700001000)
            .unwrap();
        assert_eq!(result.status, ProofingStatus::Verified);
        assert_eq!(result.resolved_by.as_deref(), Some("did:goya:officer"));
        assert_eq!(result.resolved_at, Some(1700001000));
        assert!(store.is_verified("did:goya:sub"));
    }

    #[test]
    fn reject_flow() {
        let store = RaStore::new();
        store
            .submit(
                "did:goya:sub".into(),
                "12345678-5".into(),
                "Name".into(),
                ProofingMethod::InPerson,
                1700000000,
            )
            .unwrap();

        let result = store
            .reject(
                "did:goya:sub",
                "did:goya:officer",
                "document expired",
                1700001000,
            )
            .unwrap();
        assert_eq!(result.status, ProofingStatus::Rejected);
        assert_eq!(result.rejection_reason.as_deref(), Some("document expired"));
        assert!(!store.is_verified("did:goya:sub"));
    }

    #[test]
    fn cannot_approve_non_pending() {
        let store = RaStore::new();
        store
            .submit(
                "did:goya:sub".into(),
                "12345678-5".into(),
                "Name".into(),
                ProofingMethod::InPerson,
                1700000000,
            )
            .unwrap();
        store
            .approve("did:goya:sub", "did:goya:officer", 1700001000)
            .unwrap();

        let err = store
            .approve("did:goya:sub", "did:goya:officer2", 1700002000)
            .unwrap_err();
        assert!(err.contains("cannot approve"));
    }

    #[test]
    fn cannot_reject_non_pending() {
        let store = RaStore::new();
        store
            .submit(
                "did:goya:sub".into(),
                "12345678-5".into(),
                "Name".into(),
                ProofingMethod::InPerson,
                1700000000,
            )
            .unwrap();
        store
            .reject("did:goya:sub", "did:goya:officer", "reason", 1700001000)
            .unwrap();

        let err = store
            .reject("did:goya:sub", "did:goya:officer2", "other", 1700002000)
            .unwrap_err();
        assert!(err.contains("cannot reject"));
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let store = RaStore::new();
        assert!(store.get("did:goya:nobody").is_none());
    }

    #[test]
    fn is_verified_false_for_pending() {
        let store = RaStore::new();
        store
            .submit(
                "did:goya:sub".into(),
                "12345678-5".into(),
                "Name".into(),
                ProofingMethod::InPerson,
                1700000000,
            )
            .unwrap();
        assert!(!store.is_verified("did:goya:sub"));
    }

    #[test]
    fn is_verified_false_for_unknown() {
        let store = RaStore::new();
        assert!(!store.is_verified("did:goya:unknown"));
    }

    #[test]
    fn proofing_method_variants() {
        let store = RaStore::new();
        for (i, method) in [
            ProofingMethod::InPerson,
            ProofingMethod::VideoConference,
            ProofingMethod::RemoteAutomated,
        ]
        .iter()
        .enumerate()
        {
            let did = format!("did:goya:sub{i}");
            let rut = match i {
                0 => "12345678-5",
                1 => "11111111-1",
                _ => "10000013-K",
            };
            let result = store
                .submit(did, rut.into(), "Name".into(), *method, 1700000000)
                .unwrap();
            assert_eq!(result.method, *method);
        }
    }

    #[test]
    fn serialization_roundtrip() {
        let proofing = IdentityProofing {
            did: "did:goya:test".into(),
            rut: "12345678-5".into(),
            legal_name: "Test".into(),
            method: ProofingMethod::InPerson,
            status: ProofingStatus::Verified,
            requested_at: 1700000000,
            resolved_at: Some(1700001000),
            resolved_by: Some("did:goya:officer".into()),
            rejection_reason: None,
        };
        let json = serde_json::to_string(&proofing).unwrap();
        let parsed: IdentityProofing = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rut, "12345678-5");
        assert_eq!(parsed.status, ProofingStatus::Verified);
    }

    #[test]
    fn approve_and_issue_cert_produces_pem() {
        let store = RaStore::new();
        let did = "did:goya:certtest".to_string();
        store
            .submit(
                did.clone(),
                "11111111-1".into(),
                "Test User".into(),
                ProofingMethod::InPerson,
                1_700_000_000,
            )
            .unwrap();

        let (ca, _, _) = crate::pki::NodeCaConfig::generate().unwrap();
        let (proofing, cert) = store
            .approve_and_issue_cert(&did, "did:goya:officer", 1_700_001_000, &ca, 365)
            .unwrap();
        assert_eq!(proofing.status, ProofingStatus::Verified);
        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.contains("BEGIN"));
    }

    #[test]
    fn approve_and_issue_cert_fails_without_proofing() {
        let store = RaStore::new();
        let (ca, _, _) = crate::pki::NodeCaConfig::generate().unwrap();
        let result =
            store.approve_and_issue_cert("did:goya:none", "did:goya:off", 1_700_000_000, &ca, 365);
        assert!(result.is_err());
    }
}
