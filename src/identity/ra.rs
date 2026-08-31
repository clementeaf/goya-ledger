//! Registration Authority (RA) — identity proofing.
//!
//! Supports multiple jurisdictions:
//! - Chile: Ley 19.799 Art. 15 (RUT validation)
//! - UAE: Federal Decree-Law 46/2021 (Emirates ID validation)
//! - EU: eIDAS Art. 24 (national ID)
//!
//! A TSP must verify subscriber identity before issuing certificates.
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
    /// UAE Pass digital identity verification.
    UaePass,
}

impl std::fmt::Display for ProofingMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InPerson => write!(f, "in_person"),
            Self::VideoConference => write!(f, "video_conference"),
            Self::RemoteAutomated => write!(f, "remote_automated"),
            Self::UaePass => write!(f, "uae_pass"),
        }
    }
}

/// Jurisdiction for identity proofing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Jurisdiction {
    /// Chile — Ley 19.799, RUT as national ID.
    #[default]
    Chile,
    /// UAE — Federal Decree-Law 46/2021, Emirates ID as national ID.
    Uae,
    /// EU — eIDAS 910/2014, national ID per member state.
    Eu,
}

impl std::fmt::Display for Jurisdiction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Chile => write!(f, "chile"),
            Self::Uae => write!(f, "uae"),
            Self::Eu => write!(f, "eu"),
        }
    }
}

/// eIDAS Level of Assurance (Regulation 2015/1502).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EidasLoA {
    /// Low — self-asserted identity.
    #[default]
    Low,
    /// Substantial — verified identity with moderate assurance.
    Substantial,
    /// High — verified identity with high assurance (in-person or equivalent).
    High,
}

impl std::fmt::Display for EidasLoA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Substantial => write!(f, "substantial"),
            Self::High => write!(f, "high"),
        }
    }
}

/// Derive eIDAS LoA from proofing method.
pub fn loa_from_method(method: ProofingMethod) -> EidasLoA {
    match method {
        ProofingMethod::InPerson => EidasLoA::High,
        ProofingMethod::VideoConference => EidasLoA::Substantial,
        ProofingMethod::UaePass => EidasLoA::Substantial,
        ProofingMethod::RemoteAutomated => EidasLoA::Low,
    }
}

/// Identity proofing request submitted by a subscriber.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProofing {
    /// DID of the subscriber requesting proofing.
    pub did: String,
    /// Chilean RUT (Rol Unico Tributario), e.g. "12.345.678-5".
    /// For UAE/EU, use `national_id` instead.
    pub rut: String,
    /// National ID for non-Chilean jurisdictions (Emirates ID, EU national ID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub national_id: Option<String>,
    /// Jurisdiction for this proofing request.
    #[serde(default)]
    pub jurisdiction: Jurisdiction,
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
    /// eIDAS Level of Assurance, derived from proofing method.
    #[serde(default)]
    pub loa: EidasLoA,
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

/// Validate a UAE Emirates ID number.
///
/// Format: 784-YYYY-NNNNNNN-C (15 digits total).
/// - 784 = UAE country code (ISO 3166)
/// - YYYY = birth year
/// - NNNNNNN = sequence number
/// - C = check digit (Luhn algorithm)
///
/// Accepts formats: "784-1990-1234567-6", "784199012345671", "784 1990 1234567 1".
/// Returns the normalized form (with hyphens) or an error.
pub fn validate_emirates_id(id: &str) -> Result<String, String> {
    let digits: String = id.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() != 15 {
        return Err(format!(
            "Emirates ID must be 15 digits, got {}",
            digits.len()
        ));
    }

    if !digits.starts_with("784") {
        return Err("Emirates ID must start with 784 (UAE country code)".into());
    }

    let year: u16 = digits[3..7]
        .parse()
        .map_err(|_| "Invalid birth year in Emirates ID")?;
    if !(1900..=2100).contains(&year) {
        return Err(format!("Implausible birth year in Emirates ID: {year}"));
    }

    let expected_check = compute_luhn_check(&digits[..14]);
    let actual_check = digits.as_bytes()[14] - b'0';
    if actual_check != expected_check {
        return Err(format!(
            "Emirates ID check digit mismatch: expected {expected_check}, got {actual_check}"
        ));
    }

    Ok(format!(
        "{}-{}-{}-{}",
        &digits[0..3],
        &digits[3..7],
        &digits[7..14],
        &digits[14..15]
    ))
}

/// Compute Luhn check digit for a digit string.
fn compute_luhn_check(digits: &str) -> u8 {
    let mut sum: u32 = 0;
    for (i, ch) in digits.chars().rev().enumerate() {
        let mut d = ch.to_digit(10).unwrap_or(0);
        if i % 2 == 0 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    ((10 - (sum % 10)) % 10) as u8
}

/// Validate a national ID based on jurisdiction.
pub fn validate_national_id(id: &str, jurisdiction: Jurisdiction) -> Result<String, String> {
    match jurisdiction {
        Jurisdiction::Chile => validate_rut(id),
        Jurisdiction::Uae => validate_emirates_id(id),
        Jurisdiction::Eu => {
            let trimmed = id.trim();
            if trimmed.len() < 4 {
                return Err("EU national ID too short".into());
            }
            Ok(trimmed.to_string())
        }
    }
}

/// Result of an external identity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verified: bool,
    pub provider_name: String,
    pub loa: EidasLoA,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

/// Pluggable external identity verification provider (eIDAS Art. 26(b), CIR 2026/798).
///
/// Implementations call an external service (eID, video-ident, national eID scheme)
/// to verify that a natural person matches their claimed identity.
pub trait IdentityVerificationProvider: Send + Sync {
    fn provider_name(&self) -> &str;
    fn verify(
        &self,
        legal_name: &str,
        national_id: &str,
        jurisdiction: Jurisdiction,
    ) -> Result<VerificationResult, String>;
}

/// Simulated external verifier for testing and development.
/// Approves any identity where the national ID passes format validation.
pub struct SimulatedIdentityVerifier;

impl IdentityVerificationProvider for SimulatedIdentityVerifier {
    fn provider_name(&self) -> &str {
        "simulated"
    }

    fn verify(
        &self,
        _legal_name: &str,
        national_id: &str,
        jurisdiction: Jurisdiction,
    ) -> Result<VerificationResult, String> {
        match validate_national_id(national_id, jurisdiction) {
            Ok(_) => Ok(VerificationResult {
                verified: true,
                provider_name: "simulated".into(),
                loa: EidasLoA::Substantial,
                external_reference: Some(format!(
                    "sim-{}",
                    &national_id[..4.min(national_id.len())]
                )),
                rejection_reason: None,
            }),
            Err(e) => Ok(VerificationResult {
                verified: false,
                provider_name: "simulated".into(),
                loa: EidasLoA::Low,
                external_reference: None,
                rejection_reason: Some(e),
            }),
        }
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
            national_id: None,
            jurisdiction: Jurisdiction::default(),
            legal_name,
            loa: loa_from_method(method),
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

    /// Submit and immediately verify via an external identity provider.
    /// On success, the record transitions directly to Verified with the
    /// provider's LoA. On failure, it stays Pending for manual review.
    pub fn submit_and_verify(
        &self,
        did: String,
        national_id: String,
        legal_name: String,
        jurisdiction: Jurisdiction,
        requested_at: u64,
        provider: &dyn IdentityVerificationProvider,
    ) -> Result<(IdentityProofing, VerificationResult), String> {
        let vr = provider.verify(&legal_name, &national_id, jurisdiction)?;

        let method = ProofingMethod::RemoteAutomated;
        let loa = if vr.verified { vr.loa } else { EidasLoA::Low };

        let proofing = IdentityProofing {
            did: did.clone(),
            rut: if jurisdiction == Jurisdiction::Chile {
                validate_rut(&national_id).unwrap_or_default()
            } else {
                String::new()
            },
            national_id: Some(national_id),
            jurisdiction,
            legal_name,
            loa,
            method,
            status: if vr.verified {
                ProofingStatus::Verified
            } else {
                ProofingStatus::Pending
            },
            requested_at,
            resolved_at: if vr.verified {
                Some(requested_at)
            } else {
                None
            },
            resolved_by: if vr.verified {
                Some(format!("provider:{}", provider.provider_name()))
            } else {
                None
            },
            rejection_reason: vr.rejection_reason.clone(),
        };

        let mut records = self.records.write().map_err(|e| e.to_string())?;
        records.insert(did, proofing.clone());
        Ok((proofing, vr))
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

    // ── Emirates ID validation ───────────────────────────────────────

    #[test]
    fn valid_emirates_id_with_hyphens() {
        let result = validate_emirates_id("784-1990-1234567-6");
        assert!(result.is_ok(), "Expected valid, got: {result:?}");
    }

    #[test]
    fn valid_emirates_id_digits_only() {
        let with_hyphens = validate_emirates_id("784-1990-1234567-6").unwrap();
        let digits: String = with_hyphens
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        let result = validate_emirates_id(&digits);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), with_hyphens);
    }

    #[test]
    fn emirates_id_wrong_country_code() {
        let err = validate_emirates_id("123-1990-1234567-1").unwrap_err();
        assert!(err.contains("784"));
    }

    #[test]
    fn emirates_id_wrong_length() {
        let err = validate_emirates_id("784-1990-123-1").unwrap_err();
        assert!(err.contains("15 digits"));
    }

    #[test]
    fn emirates_id_bad_check_digit() {
        let err = validate_emirates_id("784-1990-1234567-9").unwrap_err();
        assert!(err.contains("check digit"));
    }

    #[test]
    fn emirates_id_implausible_year() {
        let err = validate_emirates_id("784-1800-1234567-1").unwrap_err();
        assert!(err.contains("Implausible"));
    }

    #[test]
    fn validate_national_id_dispatches_chile() {
        assert!(validate_national_id("12345678-5", Jurisdiction::Chile).is_ok());
        assert!(validate_national_id("12345678-0", Jurisdiction::Chile).is_err());
    }

    #[test]
    fn validate_national_id_dispatches_uae() {
        assert!(validate_national_id("784-1990-1234567-6", Jurisdiction::Uae).is_ok());
        assert!(validate_national_id("000-1990-1234567-1", Jurisdiction::Uae).is_err());
    }

    #[test]
    fn validate_national_id_dispatches_eu() {
        assert!(validate_national_id("DE123456789", Jurisdiction::Eu).is_ok());
        assert!(validate_national_id("AB", Jurisdiction::Eu).is_err());
    }

    // ── Jurisdiction serde ─────────────────────────────────────────

    #[test]
    fn jurisdiction_default_is_chile() {
        assert_eq!(Jurisdiction::default(), Jurisdiction::Chile);
    }

    #[test]
    fn jurisdiction_serde_roundtrip() {
        let json = serde_json::to_string(&Jurisdiction::Uae).unwrap();
        assert_eq!(json, "\"uae\"");
        let parsed: Jurisdiction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Jurisdiction::Uae);
    }

    #[test]
    fn identity_proofing_backwards_compat() {
        let legacy = r#"{"did":"did:goya:x","rut":"12345678-5","legal_name":"Test","method":"in_person","status":"pending","requested_at":0}"#;
        let parsed: IdentityProofing = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.jurisdiction, Jurisdiction::Chile);
        assert!(parsed.national_id.is_none());
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
            national_id: None,
            jurisdiction: Jurisdiction::default(),
            legal_name: "Test".into(),
            method: ProofingMethod::InPerson,
            status: ProofingStatus::Verified,
            requested_at: 1700000000,
            resolved_at: Some(1700001000),
            resolved_by: Some("did:goya:officer".into()),
            rejection_reason: None,
            loa: EidasLoA::High,
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

    // ── External identity verification (CIR 2026/798) ──────────────

    #[test]
    fn simulated_verifier_approves_valid_rut() {
        let verifier = SimulatedIdentityVerifier;
        let result = verifier
            .verify("Juan Pérez", "12345678-5", Jurisdiction::Chile)
            .unwrap();
        assert!(result.verified);
        assert_eq!(result.provider_name, "simulated");
        assert_eq!(result.loa, EidasLoA::Substantial);
        assert!(result.external_reference.is_some());
    }

    #[test]
    fn simulated_verifier_rejects_invalid_rut() {
        let verifier = SimulatedIdentityVerifier;
        let result = verifier
            .verify("Juan Pérez", "12345678-0", Jurisdiction::Chile)
            .unwrap();
        assert!(!result.verified);
        assert!(result.rejection_reason.is_some());
    }

    #[test]
    fn submit_and_verify_success() {
        let store = RaStore::new();
        let verifier = SimulatedIdentityVerifier;
        let (proofing, vr) = store
            .submit_and_verify(
                "did:goya:verified".into(),
                "12345678-5".into(),
                "Juan Pérez".into(),
                Jurisdiction::Chile,
                1_700_000_000,
                &verifier,
            )
            .unwrap();

        assert!(vr.verified);
        assert_eq!(proofing.status, ProofingStatus::Verified);
        assert_eq!(proofing.method, ProofingMethod::RemoteAutomated);
        assert!(proofing.resolved_by.unwrap().starts_with("provider:"));
        assert!(store.is_verified("did:goya:verified"));
    }

    #[test]
    fn submit_and_verify_failure_stays_pending() {
        let store = RaStore::new();
        let verifier = SimulatedIdentityVerifier;
        let (proofing, vr) = store
            .submit_and_verify(
                "did:goya:failed".into(),
                "00000000-0".into(),
                "Invalid Person".into(),
                Jurisdiction::Chile,
                1_700_000_000,
                &verifier,
            )
            .unwrap();

        assert!(!vr.verified);
        assert_eq!(proofing.status, ProofingStatus::Pending);
        assert!(!store.is_verified("did:goya:failed"));
    }

    #[test]
    fn simulated_verifier_uae_valid() {
        let verifier = SimulatedIdentityVerifier;
        let result = verifier
            .verify("Ahmed Al-Rashid", "784-1990-1234567-6", Jurisdiction::Uae)
            .unwrap();
        assert!(result.verified);
    }

    #[test]
    fn simulated_verifier_eu_valid() {
        let verifier = SimulatedIdentityVerifier;
        let result = verifier
            .verify("Hans Mueller", "DE-1234567890", Jurisdiction::Eu)
            .unwrap();
        assert!(result.verified);
    }

    #[test]
    fn trait_object_dispatch() {
        let verifier: Box<dyn IdentityVerificationProvider> = Box::new(SimulatedIdentityVerifier);
        let result = verifier
            .verify("Test", "12345678-5", Jurisdiction::Chile)
            .unwrap();
        assert!(result.verified);
        assert_eq!(verifier.provider_name(), "simulated");
    }
}
