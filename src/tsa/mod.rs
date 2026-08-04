//! Time Stamping Authority (TSA) — RFC 3161 compliant.
//!
//! Produces signed timestamp tokens that bind a content hash to a
//! precise point in time. The TSA signs each token with the node's
//! signing provider (Ed25519 or ML-DSA-65).
//!
//! Token structure follows RFC 3161 TSTInfo semantics:
//! serial number, genTime, hash algorithm, message imprint,
//! TSA name, policy OID, nonce, accuracy, and ordering flag.

use crate::crypto::hasher::HashAlgorithm;
use crate::identity::signing::{SigningAlgorithm, SigningProvider};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// TSA policy OID (private arc under Goya namespace).
pub const TSA_POLICY_OID: &str = "1.3.6.1.4.1.99999.1.1";

/// Default accuracy: 1 second.
const DEFAULT_ACCURACY_SECS: u32 = 1;

/// Request for a timestamp token (mirrors RFC 3161 TimeStampReq).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeStampRequest {
    /// Hash algorithm used to produce the imprint.
    #[serde(default)]
    pub hash_algorithm: HashAlgorithm,
    /// Hash of the data to timestamp (hex-encoded).
    pub message_imprint: String,
    /// Client-supplied nonce for replay protection.
    #[serde(default)]
    pub nonce: Option<u64>,
    /// Whether the client requests ordering.
    #[serde(default)]
    pub require_ordering: bool,
}

/// RFC 3161 TSTInfo — the core timestamp token content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TstInfo {
    /// Version (always 1 per RFC 3161).
    pub version: u32,
    /// TSA policy OID.
    pub policy: String,
    /// Hash algorithm used for the imprint.
    pub hash_algorithm: HashAlgorithm,
    /// Hash of the timestamped data (hex).
    pub message_imprint: String,
    /// Monotonically increasing serial number.
    pub serial_number: u64,
    /// Generation time (UNIX seconds, UTC).
    pub gen_time: u64,
    /// Accuracy in seconds.
    pub accuracy_secs: u32,
    /// Whether ordering is guaranteed among tokens from this TSA.
    pub ordering: bool,
    /// Client-supplied nonce echoed back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    /// TSA name (DID or identifier).
    pub tsa_name: String,
}

/// Complete signed timestamp token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeStampToken {
    /// Unique token ID.
    pub id: String,
    /// The timestamp info.
    pub tst_info: TstInfo,
    /// Signature over the canonical TstInfo (hex-encoded).
    pub signature: String,
    /// Public key of the TSA (hex-encoded).
    pub public_key: String,
    /// Signing algorithm used.
    pub signature_algorithm: SigningAlgorithm,
}

/// Response to a timestamp request (mirrors RFC 3161 TimeStampResp).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeStampResponse {
    /// Status: 0 = granted, 2 = rejection.
    pub status: u32,
    /// Human-readable status string.
    pub status_string: String,
    /// The token (present when status == 0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<TimeStampToken>,
}

/// TSA provider — generates and verifies timestamp tokens.
pub struct TsaProvider {
    signer: Arc<dyn SigningProvider>,
    serial: AtomicU64,
    tsa_name: String,
    policy_oid: String,
    accuracy_secs: u32,
}

impl TsaProvider {
    pub fn new(signer: Arc<dyn SigningProvider>, tsa_name: String) -> Self {
        Self {
            signer,
            serial: AtomicU64::new(1),
            tsa_name,
            policy_oid: TSA_POLICY_OID.to_string(),
            accuracy_secs: DEFAULT_ACCURACY_SECS,
        }
    }

    pub fn with_accuracy(mut self, secs: u32) -> Self {
        self.accuracy_secs = secs;
        self
    }

    pub fn issue(&self, req: &TimeStampRequest) -> TimeStampResponse {
        if let Err(msg) = validate_imprint(&req.message_imprint) {
            return TimeStampResponse {
                status: 2,
                status_string: msg,
                token: None,
            };
        }

        let serial = self.serial.fetch_add(1, Ordering::SeqCst);
        let gen_time = now_secs();

        let tst_info = TstInfo {
            version: 1,
            policy: self.policy_oid.clone(),
            hash_algorithm: req.hash_algorithm,
            message_imprint: req.message_imprint.clone(),
            serial_number: serial,
            gen_time,
            accuracy_secs: self.accuracy_secs,
            ordering: req.require_ordering,
            nonce: req.nonce,
            tsa_name: self.tsa_name.clone(),
        };

        let canonical = tst_info.signing_payload();
        let signature = match self.signer.sign(canonical.as_bytes()) {
            Ok(sig) => hex::encode(sig),
            Err(e) => {
                return TimeStampResponse {
                    status: 2,
                    status_string: format!("signing failed: {e}"),
                    token: None,
                };
            }
        };

        let token = TimeStampToken {
            id: uuid::Uuid::new_v4().to_string(),
            tst_info,
            signature,
            public_key: hex::encode(self.signer.public_key()),
            signature_algorithm: self.signer.algorithm(),
        };

        TimeStampResponse {
            status: 0,
            status_string: "granted".to_string(),
            token: Some(token),
        }
    }

    pub fn policy_info(&self) -> serde_json::Value {
        serde_json::json!({
            "policy_oid": self.policy_oid,
            "tsa_name": self.tsa_name,
            "hash_algorithms": ["SHA-256", "SHA3-256"],
            "signing_algorithm": self.signer.algorithm(),
            "accuracy_secs": self.accuracy_secs,
            "ordering_supported": true,
        })
    }
}

impl TstInfo {
    /// Deterministic signing payload (canonical string representation).
    pub fn signing_payload(&self) -> String {
        format!(
            "tsa:v{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.version,
            self.policy,
            self.hash_algorithm,
            self.message_imprint,
            self.serial_number,
            self.gen_time,
            self.accuracy_secs,
            self.ordering,
            self.nonce.unwrap_or(0),
        )
    }
}

/// Verify a timestamp token's signature.
pub fn verify_token(token: &TimeStampToken) -> bool {
    let payload = token.tst_info.signing_payload();
    crate::signature::verify_signature(
        token.signature_algorithm,
        &token.public_key,
        payload.as_bytes(),
        &token.signature,
    )
}

fn validate_imprint(imprint: &str) -> Result<(), String> {
    if imprint.len() != 64 {
        return Err(format!(
            "message_imprint must be 64 hex chars, got {}",
            imprint.len()
        ));
    }
    if hex::decode(imprint).is_err() {
        return Err("message_imprint is not valid hex".to_string());
    }
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::SoftwareSigningProvider;

    fn make_provider() -> TsaProvider {
        let signer = Arc::new(SoftwareSigningProvider::generate());
        TsaProvider::new(signer, "did:goya:tsa-test".to_string())
    }

    fn valid_imprint() -> String {
        use crate::crypto::hasher::{hash_with, HashAlgorithm};
        hex::encode(hash_with(HashAlgorithm::Sha256, b"test data"))
    }

    #[test]
    fn issue_granted_token() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: Some(42),
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.status_string, "granted");
        let token = resp.token.unwrap();
        assert_eq!(token.tst_info.version, 1);
        assert_eq!(token.tst_info.message_imprint, req.message_imprint);
        assert_eq!(token.tst_info.nonce, Some(42));
        assert_eq!(token.tst_info.policy, TSA_POLICY_OID);
        assert_eq!(token.tst_info.accuracy_secs, 1);
    }

    #[test]
    fn serial_numbers_are_monotonic() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let s1 = tsa.issue(&req).token.unwrap().tst_info.serial_number;
        let s2 = tsa.issue(&req).token.unwrap().tst_info.serial_number;
        let s3 = tsa.issue(&req).token.unwrap().tst_info.serial_number;
        assert_eq!(s1 + 1, s2);
        assert_eq!(s2 + 1, s3);
    }

    #[test]
    fn nonce_echoed_back() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: Some(123456),
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert_eq!(token.tst_info.nonce, Some(123456));
    }

    #[test]
    fn nonce_none_when_not_requested() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert_eq!(token.tst_info.nonce, None);
    }

    #[test]
    fn token_signature_verifies() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: Some(99),
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert!(verify_token(&token));
    }

    #[test]
    fn tampered_token_fails_verification() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let mut token = tsa.issue(&req).token.unwrap();
        token.tst_info.gen_time += 1;
        assert!(!verify_token(&token));
    }

    #[test]
    fn rejects_short_imprint() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: "abcd".to_string(),
            nonce: None,
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        assert_eq!(resp.status, 2);
        assert!(resp.token.is_none());
    }

    #[test]
    fn rejects_non_hex_imprint() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: "z".repeat(64),
            nonce: None,
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        assert_eq!(resp.status, 2);
    }

    #[test]
    fn ordering_flag_preserved() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: true,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert!(token.tst_info.ordering);
    }

    #[test]
    fn custom_accuracy() {
        let signer = Arc::new(SoftwareSigningProvider::generate());
        let tsa = TsaProvider::new(signer, "did:goya:tsa".to_string()).with_accuracy(5);
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert_eq!(token.tst_info.accuracy_secs, 5);
    }

    #[test]
    fn sha3_hash_algorithm() {
        let tsa = make_provider();
        let imprint = hex::encode(crate::crypto::hasher::hash_with(
            HashAlgorithm::Sha3_256,
            b"sha3 data",
        ));
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha3_256,
            message_imprint: imprint.clone(),
            nonce: None,
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert_eq!(token.tst_info.hash_algorithm, HashAlgorithm::Sha3_256);
        assert_eq!(token.tst_info.message_imprint, imprint);
    }

    #[test]
    fn signing_payload_is_deterministic() {
        let info = TstInfo {
            version: 1,
            policy: TSA_POLICY_OID.to_string(),
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: "aa".repeat(32),
            serial_number: 42,
            gen_time: 1700000000,
            accuracy_secs: 1,
            ordering: false,
            nonce: Some(99),
            tsa_name: "did:goya:tsa".to_string(),
        };
        assert_eq!(info.signing_payload(), info.signing_payload());
    }

    #[test]
    fn different_fields_produce_different_payloads() {
        let base = TstInfo {
            version: 1,
            policy: TSA_POLICY_OID.to_string(),
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: "aa".repeat(32),
            serial_number: 1,
            gen_time: 1700000000,
            accuracy_secs: 1,
            ordering: false,
            nonce: None,
            tsa_name: "did:goya:tsa".to_string(),
        };
        let mut modified = base.clone();
        modified.serial_number = 2;
        assert_ne!(base.signing_payload(), modified.signing_payload());
    }

    #[test]
    fn policy_info_contains_required_fields() {
        let tsa = make_provider();
        let info = tsa.policy_info();
        assert_eq!(info["policy_oid"], TSA_POLICY_OID);
        assert!(info["hash_algorithms"].as_array().unwrap().len() >= 2);
        assert!(info["accuracy_secs"].as_u64().is_some());
    }

    #[test]
    fn token_serialization_roundtrip() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: Some(7),
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        let json = serde_json::to_string(&token).unwrap();
        let parsed: TimeStampToken = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tst_info, token.tst_info);
        assert!(verify_token(&parsed));
    }

    #[test]
    fn mldsa65_signing() {
        use crate::identity::signing::MlDsaSigningProvider;
        let signer = Arc::new(MlDsaSigningProvider::generate());
        let tsa = TsaProvider::new(signer, "did:goya:tsa-pqc".to_string());
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        assert_eq!(resp.status, 0);
        let token = resp.token.unwrap();
        assert_eq!(token.signature_algorithm, SigningAlgorithm::MlDsa65);
        assert!(verify_token(&token));
    }

    #[test]
    fn gen_time_is_recent() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        let now = now_secs();
        assert!(token.tst_info.gen_time <= now);
        assert!(token.tst_info.gen_time >= now - 2);
    }
}
