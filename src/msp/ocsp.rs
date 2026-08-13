//! OCSP Responder — RFC 6960 semantics.
//!
//! Answers certificate status queries by checking the CRL store.
//! Responses are signed by the node's signing provider.

use crate::identity::signing::{SigningAlgorithm, SigningProvider};
use crate::msp::CrlStore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Certificate status per RFC 6960.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    Good,
    Revoked,
    Unknown,
}

impl std::fmt::Display for CertStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Good => write!(f, "good"),
            Self::Revoked => write!(f, "revoked"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// OCSP query request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspRequest {
    /// MSP/organization identifier (CRL namespace).
    pub msp_id: String,
    /// Hex-encoded serial number to check.
    pub serial: String,
    /// Client-supplied nonce for replay protection.
    #[serde(default)]
    pub nonce: Option<u64>,
}

/// Single certificate status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleResponse {
    pub serial: String,
    pub status: CertStatus,
    pub this_update: u64,
    pub next_update: u64,
}

/// Signed OCSP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspResponse {
    /// Response status: 0 = successful, 1 = malformed_request, 6 = unauthorized.
    pub response_status: u32,
    /// Responder identifier (DID or name).
    pub responder_id: String,
    /// When this response was produced (UNIX seconds).
    pub produced_at: u64,
    /// The certificate status answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<SingleResponse>,
    /// Echoed nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    /// Signature over the canonical response data (hex).
    pub signature: String,
    /// Public key of the responder (hex).
    pub public_key: String,
    /// Signing algorithm.
    pub signature_algorithm: SigningAlgorithm,
}

/// OCSP responder — checks CRL store and signs responses.
pub struct OcspResponder {
    signer: Arc<dyn SigningProvider>,
    responder_id: String,
    validity_secs: u64,
}

impl OcspResponder {
    pub fn new(signer: Arc<dyn SigningProvider>, responder_id: String) -> Self {
        Self {
            signer,
            responder_id,
            validity_secs: 3600,
        }
    }

    pub fn with_validity_secs(mut self, secs: u64) -> Self {
        self.validity_secs = secs;
        self
    }

    /// Query certificate status.
    pub fn query(&self, req: &OcspRequest, crl_store: &dyn CrlStore) -> OcspResponse {
        if req.serial.is_empty() || req.msp_id.is_empty() {
            return self.error_response(1, "malformed_request", req.nonce);
        }

        if hex::decode(&req.serial).is_err() {
            return self.error_response(1, "invalid serial hex", req.nonce);
        }

        let revoked_serials = match crl_store.read_crl(&req.msp_id) {
            Ok(serials) => serials,
            Err(_) => return self.error_response(6, "crl_store_error", req.nonce),
        };

        let status = if revoked_serials.contains(&req.serial) {
            CertStatus::Revoked
        } else {
            CertStatus::Good
        };

        let now = now_secs();
        let single = SingleResponse {
            serial: req.serial.clone(),
            status,
            this_update: now,
            next_update: now + self.validity_secs,
        };

        let payload = signing_payload(&self.responder_id, now, &single, req.nonce);
        let signature = match self.signer.sign(payload.as_bytes()) {
            Ok(sig) => hex::encode(sig),
            Err(e) => return self.error_response(2, &format!("signing failed: {e}"), req.nonce),
        };

        OcspResponse {
            response_status: 0,
            responder_id: self.responder_id.clone(),
            produced_at: now,
            response: Some(single),
            nonce: req.nonce,
            signature,
            public_key: hex::encode(self.signer.public_key()),
            signature_algorithm: self.signer.algorithm(),
        }
    }

    fn error_response(&self, status: u32, _reason: &str, nonce: Option<u64>) -> OcspResponse {
        OcspResponse {
            response_status: status,
            responder_id: self.responder_id.clone(),
            produced_at: now_secs(),
            response: None,
            nonce,
            signature: String::new(),
            public_key: hex::encode(self.signer.public_key()),
            signature_algorithm: self.signer.algorithm(),
        }
    }
}

/// Verify an OCSP response signature.
pub fn verify_ocsp_response(resp: &OcspResponse) -> bool {
    if resp.response_status != 0 || resp.signature.is_empty() {
        return false;
    }
    let single = match &resp.response {
        Some(s) => s,
        None => return false,
    };
    let payload = signing_payload(&resp.responder_id, resp.produced_at, single, resp.nonce);
    crate::signature::verify_signature(
        resp.signature_algorithm,
        &resp.public_key,
        payload.as_bytes(),
        &resp.signature,
    )
}

fn signing_payload(
    responder_id: &str,
    produced_at: u64,
    single: &SingleResponse,
    nonce: Option<u64>,
) -> String {
    let nonce_str = match nonce {
        Some(n) => n.to_string(),
        None => "none".to_string(),
    };
    format!(
        "ocsp:{}:{}:{}:{}:{}:{}:{}",
        responder_id,
        produced_at,
        single.serial,
        single.status,
        single.this_update,
        single.next_update,
        nonce_str,
    )
}

/// Verify that a nonce in the response matches the request.
pub fn verify_nonce(request_nonce: Option<u64>, response: &OcspResponse) -> bool {
    request_nonce == response.nonce
}

impl OcspResponse {
    /// Export as a JSON-serializable DER-like structure with all fields.
    /// Full ASN.1 DER OCSP encoding would require a DER encoder —
    /// this provides a self-contained verifiable export.
    pub fn to_export_json(&self) -> serde_json::Value {
        serde_json::json!({
            "format": "goya-ocsp-response",
            "version": "1.0",
            "response_status": self.response_status,
            "responder_id": self.responder_id,
            "produced_at": self.produced_at,
            "response": self.response,
            "nonce": self.nonce,
            "signature": self.signature,
            "public_key": self.public_key,
            "signature_algorithm": self.signature_algorithm,
            "verified": verify_ocsp_response(self),
        })
    }
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
    use crate::msp::MemoryCrlStore;

    fn make_responder() -> OcspResponder {
        let signer = Arc::new(SoftwareSigningProvider::generate());
        OcspResponder::new(signer, "did:goya:ocsp-test".to_string())
    }

    fn make_crl_store(msp_id: &str, revoked: &[&str]) -> MemoryCrlStore {
        let store = MemoryCrlStore::new();
        let serials: Vec<String> = revoked.iter().map(|s| s.to_string()).collect();
        store.write_crl(msp_id, &serials).unwrap();
        store
    }

    #[test]
    fn good_status_for_non_revoked() {
        let responder = make_responder();
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: None,
        };
        let resp = responder.query(&req, &store);
        assert_eq!(resp.response_status, 0);
        assert_eq!(resp.response.as_ref().unwrap().status, CertStatus::Good);
    }

    #[test]
    fn revoked_status_for_revoked_serial() {
        let serial = hex::encode([2u8; 8]);
        let responder = make_responder();
        let store = make_crl_store("msp1", &[&serial]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: serial.clone(),
            nonce: None,
        };
        let resp = responder.query(&req, &store);
        assert_eq!(resp.response_status, 0);
        assert_eq!(resp.response.as_ref().unwrap().status, CertStatus::Revoked);
    }

    #[test]
    fn nonce_echoed_back() {
        let responder = make_responder();
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: Some(42),
        };
        let resp = responder.query(&req, &store);
        assert_eq!(resp.nonce, Some(42));
    }

    #[test]
    fn response_signature_verifies() {
        let responder = make_responder();
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: Some(99),
        };
        let resp = responder.query(&req, &store);
        assert!(verify_ocsp_response(&resp));
    }

    #[test]
    fn tampered_response_fails_verification() {
        let responder = make_responder();
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: None,
        };
        let mut resp = responder.query(&req, &store);
        resp.response.as_mut().unwrap().status = CertStatus::Revoked;
        assert!(!verify_ocsp_response(&resp));
    }

    #[test]
    fn empty_serial_returns_malformed() {
        let responder = make_responder();
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: String::new(),
            nonce: None,
        };
        let resp = responder.query(&req, &store);
        assert_eq!(resp.response_status, 1);
        assert!(resp.response.is_none());
    }

    #[test]
    fn empty_msp_id_returns_malformed() {
        let responder = make_responder();
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: String::new(),
            serial: hex::encode([1u8; 8]),
            nonce: None,
        };
        let resp = responder.query(&req, &store);
        assert_eq!(resp.response_status, 1);
    }

    #[test]
    fn invalid_hex_serial_returns_malformed() {
        let responder = make_responder();
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: "not_hex_zz".into(),
            nonce: None,
        };
        let resp = responder.query(&req, &store);
        assert_eq!(resp.response_status, 1);
    }

    #[test]
    fn next_update_reflects_validity() {
        let responder = make_responder().with_validity_secs(7200);
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: None,
        };
        let resp = responder.query(&req, &store);
        let single = resp.response.unwrap();
        assert_eq!(single.next_update - single.this_update, 7200);
    }

    #[test]
    fn produced_at_is_recent() {
        let responder = make_responder();
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: None,
        };
        let resp = responder.query(&req, &store);
        let now = now_secs();
        assert!(resp.produced_at <= now);
        assert!(resp.produced_at >= now - 2);
    }

    #[test]
    fn error_response_has_no_signature() {
        let responder = make_responder();
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: String::new(),
            serial: String::new(),
            nonce: Some(1),
        };
        let resp = responder.query(&req, &store);
        assert!(resp.signature.is_empty());
        assert!(!verify_ocsp_response(&resp));
    }

    #[test]
    fn multiple_revoked_serials() {
        let s1 = hex::encode([1u8; 8]);
        let s2 = hex::encode([2u8; 8]);
        let s3 = hex::encode([3u8; 8]);
        let responder = make_responder();
        let store = make_crl_store("msp1", &[&s1, &s2]);

        let r1 = responder.query(
            &OcspRequest {
                msp_id: "msp1".into(),
                serial: s1,
                nonce: None,
            },
            &store,
        );
        let r2 = responder.query(
            &OcspRequest {
                msp_id: "msp1".into(),
                serial: s2,
                nonce: None,
            },
            &store,
        );
        let r3 = responder.query(
            &OcspRequest {
                msp_id: "msp1".into(),
                serial: s3,
                nonce: None,
            },
            &store,
        );
        assert_eq!(r1.response.unwrap().status, CertStatus::Revoked);
        assert_eq!(r2.response.unwrap().status, CertStatus::Revoked);
        assert_eq!(r3.response.unwrap().status, CertStatus::Good);
    }

    #[test]
    fn serialization_roundtrip() {
        let responder = make_responder();
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: Some(7),
        };
        let resp = responder.query(&req, &store);
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: OcspResponse = serde_json::from_str(&json).unwrap();
        assert!(verify_ocsp_response(&parsed));
    }

    #[test]
    fn mldsa65_signing() {
        use crate::identity::signing::MlDsaSigningProvider;
        let signer = Arc::new(MlDsaSigningProvider::generate());
        let responder = OcspResponder::new(signer, "did:goya:ocsp-pqc".into());
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: None,
        };
        let resp = responder.query(&req, &store);
        assert_eq!(resp.signature_algorithm, SigningAlgorithm::MlDsa65);
        assert!(verify_ocsp_response(&resp));
    }

    #[test]
    fn nonce_none_vs_zero_distinct() {
        let signer = Arc::new(SoftwareSigningProvider::generate());
        let responder = OcspResponder::new(signer, "did:goya:ocsp".into());
        let store = make_crl_store("msp1", &[]);

        let req_none = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: None,
        };
        let req_zero = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: Some(0),
        };
        let resp_none = responder.query(&req_none, &store);
        let resp_zero = responder.query(&req_zero, &store);
        // Signatures differ because nonce payload differs
        assert_ne!(resp_none.signature, resp_zero.signature);
    }

    #[test]
    fn verify_nonce_match() {
        let signer = Arc::new(SoftwareSigningProvider::generate());
        let responder = OcspResponder::new(signer, "did:goya:ocsp".into());
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: Some(42),
        };
        let resp = responder.query(&req, &store);
        assert!(verify_nonce(Some(42), &resp));
        assert!(!verify_nonce(Some(99), &resp));
        assert!(!verify_nonce(None, &resp));
    }

    #[test]
    fn export_json_has_verification_flag() {
        let signer = Arc::new(SoftwareSigningProvider::generate());
        let responder = OcspResponder::new(signer, "did:goya:ocsp".into());
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: None,
        };
        let resp = responder.query(&req, &store);
        let export = resp.to_export_json();
        assert_eq!(export["format"], "goya-ocsp-response");
        assert_eq!(export["verified"], true);
        assert_eq!(export["version"], "1.0");
    }
}
