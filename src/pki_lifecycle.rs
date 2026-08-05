//! Certificate lifecycle manager — orchestrates CRL publication,
//! expiry monitoring, suspension, and renewal.
//!
//! DS 181 Art. 17 requires CRL publication within 1 hour of revocation.
//! This module provides the automation layer over the PKI building blocks.

use crate::msp::crl_rfc5280::{generate_crl_der, CrlError};
use crate::msp::{CrlStore, Msp};
use crate::pki::NodeCaConfig;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Certificate lifecycle event for audit trail integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleEvent {
    pub event_type: LifecycleEventType,
    pub serial: String,
    pub msp_id: String,
    pub timestamp: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleEventType {
    CrlPublished,
    CertificateSuspended,
    CertificateReinstated,
    CertificateRevoked,
    CertificateExpiring,
    CertificateRenewed,
}

/// Manages the certificate lifecycle for one MSP/CA.
pub struct LifecycleManager {
    crl_number: AtomicU64,
    crl_validity_days: u32,
    expiry_warning_days: u32,
    events: std::sync::Mutex<Vec<LifecycleEvent>>,
}

impl LifecycleManager {
    pub fn new(crl_validity_days: u32, expiry_warning_days: u32) -> Self {
        Self {
            crl_number: AtomicU64::new(1),
            crl_validity_days,
            expiry_warning_days,
            events: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Revoke a certificate and immediately publish an updated CRL.
    ///
    /// Returns the DER-encoded CRL bytes on success.
    pub fn revoke_and_publish_crl(
        &self,
        msp: &mut Msp,
        serial: &str,
        ca: &NodeCaConfig,
        crl_store: &dyn CrlStore,
        now: u64,
    ) -> Result<Vec<u8>, LifecycleError> {
        msp.revoke(serial);

        crl_store
            .write_crl(&msp.msp_id, &msp.revoked_serials)
            .map_err(|e| LifecycleError::Storage(e.to_string()))?;

        self.record_event(
            LifecycleEventType::CertificateRevoked,
            serial,
            &msp.msp_id,
            now,
            "revoked",
        );

        self.publish_crl(msp, ca, now)
    }

    /// Suspend a certificate and publish updated CRL.
    pub fn suspend_and_publish_crl(
        &self,
        msp: &mut Msp,
        serial: &str,
        ca: &NodeCaConfig,
        crl_store: &dyn CrlStore,
        now: u64,
    ) -> Result<Vec<u8>, LifecycleError> {
        msp.suspend(serial)
            .map_err(|e| LifecycleError::Operation(e.to_string()))?;

        let mut all_inactive: Vec<String> = msp.revoked_serials.clone();
        all_inactive.extend(msp.suspended_serials.clone());
        crl_store
            .write_crl(&msp.msp_id, &all_inactive)
            .map_err(|e| LifecycleError::Storage(e.to_string()))?;

        self.record_event(
            LifecycleEventType::CertificateSuspended,
            serial,
            &msp.msp_id,
            now,
            "suspended (certificateHold)",
        );

        self.publish_crl(msp, ca, now)
    }

    /// Reinstate a suspended certificate and publish updated CRL.
    pub fn reinstate_and_publish_crl(
        &self,
        msp: &mut Msp,
        serial: &str,
        ca: &NodeCaConfig,
        crl_store: &dyn CrlStore,
        now: u64,
    ) -> Result<Vec<u8>, LifecycleError> {
        msp.reinstate(serial)
            .map_err(|e| LifecycleError::Operation(e.to_string()))?;

        let mut all_inactive: Vec<String> = msp.revoked_serials.clone();
        all_inactive.extend(msp.suspended_serials.clone());
        crl_store
            .write_crl(&msp.msp_id, &all_inactive)
            .map_err(|e| LifecycleError::Storage(e.to_string()))?;

        self.record_event(
            LifecycleEventType::CertificateReinstated,
            serial,
            &msp.msp_id,
            now,
            "reinstated",
        );

        self.publish_crl(msp, ca, now)
    }

    /// Publish a CRL from current revoked + suspended serials.
    pub fn publish_crl(
        &self,
        msp: &Msp,
        ca: &NodeCaConfig,
        now: u64,
    ) -> Result<Vec<u8>, LifecycleError> {
        let crl_num = self.crl_number.fetch_add(1, Ordering::SeqCst);

        let mut all_serials: Vec<String> = msp.revoked_serials.clone();
        all_serials.extend(msp.suspended_serials.clone());

        let der = generate_crl_der(&all_serials, ca, crl_num, self.crl_validity_days)
            .map_err(LifecycleError::Crl)?;

        self.record_event(
            LifecycleEventType::CrlPublished,
            &format!("crl#{crl_num}"),
            &msp.msp_id,
            now,
            &format!("{} entries, {} bytes", all_serials.len(), der.len()),
        );

        Ok(der)
    }

    /// Check certificates approaching expiry.
    ///
    /// Takes a list of `(serial, expiry_timestamp)` and returns those
    /// within the warning window.
    pub fn check_expiring(
        &self,
        certs: &[(String, u64)],
        msp_id: &str,
        now: u64,
    ) -> Vec<LifecycleEvent> {
        let warning_secs = u64::from(self.expiry_warning_days) * 86400;
        let mut expiring = Vec::new();

        for (serial, expiry) in certs {
            if *expiry > now && *expiry - now <= warning_secs {
                let days_left = (*expiry - now) / 86400;
                let event = LifecycleEvent {
                    event_type: LifecycleEventType::CertificateExpiring,
                    serial: serial.clone(),
                    msp_id: msp_id.to_string(),
                    timestamp: now,
                    detail: format!("{days_left} days until expiry"),
                };
                expiring.push(event.clone());
                self.events
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(event);
            }
        }

        expiring
    }

    /// Get all lifecycle events recorded so far.
    pub fn events(&self) -> Vec<LifecycleEvent> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Current CRL number (next to be issued).
    pub fn next_crl_number(&self) -> u64 {
        self.crl_number.load(Ordering::SeqCst)
    }

    fn record_event(
        &self,
        event_type: LifecycleEventType,
        serial: &str,
        msp_id: &str,
        timestamp: u64,
        detail: &str,
    ) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(LifecycleEvent {
                event_type,
                serial: serial.to_string(),
                msp_id: msp_id.to_string(),
                timestamp,
                detail: detail.to_string(),
            });
    }
}

#[derive(Debug)]
pub enum LifecycleError {
    Storage(String),
    Operation(String),
    Crl(CrlError),
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(msg) => write!(f, "storage error: {msg}"),
            Self::Operation(msg) => write!(f, "operation error: {msg}"),
            Self::Crl(e) => write!(f, "CRL error: {e}"),
        }
    }
}

impl std::error::Error for LifecycleError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msp::MemoryCrlStore;
    use crate::pki::NodeCaConfig;

    fn test_ca() -> NodeCaConfig {
        let (ca, _, _) = NodeCaConfig::generate().unwrap();
        ca
    }

    fn test_msp() -> Msp {
        Msp::new("msp-test", "org-test")
    }

    #[test]
    fn revoke_and_publish_produces_crl() {
        let ca = test_ca();
        let store = MemoryCrlStore::new();
        let mgr = LifecycleManager::new(7, 30);
        let mut msp = test_msp();
        let serial = hex::encode([1u8; 8]);

        let der = mgr
            .revoke_and_publish_crl(&mut msp, &serial, &ca, &store, 1000)
            .unwrap();
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30);
        assert!(msp.revoked_serials.contains(&serial));
    }

    #[test]
    fn revoke_records_events() {
        let ca = test_ca();
        let store = MemoryCrlStore::new();
        let mgr = LifecycleManager::new(7, 30);
        let mut msp = test_msp();
        let serial = hex::encode([1u8; 8]);

        mgr.revoke_and_publish_crl(&mut msp, &serial, &ca, &store, 1000)
            .unwrap();

        let events = mgr.events();
        assert_eq!(events.len(), 2); // revoked + crl_published
        assert_eq!(events[0].event_type, LifecycleEventType::CertificateRevoked);
        assert_eq!(events[1].event_type, LifecycleEventType::CrlPublished);
    }

    #[test]
    fn suspend_and_publish() {
        let ca = test_ca();
        let store = MemoryCrlStore::new();
        let mgr = LifecycleManager::new(7, 30);
        let mut msp = test_msp();
        let serial = hex::encode([2u8; 8]);

        let der = mgr
            .suspend_and_publish_crl(&mut msp, &serial, &ca, &store, 1000)
            .unwrap();
        assert!(!der.is_empty());
        assert!(msp.is_suspended(&serial));

        let events = mgr.events();
        assert!(events
            .iter()
            .any(|e| e.event_type == LifecycleEventType::CertificateSuspended));
    }

    #[test]
    fn reinstate_and_publish() {
        let ca = test_ca();
        let store = MemoryCrlStore::new();
        let mgr = LifecycleManager::new(7, 30);
        let mut msp = test_msp();
        let serial = hex::encode([3u8; 8]);

        mgr.suspend_and_publish_crl(&mut msp, &serial, &ca, &store, 1000)
            .unwrap();
        let der = mgr
            .reinstate_and_publish_crl(&mut msp, &serial, &ca, &store, 2000)
            .unwrap();
        assert!(!der.is_empty());
        assert!(!msp.is_suspended(&serial));

        let events = mgr.events();
        assert!(events
            .iter()
            .any(|e| e.event_type == LifecycleEventType::CertificateReinstated));
    }

    #[test]
    fn crl_numbers_increment() {
        let ca = test_ca();
        let _store = MemoryCrlStore::new();
        let mgr = LifecycleManager::new(7, 30);
        let msp = test_msp();

        assert_eq!(mgr.next_crl_number(), 1);
        mgr.publish_crl(&msp, &ca, 1000).unwrap();
        assert_eq!(mgr.next_crl_number(), 2);
        mgr.publish_crl(&msp, &ca, 2000).unwrap();
        assert_eq!(mgr.next_crl_number(), 3);
    }

    #[test]
    fn check_expiring_within_window() {
        let mgr = LifecycleManager::new(7, 30);
        let now = 1_700_000_000;
        let certs = vec![
            ("cert-1".into(), now + 10 * 86400), // 10 days — within 30-day window
            ("cert-2".into(), now + 60 * 86400), // 60 days — outside window
            ("cert-3".into(), now + 29 * 86400), // 29 days — within window
            ("cert-4".into(), now - 86400),      // already expired — not reported
        ];

        let expiring = mgr.check_expiring(&certs, "msp1", now);
        assert_eq!(expiring.len(), 2);
        assert!(expiring.iter().any(|e| e.serial == "cert-1"));
        assert!(expiring.iter().any(|e| e.serial == "cert-3"));
    }

    #[test]
    fn check_expiring_records_events() {
        let mgr = LifecycleManager::new(7, 30);
        let now = 1_700_000_000;
        let certs = vec![("cert-1".into(), now + 5 * 86400)];

        mgr.check_expiring(&certs, "msp1", now);
        let events = mgr.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            LifecycleEventType::CertificateExpiring
        );
        assert!(events[0].detail.contains("5 days"));
    }

    #[test]
    fn check_expiring_empty_list() {
        let mgr = LifecycleManager::new(7, 30);
        let expiring = mgr.check_expiring(&[], "msp1", 1_700_000_000);
        assert!(expiring.is_empty());
    }

    #[test]
    fn publish_crl_with_empty_msp() {
        let ca = test_ca();
        let mgr = LifecycleManager::new(7, 30);
        let msp = test_msp();

        let der = mgr.publish_crl(&msp, &ca, 1000).unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn multiple_revocations_accumulate() {
        let ca = test_ca();
        let store = MemoryCrlStore::new();
        let mgr = LifecycleManager::new(7, 30);
        let mut msp = test_msp();

        for i in 0..5u8 {
            let serial = hex::encode([i; 8]);
            mgr.revoke_and_publish_crl(&mut msp, &serial, &ca, &store, 1000 + u64::from(i))
                .unwrap();
        }
        assert_eq!(msp.revoked_serials.len(), 5);
        let events = mgr.events();
        let revoked_count = events
            .iter()
            .filter(|e| e.event_type == LifecycleEventType::CertificateRevoked)
            .count();
        assert_eq!(revoked_count, 5);
    }

    #[test]
    fn serialization_roundtrip() {
        let event = LifecycleEvent {
            event_type: LifecycleEventType::CrlPublished,
            serial: "crl#1".into(),
            msp_id: "msp1".into(),
            timestamp: 1000,
            detail: "test".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: LifecycleEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_type, LifecycleEventType::CrlPublished);
    }
}
