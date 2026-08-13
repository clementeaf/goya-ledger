//! Audit trail — immutable log of all API requests and domain events for
//! regulatory compliance (ISO 27001).
//!
//! Two levels of audit:
//! - **Request-level**: every HTTP request (method, path, status, duration).
//! - **Action-level**: semantic domain events (block_mined, did_registered,
//!   chaincode_installed, etc.) emitted from business logic.
//!
//! Records are append-only. The `action` field distinguishes domain events
//! from raw HTTP request logs (`action = "http_request"`).

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::storage::errors::StorageResult;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Semantic action types for domain-level audit events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Raw HTTP request (populated by middleware).
    HttpRequest,
    /// A new block was mined / committed.
    BlockMined,
    /// A wallet was created.
    WalletCreated,
    /// Tokens were transferred.
    TokenTransfer,
    /// Tokens were staked.
    TokenStaked,
    /// Unstake requested.
    TokenUnstaked,
    /// Chaincode (smart contract) was installed.
    ChaincodeInstalled,
    /// Chaincode was upgraded.
    ChaincodeUpgraded,
    /// A DID identity was registered.
    DidRegistered,
    /// A DID was revoked.
    DidRevoked,
    /// A verifiable credential was stored.
    CredentialStored,
    /// A credential was revoked.
    CredentialRevoked,
    /// A channel was created.
    ChannelCreated,
    /// A governance proposal was submitted.
    ProposalSubmitted,
    /// A vote was cast on a proposal.
    ProposalVoted,
    /// A vault operation (store, get, recover).
    VaultOperation,

    // ── ETSI TS 102 042 audit event categories ────────────────────
    /// CA key pair generated (key ceremony).
    KeyGenerated,
    /// CA key activated for operational use.
    KeyActivated,
    /// CA key deactivated or suspended.
    KeyDeactivated,
    /// CA key destroyed / zeroized.
    KeyDestroyed,
    /// CA key backed up to HSM or custodian shares.
    KeyBackedUp,
    /// CA key restored from backup.
    KeyRestored,

    /// Certificate issued to a subscriber.
    CertificateIssued,
    /// Certificate renewed.
    CertificateRenewed,
    /// Certificate suspended.
    CertificateSuspended,
    /// Certificate revoked and added to CRL.
    CertificateRevoked,

    /// CRL published.
    CrlPublished,
    /// OCSP response generated.
    OcspResponseGenerated,

    /// Timestamp token issued (TSA operation).
    TimestampIssued,
    /// TSA key rollover.
    TsaKeyRollover,

    /// Identity proofing request submitted (RA).
    IdentityProofingSubmitted,
    /// Identity proofing approved by RA officer.
    IdentityProofingApproved,
    /// Identity proofing rejected by RA officer.
    IdentityProofingRejected,

    /// Security officer login.
    SecurityOfficerLogin,
    /// Security officer configuration change.
    SecurityOfficerConfigChange,
    /// Security officer role assignment.
    SecurityOfficerRoleAssigned,

    /// System startup.
    SystemStartup,
    /// System shutdown.
    SystemShutdown,
    /// Audit log integrity verification performed.
    AuditLogVerified,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| format!("{self:?}"));
        f.write_str(&s)
    }
}

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action: AuditAction,
    pub method: String,
    pub path: String,
    pub org_id: String,
    pub source_ip: String,
    pub status_code: u16,
    pub trace_id: String,
    pub duration_ms: u64,
    /// Optional domain-specific metadata (e.g., block height, DID, chaincode ID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    /// SHA-256 hash of the previous entry (hex). Empty string for the first entry.
    #[serde(default)]
    pub previous_hash: String,
    /// SHA-256(previous_hash + canonical entry data). Forms a tamper-evident chain.
    #[serde(default)]
    pub entry_hash: String,
}

impl AuditEntry {
    /// Canonical data for hashing (excludes previous_hash and entry_hash).
    fn canonical_data(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.timestamp,
            self.action,
            self.method,
            self.path,
            self.org_id,
            self.source_ip,
            self.status_code,
            self.trace_id,
            self.duration_ms,
            self.metadata.as_deref().unwrap_or(""),
        )
    }

    /// Compute the entry hash: SHA-256(previous_hash + canonical_data).
    pub fn compute_hash(&self) -> String {
        let input = format!("{}|{}", self.previous_hash, self.canonical_data());
        hex::encode(hash_with(HashAlgorithm::Sha256, input.as_bytes()))
    }

    /// Seal this entry with its hash chain link.
    pub fn seal(&mut self, previous_hash: &str) {
        self.previous_hash = previous_hash.to_string();
        self.entry_hash = self.compute_hash();
    }

    /// Verify this entry's hash is consistent with its data and previous_hash.
    pub fn verify(&self) -> bool {
        !self.entry_hash.is_empty() && self.entry_hash == self.compute_hash()
    }
}

/// Verify the integrity of an ordered sequence of audit entries.
/// Returns Ok(()) if the chain is valid, or Err with the index of the first broken link.
pub fn verify_audit_chain(entries: &[AuditEntry]) -> Result<(), usize> {
    for (i, entry) in entries.iter().enumerate() {
        if !entry.verify() {
            return Err(i);
        }
        if i > 0 && entry.previous_hash != entries[i - 1].entry_hash {
            return Err(i);
        }
    }
    Ok(())
}

/// Helper to emit a domain audit event without needing HTTP context.
pub fn emit_domain_event(
    store: &dyn AuditStore,
    action: AuditAction,
    org_id: &str,
    metadata: Option<String>,
) {
    let entry = AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        action,
        method: String::new(),
        path: String::new(),
        org_id: org_id.to_string(),
        source_ip: String::new(),
        status_code: 0,
        trace_id: uuid::Uuid::new_v4().to_string(),
        duration_ms: 0,
        metadata,
        previous_hash: String::new(),
        entry_hash: String::new(),
    };
    if let Err(e) = store.append(&entry) {
        log::error!("audit domain event failed: {e}");
    }
}

/// Convenience wrapper: emit if store is `Some`.
pub fn emit_if_present(
    store: &Option<Arc<dyn AuditStore>>,
    action: AuditAction,
    org_id: &str,
    metadata: Option<String>,
) {
    if let Some(s) = store {
        emit_domain_event(s.as_ref(), action, org_id, metadata);
    }
}

/// Trait for persisting and querying audit entries.
pub trait AuditStore: Send + Sync {
    /// Append an audit entry (append-only, never delete).
    fn append(&self, entry: &AuditEntry) -> StorageResult<()>;

    /// Query entries within a time range, optionally filtered by org_id and/or action.
    fn query(
        &self,
        from: Option<&str>,
        to: Option<&str>,
        org_id: Option<&str>,
        action: Option<&AuditAction>,
        limit: usize,
    ) -> StorageResult<Vec<AuditEntry>>;

    /// Export entries as CSV string.
    fn export_csv(&self, from: Option<&str>, to: Option<&str>) -> StorageResult<String> {
        let entries = self.query(from, to, None, None, usize::MAX)?;
        let mut csv = String::from(
            "timestamp,action,method,path,org_id,source_ip,status_code,trace_id,duration_ms,metadata,previous_hash,entry_hash\n",
        );
        for e in &entries {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                e.timestamp,
                e.action,
                e.method,
                e.path,
                e.org_id,
                e.source_ip,
                e.status_code,
                e.trace_id,
                e.duration_ms,
                e.metadata.as_deref().unwrap_or(""),
                e.previous_hash,
                e.entry_hash,
            ));
        }
        Ok(csv)
    }

    /// Count entries eligible for purge under the given retention policy.
    fn retention_status(
        &self,
        policy: &crate::audit_retention::AuditRetentionPolicy,
        now_secs: u64,
    ) -> StorageResult<(usize, usize)> {
        let entries = self.query(None, None, None, None, usize::MAX)?;
        let total = entries.len();
        let purgeable = entries
            .iter()
            .filter(|e| {
                chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                    .map(|dt| policy.is_purgeable(dt.timestamp() as u64, now_secs))
                    .unwrap_or(false)
            })
            .count();
        Ok((total, purgeable))
    }

    /// Purge entries older than the retention policy's max_retention_secs.
    /// Returns the number of entries removed.
    fn purge_expired(
        &self,
        policy: &crate::audit_retention::AuditRetentionPolicy,
        now_secs: u64,
    ) -> StorageResult<usize> {
        let _ = (policy, now_secs);
        Ok(0)
    }

    /// Export entries as JSON with hash chain metadata for independent verification.
    fn export_json(&self, from: Option<&str>, to: Option<&str>) -> StorageResult<String> {
        let entries = self.query(from, to, None, None, usize::MAX)?;
        let chain_valid = verify_audit_chain(&entries).is_ok();
        let export = serde_json::json!({
            "version": "1.0",
            "format": "goya-audit-export",
            "entry_count": entries.len(),
            "chain_valid": chain_valid,
            "first_hash": entries.first().map(|e| &e.entry_hash).unwrap_or(&String::new()),
            "last_hash": entries.last().map(|e| &e.entry_hash).unwrap_or(&String::new()),
            "entries": entries,
        });
        serde_json::to_string_pretty(&export)
            .map_err(|e| crate::storage::errors::StorageError::SerializationError(e.to_string()))
    }
}

/// In-memory audit store (for testing or when RocksDB is not configured).
pub struct MemoryAuditStore {
    entries: std::sync::Mutex<Vec<AuditEntry>>,
}

impl MemoryAuditStore {
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Default for MemoryAuditStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditStore for MemoryAuditStore {
    fn append(&self, entry: &AuditEntry) -> StorageResult<()> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut sealed = entry.clone();
        let prev_hash = entries.last().map(|e| e.entry_hash.as_str()).unwrap_or("");
        sealed.seal(prev_hash);
        entries.push(sealed);
        Ok(())
    }

    fn query(
        &self,
        from: Option<&str>,
        to: Option<&str>,
        org_id: Option<&str>,
        action: Option<&AuditAction>,
        limit: usize,
    ) -> StorageResult<Vec<AuditEntry>> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let filtered = entries
            .iter()
            .filter(|e| {
                if let Some(f) = from {
                    if e.timestamp.as_str() < f {
                        return false;
                    }
                }
                if let Some(t) = to {
                    if e.timestamp.as_str() > t {
                        return false;
                    }
                }
                if let Some(org) = org_id {
                    if e.org_id != org {
                        return false;
                    }
                }
                if let Some(act) = action {
                    if &e.action != act {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .cloned()
            .collect();
        Ok(filtered)
    }

    fn purge_expired(
        &self,
        policy: &crate::audit_retention::AuditRetentionPolicy,
        now_secs: u64,
    ) -> StorageResult<usize> {
        if !policy.auto_purge_enabled || policy.max_retention_secs == 0 {
            return Ok(0);
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let before = entries.len();
        entries.retain(|e| {
            let ts = chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                .map(|dt| dt.timestamp() as u64)
                .unwrap_or(0);
            !policy.is_purgeable(ts, now_secs)
        });
        let purged = before - entries.len();
        // Re-seal hash chain after purge to maintain integrity
        if purged > 0 {
            let mut prev_hash = String::new();
            for entry in entries.iter_mut() {
                entry.seal(&prev_hash);
                prev_hash = entry.entry_hash.clone();
            }
        }
        Ok(purged)
    }
}

/// Spawn a background task that periodically purges expired audit entries.
///
/// Runs every `interval` and purges entries older than the policy's
/// `max_retention_secs`. Set `shutdown` to `true` to stop the task.
pub fn spawn_auto_purge_task(
    store: std::sync::Arc<dyn AuditStore>,
    policy: crate::audit_retention::AuditRetentionPolicy,
    interval: std::time::Duration,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::JoinHandle<u64> {
    tokio::spawn(async move {
        let mut total_purged = 0u64;
        loop {
            tokio::time::sleep(interval).await;
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            if !policy.auto_purge_enabled {
                continue;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            match store.purge_expired(&policy, now) {
                Ok(n) if n > 0 => {
                    total_purged += n as u64;
                    tracing::info!(purged = n, total = total_purged, "audit auto-purge cycle");
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "audit auto-purge failed");
                }
            }
        }
        total_purged
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(ts: &str, org: &str, path: &str) -> AuditEntry {
        AuditEntry {
            timestamp: ts.to_string(),
            action: AuditAction::HttpRequest,
            method: "POST".to_string(),
            path: path.to_string(),
            org_id: org.to_string(),
            source_ip: "127.0.0.1".to_string(),
            status_code: 200,
            trace_id: "trace-1".to_string(),
            duration_ms: 5,
            metadata: None,
            previous_hash: String::new(),
            entry_hash: String::new(),
        }
    }

    fn make_domain_entry(ts: &str, org: &str, action: AuditAction, meta: &str) -> AuditEntry {
        AuditEntry {
            timestamp: ts.to_string(),
            action,
            method: String::new(),
            path: String::new(),
            org_id: org.to_string(),
            source_ip: String::new(),
            status_code: 0,
            trace_id: "trace-d".to_string(),
            duration_ms: 0,
            metadata: Some(meta.to_string()),
            previous_hash: String::new(),
            entry_hash: String::new(),
        }
    }

    #[test]
    fn append_and_query_all() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry(
                "2026-04-07T10:00:00Z",
                "org1",
                "/gateway/submit",
            ))
            .unwrap();
        store
            .append(&make_entry("2026-04-07T11:00:00Z", "org2", "/channels"))
            .unwrap();

        let all = store.query(None, None, None, None, 100).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn query_by_org_id() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry("2026-04-07T10:00:00Z", "org1", "/a"))
            .unwrap();
        store
            .append(&make_entry("2026-04-07T10:01:00Z", "org2", "/b"))
            .unwrap();
        store
            .append(&make_entry("2026-04-07T10:02:00Z", "org1", "/c"))
            .unwrap();

        let org1 = store.query(None, None, Some("org1"), None, 100).unwrap();
        assert_eq!(org1.len(), 2);
    }

    #[test]
    fn query_by_time_range() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry("2026-04-07T10:00:00Z", "org1", "/a"))
            .unwrap();
        store
            .append(&make_entry("2026-04-07T12:00:00Z", "org1", "/b"))
            .unwrap();
        store
            .append(&make_entry("2026-04-07T14:00:00Z", "org1", "/c"))
            .unwrap();

        let range = store
            .query(
                Some("2026-04-07T11:00:00Z"),
                Some("2026-04-07T13:00:00Z"),
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(range.len(), 1);
        assert_eq!(range[0].path, "/b");
    }

    #[test]
    fn query_by_action_type() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry("2026-04-07T10:00:00Z", "org1", "/a"))
            .unwrap();
        store
            .append(&make_domain_entry(
                "2026-04-07T10:01:00Z",
                "org1",
                AuditAction::BlockMined,
                "height=42",
            ))
            .unwrap();
        store
            .append(&make_domain_entry(
                "2026-04-07T10:02:00Z",
                "org1",
                AuditAction::DidRegistered,
                "did:goya:abc",
            ))
            .unwrap();

        let blocks = store
            .query(None, None, None, Some(&AuditAction::BlockMined), 100)
            .unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].metadata.as_deref(), Some("height=42"));

        let http = store
            .query(None, None, None, Some(&AuditAction::HttpRequest), 100)
            .unwrap();
        assert_eq!(http.len(), 1);
    }

    #[test]
    fn query_combined_filters() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_domain_entry(
                "2026-04-07T10:00:00Z",
                "org1",
                AuditAction::BlockMined,
                "h=1",
            ))
            .unwrap();
        store
            .append(&make_domain_entry(
                "2026-04-07T10:01:00Z",
                "org2",
                AuditAction::BlockMined,
                "h=2",
            ))
            .unwrap();
        store
            .append(&make_domain_entry(
                "2026-04-07T10:02:00Z",
                "org1",
                AuditAction::DidRegistered,
                "did:x",
            ))
            .unwrap();

        let result = store
            .query(
                None,
                None,
                Some("org1"),
                Some(&AuditAction::BlockMined),
                100,
            )
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].metadata.as_deref(), Some("h=1"));
    }

    #[test]
    fn export_csv_format() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry(
                "2026-04-07T10:00:00Z",
                "org1",
                "/gateway/submit",
            ))
            .unwrap();

        let csv = store.export_csv(None, None).unwrap();
        assert!(csv.starts_with("timestamp,action,method,path,org_id"));
        assert!(csv.contains("/gateway/submit"));
        assert!(csv.contains("http_request"));
    }

    #[test]
    fn query_respects_limit() {
        let store = MemoryAuditStore::new();
        for i in 0..10 {
            store
                .append(&make_entry(
                    &format!("2026-04-07T10:{i:02}:00Z"),
                    "org1",
                    "/a",
                ))
                .unwrap();
        }
        let limited = store.query(None, None, None, None, 3).unwrap();
        assert_eq!(limited.len(), 3);
    }

    #[test]
    fn emit_domain_event_appends_entry() {
        let store = MemoryAuditStore::new();
        emit_domain_event(
            &store,
            AuditAction::ChaincodeInstalled,
            "org1",
            Some("cc_id=mycc".to_string()),
        );
        let entries = store.query(None, None, None, None, 100).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, AuditAction::ChaincodeInstalled);
        assert_eq!(entries[0].metadata.as_deref(), Some("cc_id=mycc"));
    }

    #[test]
    fn emit_if_present_with_none_is_noop() {
        let store: Option<Arc<dyn AuditStore>> = None;
        emit_if_present(&store, AuditAction::BlockMined, "org1", None);
        // No panic — just a no-op.
    }

    #[test]
    fn emit_if_present_with_some_appends() {
        let store: Option<Arc<dyn AuditStore>> = Some(Arc::new(MemoryAuditStore::new()));
        emit_if_present(
            &store,
            AuditAction::DidRevoked,
            "org2",
            Some("did:x".to_string()),
        );
        let entries = store
            .as_ref()
            .unwrap()
            .query(None, None, None, Some(&AuditAction::DidRevoked), 100)
            .unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn audit_action_display() {
        assert_eq!(AuditAction::BlockMined.to_string(), "block_mined");
        assert_eq!(AuditAction::HttpRequest.to_string(), "http_request");
        assert_eq!(
            AuditAction::ChaincodeInstalled.to_string(),
            "chaincode_installed"
        );
    }

    // ── ETSI audit event categories ────────────────────────────────

    #[test]
    fn etsi_key_lifecycle_actions_display() {
        assert_eq!(AuditAction::KeyGenerated.to_string(), "key_generated");
        assert_eq!(AuditAction::KeyActivated.to_string(), "key_activated");
        assert_eq!(AuditAction::KeyDeactivated.to_string(), "key_deactivated");
        assert_eq!(AuditAction::KeyDestroyed.to_string(), "key_destroyed");
        assert_eq!(AuditAction::KeyBackedUp.to_string(), "key_backed_up");
        assert_eq!(AuditAction::KeyRestored.to_string(), "key_restored");
    }

    #[test]
    fn etsi_certificate_actions_display() {
        assert_eq!(
            AuditAction::CertificateIssued.to_string(),
            "certificate_issued"
        );
        assert_eq!(
            AuditAction::CertificateRenewed.to_string(),
            "certificate_renewed"
        );
        assert_eq!(
            AuditAction::CertificateSuspended.to_string(),
            "certificate_suspended"
        );
        assert_eq!(
            AuditAction::CertificateRevoked.to_string(),
            "certificate_revoked"
        );
    }

    #[test]
    fn etsi_revocation_service_actions_display() {
        assert_eq!(AuditAction::CrlPublished.to_string(), "crl_published");
        assert_eq!(
            AuditAction::OcspResponseGenerated.to_string(),
            "ocsp_response_generated"
        );
    }

    #[test]
    fn etsi_tsa_actions_display() {
        assert_eq!(AuditAction::TimestampIssued.to_string(), "timestamp_issued");
        assert_eq!(AuditAction::TsaKeyRollover.to_string(), "tsa_key_rollover");
    }

    #[test]
    fn etsi_ra_actions_display() {
        assert_eq!(
            AuditAction::IdentityProofingSubmitted.to_string(),
            "identity_proofing_submitted"
        );
        assert_eq!(
            AuditAction::IdentityProofingApproved.to_string(),
            "identity_proofing_approved"
        );
        assert_eq!(
            AuditAction::IdentityProofingRejected.to_string(),
            "identity_proofing_rejected"
        );
    }

    #[test]
    fn etsi_security_officer_actions_display() {
        assert_eq!(
            AuditAction::SecurityOfficerLogin.to_string(),
            "security_officer_login"
        );
        assert_eq!(
            AuditAction::SecurityOfficerConfigChange.to_string(),
            "security_officer_config_change"
        );
        assert_eq!(
            AuditAction::SecurityOfficerRoleAssigned.to_string(),
            "security_officer_role_assigned"
        );
    }

    #[test]
    fn etsi_system_actions_display() {
        assert_eq!(AuditAction::SystemStartup.to_string(), "system_startup");
        assert_eq!(AuditAction::SystemShutdown.to_string(), "system_shutdown");
        assert_eq!(
            AuditAction::AuditLogVerified.to_string(),
            "audit_log_verified"
        );
    }

    #[test]
    fn etsi_actions_queryable() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_domain_entry(
                "2026-01-01T00:00:00Z",
                "org1",
                AuditAction::KeyGenerated,
                "algo=Ed25519",
            ))
            .unwrap();
        store
            .append(&make_domain_entry(
                "2026-01-01T00:01:00Z",
                "org1",
                AuditAction::CertificateIssued,
                "did:goya:sub1",
            ))
            .unwrap();
        store
            .append(&make_domain_entry(
                "2026-01-01T00:02:00Z",
                "org1",
                AuditAction::TimestampIssued,
                "serial=42",
            ))
            .unwrap();

        let keys = store
            .query(None, None, None, Some(&AuditAction::KeyGenerated), 100)
            .unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].metadata.as_deref(), Some("algo=Ed25519"));

        let certs = store
            .query(None, None, None, Some(&AuditAction::CertificateIssued), 100)
            .unwrap();
        assert_eq!(certs.len(), 1);

        let tsa = store
            .query(None, None, None, Some(&AuditAction::TimestampIssued), 100)
            .unwrap();
        assert_eq!(tsa.len(), 1);
    }

    #[test]
    fn etsi_actions_in_hash_chain() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_domain_entry(
                "2026-01-01T00:00:00Z",
                "org1",
                AuditAction::SecurityOfficerLogin,
                "officer=admin",
            ))
            .unwrap();
        store
            .append(&make_domain_entry(
                "2026-01-01T00:01:00Z",
                "org1",
                AuditAction::KeyGenerated,
                "root_ca",
            ))
            .unwrap();
        store
            .append(&make_domain_entry(
                "2026-01-01T00:02:00Z",
                "org1",
                AuditAction::CertificateIssued,
                "sub=did:goya:x",
            ))
            .unwrap();

        let entries = store.query(None, None, None, None, 100).unwrap();
        assert!(verify_audit_chain(&entries).is_ok());
    }

    #[test]
    fn etsi_actions_serialization_roundtrip() {
        let actions = vec![
            AuditAction::KeyGenerated,
            AuditAction::CertificateIssued,
            AuditAction::CrlPublished,
            AuditAction::OcspResponseGenerated,
            AuditAction::TimestampIssued,
            AuditAction::IdentityProofingApproved,
            AuditAction::SecurityOfficerLogin,
            AuditAction::SystemStartup,
            AuditAction::AuditLogVerified,
        ];
        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let parsed: AuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, action);
        }
    }

    // ── Hash chain tamper evidence ──────────────────────────────────

    #[test]
    fn appended_entries_are_sealed() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry("2026-01-01T00:00:00Z", "org1", "/a"))
            .unwrap();
        let entries = store.query(None, None, None, None, 10).unwrap();
        assert!(!entries[0].entry_hash.is_empty());
        assert!(entries[0].previous_hash.is_empty());
    }

    #[test]
    fn hash_chain_links_entries() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry("2026-01-01T00:00:00Z", "org1", "/a"))
            .unwrap();
        store
            .append(&make_entry("2026-01-01T00:01:00Z", "org1", "/b"))
            .unwrap();
        store
            .append(&make_entry("2026-01-01T00:02:00Z", "org1", "/c"))
            .unwrap();

        let entries = store.query(None, None, None, None, 10).unwrap();
        assert_eq!(entries[1].previous_hash, entries[0].entry_hash);
        assert_eq!(entries[2].previous_hash, entries[1].entry_hash);
    }

    #[test]
    fn valid_chain_verifies() {
        let store = MemoryAuditStore::new();
        for i in 0..5 {
            store
                .append(&make_entry(
                    &format!("2026-01-01T00:{i:02}:00Z"),
                    "org1",
                    "/x",
                ))
                .unwrap();
        }
        let entries = store.query(None, None, None, None, 100).unwrap();
        assert!(verify_audit_chain(&entries).is_ok());
    }

    #[test]
    fn tampered_entry_detected() {
        let store = MemoryAuditStore::new();
        for i in 0..3 {
            store
                .append(&make_entry(
                    &format!("2026-01-01T00:{i:02}:00Z"),
                    "org1",
                    "/x",
                ))
                .unwrap();
        }
        let mut entries = store.query(None, None, None, None, 100).unwrap();
        entries[1].path = "/TAMPERED".to_string();
        assert_eq!(verify_audit_chain(&entries), Err(1));
    }

    #[test]
    fn broken_chain_link_detected() {
        let store = MemoryAuditStore::new();
        for i in 0..3 {
            store
                .append(&make_entry(
                    &format!("2026-01-01T00:{i:02}:00Z"),
                    "org1",
                    "/x",
                ))
                .unwrap();
        }
        let mut entries = store.query(None, None, None, None, 100).unwrap();
        entries[2].previous_hash = "ff".repeat(32);
        entries[2].entry_hash = entries[2].compute_hash();
        assert_eq!(verify_audit_chain(&entries), Err(2));
    }

    #[test]
    fn single_entry_verifies() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry("2026-01-01T00:00:00Z", "org1", "/a"))
            .unwrap();
        let entries = store.query(None, None, None, None, 10).unwrap();
        assert!(verify_audit_chain(&entries).is_ok());
    }

    #[test]
    fn empty_chain_verifies() {
        let entries: Vec<AuditEntry> = vec![];
        assert!(verify_audit_chain(&entries).is_ok());
    }

    #[test]
    fn entry_hash_is_deterministic() {
        let mut e1 = make_entry("2026-01-01T00:00:00Z", "org1", "/a");
        e1.seal("");
        let mut e2 = make_entry("2026-01-01T00:00:00Z", "org1", "/a");
        e2.seal("");
        assert_eq!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn different_data_different_hash() {
        let mut e1 = make_entry("2026-01-01T00:00:00Z", "org1", "/a");
        e1.seal("");
        let mut e2 = make_entry("2026-01-01T00:00:00Z", "org1", "/b");
        e2.seal("");
        assert_ne!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn entry_verify_method() {
        let mut entry = make_entry("2026-01-01T00:00:00Z", "org1", "/a");
        entry.seal("");
        assert!(entry.verify());
        entry.status_code = 500;
        assert!(!entry.verify());
    }

    // ── JSON + CSV export ─────────────────────────────────────────────

    #[test]
    fn export_json_structure() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry("2026-01-01T00:00:00Z", "org1", "/a"))
            .unwrap();
        store
            .append(&make_entry("2026-01-01T00:01:00Z", "org1", "/b"))
            .unwrap();

        let json_str = store.export_json(None, None).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(doc["version"], "1.0");
        assert_eq!(doc["format"], "goya-audit-export");
        assert_eq!(doc["entry_count"], 2);
        assert_eq!(doc["chain_valid"], true);
        assert!(!doc["first_hash"].as_str().unwrap().is_empty());
        assert!(!doc["last_hash"].as_str().unwrap().is_empty());
        assert_ne!(doc["first_hash"], doc["last_hash"]);
        assert_eq!(doc["entries"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn export_json_entries_have_hashes() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry("2026-01-01T00:00:00Z", "org1", "/a"))
            .unwrap();

        let json_str = store.export_json(None, None).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let entry = &doc["entries"][0];
        assert!(!entry["entry_hash"].as_str().unwrap().is_empty());
        assert!(entry["previous_hash"].as_str().unwrap().is_empty());
    }

    #[test]
    fn export_json_chain_valid_false_on_tamper() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry("2026-01-01T00:00:00Z", "org1", "/a"))
            .unwrap();
        // Tamper internally
        {
            let mut entries = store.entries.lock().unwrap();
            entries[0].path = "/TAMPERED".to_string();
        }
        let json_str = store.export_json(None, None).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(doc["chain_valid"], false);
    }

    #[test]
    fn export_json_empty_store() {
        let store = MemoryAuditStore::new();
        let json_str = store.export_json(None, None).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(doc["entry_count"], 0);
        assert_eq!(doc["chain_valid"], true);
        assert!(doc["entries"].as_array().unwrap().is_empty());
    }

    #[test]
    fn export_json_with_metadata() {
        let store = MemoryAuditStore::new();
        emit_domain_event(
            &store,
            AuditAction::KeyGenerated,
            "org1",
            Some("algo=Ed25519".to_string()),
        );
        let json_str = store.export_json(None, None).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(doc["entries"][0]["metadata"], "algo=Ed25519");
    }

    #[test]
    fn export_csv_includes_metadata_and_hashes() {
        let store = MemoryAuditStore::new();
        emit_domain_event(
            &store,
            AuditAction::KeyGenerated,
            "org1",
            Some("algo=Ed25519".to_string()),
        );
        let csv = store.export_csv(None, None).unwrap();
        assert!(csv.contains("previous_hash,entry_hash"));
        assert!(csv.contains("algo=Ed25519"));
        let lines: Vec<&str> = csv.lines().collect();
        // Header has 12 columns
        assert_eq!(lines[0].matches(',').count(), 11);
        // Data row has 12 columns too
        assert_eq!(lines[1].matches(',').count(), 11);
    }

    #[test]
    fn export_json_independently_verifiable() {
        let store = MemoryAuditStore::new();
        for i in 0..5 {
            store
                .append(&make_entry(
                    &format!("2026-01-01T00:{i:02}:00Z"),
                    "org1",
                    "/x",
                ))
                .unwrap();
        }
        let json_str = store.export_json(None, None).unwrap();
        // Parse back and verify chain independently
        let doc: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let entries: Vec<AuditEntry> = serde_json::from_value(doc["entries"].clone()).unwrap();
        assert!(verify_audit_chain(&entries).is_ok());
    }

    #[test]
    fn purge_expired_removes_old_entries() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry("2020-01-01T00:00:00Z", "org1", "/old"))
            .unwrap();
        store
            .append(&make_entry("2026-07-01T00:00:00Z", "org1", "/new"))
            .unwrap();

        let policy = crate::audit_retention::AuditRetentionPolicy {
            min_retention_secs: 365 * 24 * 3600,
            max_retention_secs: 2 * 365 * 24 * 3600,
            auto_purge_enabled: true,
        };
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .timestamp() as u64;

        let purged = store.purge_expired(&policy, now).unwrap();
        assert_eq!(purged, 1);
        let remaining = store.query(None, None, None, None, 100).unwrap();
        assert_eq!(remaining.len(), 1);
        assert!(remaining[0].path.contains("/new"));
    }

    #[test]
    fn purge_disabled_does_nothing() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry("2020-01-01T00:00:00Z", "org1", "/old"))
            .unwrap();

        let policy = crate::audit_retention::AuditRetentionPolicy {
            min_retention_secs: 365 * 24 * 3600,
            max_retention_secs: 2 * 365 * 24 * 3600,
            auto_purge_enabled: false,
        };
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .timestamp() as u64;

        let purged = store.purge_expired(&policy, now).unwrap();
        assert_eq!(purged, 0);
    }

    #[test]
    fn purge_max_zero_does_nothing() {
        let store = MemoryAuditStore::new();
        store
            .append(&make_entry("2020-01-01T00:00:00Z", "org1", "/old"))
            .unwrap();

        let policy = crate::audit_retention::AuditRetentionPolicy {
            min_retention_secs: 365 * 24 * 3600,
            max_retention_secs: 0,
            auto_purge_enabled: true,
        };
        let purged = store.purge_expired(&policy, 2_000_000_000).unwrap();
        assert_eq!(purged, 0);
    }

    #[tokio::test]
    async fn auto_purge_task_runs() {
        let store = std::sync::Arc::new(MemoryAuditStore::new());
        store
            .append(&make_entry("2020-01-01T00:00:00Z", "org1", "/old"))
            .unwrap();
        store
            .append(&make_entry("2026-07-01T00:00:00Z", "org1", "/new"))
            .unwrap();

        let policy = crate::audit_retention::AuditRetentionPolicy {
            min_retention_secs: 365 * 24 * 3600,
            max_retention_secs: 2 * 365 * 24 * 3600,
            auto_purge_enabled: true,
        };
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let handle = spawn_auto_purge_task(
            store.clone(),
            policy,
            std::time::Duration::from_millis(50),
            shutdown.clone(),
        );

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        let total = handle.await.unwrap();
        assert!(total >= 1);
        let remaining = store.query(None, None, None, None, 100).unwrap();
        assert_eq!(remaining.len(), 1);
    }
}
