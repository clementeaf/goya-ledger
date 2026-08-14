//! Audit log retention enforcement.
//!
//! ETSI TS 102 042 and Chilean regulations require audit log retention
//! for a minimum period (typically 7 years). This module provides:
//! - Configurable retention policy for audit entries
//! - Expiration checking
//! - Purge of entries older than the retention window

use serde::{Deserialize, Serialize};

/// Default retention period: 7 years in seconds (Chile, ETSI TS 102 042).
pub const DEFAULT_RETENTION_SECS: u64 = 7 * 365 * 24 * 3600;

/// UAE retention period: 15 years in seconds (Federal Decree-Law 46/2021 Art. 10).
pub const UAE_RETENTION_SECS: u64 = 15 * 365 * 24 * 3600;

/// Audit log retention policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRetentionPolicy {
    /// Minimum retention period in seconds. Entries younger than this
    /// must never be purged. Default: 7 years.
    pub min_retention_secs: u64,
    /// Maximum retention period in seconds. Entries older than this
    /// are eligible for archival/purge. 0 = retain indefinitely.
    pub max_retention_secs: u64,
    /// Whether automatic purge is enabled.
    pub auto_purge_enabled: bool,
}

impl Default for AuditRetentionPolicy {
    fn default() -> Self {
        Self {
            min_retention_secs: DEFAULT_RETENTION_SECS,
            max_retention_secs: 0,
            auto_purge_enabled: false,
        }
    }
}

impl AuditRetentionPolicy {
    /// Create a policy with a specific minimum retention period.
    pub fn with_min_retention_years(years: u32) -> Self {
        Self {
            min_retention_secs: u64::from(years) * 365 * 24 * 3600,
            ..Default::default()
        }
    }

    /// Check if an entry with the given timestamp is within the retention window.
    pub fn is_retained(&self, entry_timestamp_secs: u64, now_secs: u64) -> bool {
        if now_secs < entry_timestamp_secs {
            return true;
        }
        let age = now_secs - entry_timestamp_secs;
        age < self.min_retention_secs
    }

    /// Check if an entry is eligible for purge (older than max_retention).
    pub fn is_purgeable(&self, entry_timestamp_secs: u64, now_secs: u64) -> bool {
        if self.max_retention_secs == 0 {
            return false;
        }
        if now_secs < entry_timestamp_secs {
            return false;
        }
        let age = now_secs - entry_timestamp_secs;
        age > self.max_retention_secs
    }

    /// Filter a list of entries, returning only those within retention.
    pub fn filter_retained<'a>(
        &self,
        entries: &'a [crate::audit::AuditEntry],
        now_secs: u64,
    ) -> Vec<&'a crate::audit::AuditEntry> {
        entries
            .iter()
            .filter(|e| {
                let ts = parse_timestamp(&e.timestamp);
                self.is_retained(ts, now_secs)
            })
            .collect()
    }

    /// Count entries that are purgeable.
    pub fn count_purgeable(&self, entries: &[crate::audit::AuditEntry], now_secs: u64) -> usize {
        entries
            .iter()
            .filter(|e| {
                let ts = parse_timestamp(&e.timestamp);
                self.is_purgeable(ts, now_secs)
            })
            .count()
    }
}

/// Parse an RFC 3339 timestamp to UNIX seconds (best-effort).
fn parse_timestamp(ts: &str) -> u64 {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.timestamp() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditAction, AuditEntry};

    fn entry_at(ts: &str) -> AuditEntry {
        AuditEntry {
            timestamp: ts.to_string(),
            action: AuditAction::HttpRequest,
            method: String::new(),
            path: String::new(),
            org_id: String::new(),
            source_ip: String::new(),
            status_code: 200,
            trace_id: String::new(),
            duration_ms: 0,
            metadata: None,
            previous_hash: String::new(),
            entry_hash: String::new(),
        }
    }

    #[test]
    fn default_retention_is_7_years() {
        let policy = AuditRetentionPolicy::default();
        assert_eq!(policy.min_retention_secs, 7 * 365 * 24 * 3600);
        assert_eq!(policy.max_retention_secs, 0);
        assert!(!policy.auto_purge_enabled);
    }

    #[test]
    fn with_min_retention_years() {
        let policy = AuditRetentionPolicy::with_min_retention_years(10);
        assert_eq!(policy.min_retention_secs, 10 * 365 * 24 * 3600);
    }

    #[test]
    fn recent_entry_is_retained() {
        let policy = AuditRetentionPolicy::default();
        let now = 1_700_000_000;
        let recent = now - 3600;
        assert!(policy.is_retained(recent, now));
    }

    #[test]
    fn old_entry_not_retained() {
        let policy = AuditRetentionPolicy::with_min_retention_years(1);
        let now = 1_700_000_000;
        let old = now - (2 * 365 * 24 * 3600);
        assert!(!policy.is_retained(old, now));
    }

    #[test]
    fn entry_exactly_at_boundary_is_retained() {
        let policy = AuditRetentionPolicy::with_min_retention_years(1);
        let now = 1_700_000_000;
        let boundary = now - (365 * 24 * 3600) + 1;
        assert!(policy.is_retained(boundary, now));
    }

    #[test]
    fn future_entry_is_retained() {
        let policy = AuditRetentionPolicy::default();
        assert!(policy.is_retained(2_000_000_000, 1_700_000_000));
    }

    #[test]
    fn not_purgeable_when_max_is_zero() {
        let policy = AuditRetentionPolicy::default();
        assert!(!policy.is_purgeable(0, 2_000_000_000));
    }

    #[test]
    fn purgeable_when_older_than_max() {
        let policy = AuditRetentionPolicy {
            max_retention_secs: 365 * 24 * 3600,
            ..Default::default()
        };
        let now = 1_700_000_000;
        let old = now - (2 * 365 * 24 * 3600);
        assert!(policy.is_purgeable(old, now));
    }

    #[test]
    fn not_purgeable_when_within_max() {
        let policy = AuditRetentionPolicy {
            max_retention_secs: 365 * 24 * 3600,
            ..Default::default()
        };
        let now = 1_700_000_000;
        let recent = now - 3600;
        assert!(!policy.is_purgeable(recent, now));
    }

    #[test]
    fn filter_retained_entries() {
        let policy = AuditRetentionPolicy::with_min_retention_years(1);
        let entries = vec![
            entry_at("2020-01-01T00:00:00Z"),
            entry_at("2026-01-01T00:00:00Z"),
            entry_at("2026-06-01T00:00:00Z"),
        ];
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .timestamp() as u64;
        let retained = policy.filter_retained(&entries, now);
        assert_eq!(retained.len(), 2);
    }

    #[test]
    fn count_purgeable_entries() {
        let policy = AuditRetentionPolicy {
            min_retention_secs: 365 * 24 * 3600,
            max_retention_secs: 2 * 365 * 24 * 3600,
            auto_purge_enabled: false,
        };
        let entries = vec![
            entry_at("2020-01-01T00:00:00Z"),
            entry_at("2023-01-01T00:00:00Z"),
            entry_at("2026-06-01T00:00:00Z"),
        ];
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .timestamp() as u64;
        let count = policy.count_purgeable(&entries, now);
        assert_eq!(count, 2);
    }

    #[test]
    fn serialization_roundtrip() {
        let policy = AuditRetentionPolicy::with_min_retention_years(5);
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: AuditRetentionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.min_retention_secs, 5 * 365 * 24 * 3600);
    }
}
