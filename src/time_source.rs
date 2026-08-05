//! Trusted time source abstraction for regulatory compliance.
//!
//! TSA (RFC 3161) and audit logging require a reliable time source.
//! This module abstracts time acquisition so the system can:
//! - Use the OS clock (default)
//! - Validate NTP synchronization status
//! - Use a simulated clock for testing
//! - Record which time source was used (for audit)

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum acceptable drift from a trusted source (seconds).
const DEFAULT_MAX_DRIFT_SECS: u64 = 5;

/// Time source identifier for audit trails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeSourceType {
    /// OS system clock (no NTP validation).
    System,
    /// NTP-synchronized system clock (drift validated).
    Ntp,
    /// Simulated clock for testing.
    Simulated,
}

impl std::fmt::Display for TimeSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => write!(f, "system"),
            Self::Ntp => write!(f, "ntp"),
            Self::Simulated => write!(f, "simulated"),
        }
    }
}

/// A timestamped value with its source metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedTimestamp {
    /// UNIX seconds (UTC).
    pub unix_secs: u64,
    /// Which time source produced this timestamp.
    pub source: TimeSourceType,
    /// Estimated accuracy in seconds (0 = unknown).
    pub accuracy_secs: u32,
}

/// Trait for pluggable time sources.
pub trait TimeSource: Send + Sync {
    /// Get the current time as a trusted timestamp.
    fn now(&self) -> TrustedTimestamp;

    /// The type of this source.
    fn source_type(&self) -> TimeSourceType;

    /// Validate that this source is within acceptable drift.
    fn validate(&self) -> Result<(), TimeError>;
}

/// Errors from time source operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeError {
    /// Clock drift exceeds maximum tolerance.
    DriftExceeded { drift_secs: u64, max_secs: u64 },
    /// NTP service is not synchronized.
    NtpNotSynced(String),
    /// Time source unavailable.
    Unavailable(String),
}

impl std::fmt::Display for TimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DriftExceeded {
                drift_secs,
                max_secs,
            } => write!(f, "clock drift {drift_secs}s exceeds max {max_secs}s"),
            Self::NtpNotSynced(msg) => write!(f, "NTP not synchronized: {msg}"),
            Self::Unavailable(msg) => write!(f, "time source unavailable: {msg}"),
        }
    }
}

impl std::error::Error for TimeError {}

// ── SystemTimeSource ────────────────────────────────────────────────────────

/// Default time source using the OS system clock.
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now(&self) -> TrustedTimestamp {
        TrustedTimestamp {
            unix_secs: system_now(),
            source: TimeSourceType::System,
            accuracy_secs: 0,
        }
    }

    fn source_type(&self) -> TimeSourceType {
        TimeSourceType::System
    }

    fn validate(&self) -> Result<(), TimeError> {
        let t = system_now();
        if t < 1_700_000_000 {
            return Err(TimeError::Unavailable(
                "system clock appears unset (before 2023)".into(),
            ));
        }
        Ok(())
    }
}

// ── NtpTimeSource ───────────────────────────────────────────────────────────

/// NTP-validated time source.
///
/// Uses the OS clock but validates that NTP synchronization is active
/// and drift is within tolerance. The actual NTP sync is handled by
/// the OS (ntpd/chrony/systemd-timesyncd).
pub struct NtpTimeSource {
    max_drift_secs: u64,
    ntp_offset_secs: AtomicU64,
    synced: std::sync::atomic::AtomicBool,
}

impl NtpTimeSource {
    pub fn new(max_drift_secs: u64) -> Self {
        Self {
            max_drift_secs,
            ntp_offset_secs: AtomicU64::new(0),
            synced: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Record NTP sync status (called by an external NTP checker).
    pub fn set_sync_status(&self, synced: bool, offset_secs: u64) {
        self.synced
            .store(synced, std::sync::atomic::Ordering::SeqCst);
        self.ntp_offset_secs
            .store(offset_secs, std::sync::atomic::Ordering::SeqCst);
    }

    /// Check if NTP is currently synchronized.
    pub fn is_synced(&self) -> bool {
        self.synced.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Current NTP offset in seconds.
    pub fn offset_secs(&self) -> u64 {
        self.ntp_offset_secs
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Default for NtpTimeSource {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_DRIFT_SECS)
    }
}

impl TimeSource for NtpTimeSource {
    fn now(&self) -> TrustedTimestamp {
        TrustedTimestamp {
            unix_secs: system_now(),
            source: TimeSourceType::Ntp,
            accuracy_secs: self.ntp_offset_secs.load(Ordering::SeqCst) as u32,
        }
    }

    fn source_type(&self) -> TimeSourceType {
        TimeSourceType::Ntp
    }

    fn validate(&self) -> Result<(), TimeError> {
        if !self.is_synced() {
            return Err(TimeError::NtpNotSynced(
                "NTP sync status not confirmed".into(),
            ));
        }
        let offset = self.offset_secs();
        if offset > self.max_drift_secs {
            return Err(TimeError::DriftExceeded {
                drift_secs: offset,
                max_secs: self.max_drift_secs,
            });
        }
        Ok(())
    }
}

// ── SimulatedTimeSource ─────────────────────────────────────────────────────

/// Deterministic time source for testing.
pub struct SimulatedTimeSource {
    current: AtomicU64,
}

impl SimulatedTimeSource {
    pub fn new(start_secs: u64) -> Self {
        Self {
            current: AtomicU64::new(start_secs),
        }
    }

    /// Advance the simulated clock by `secs` seconds.
    pub fn advance(&self, secs: u64) {
        self.current.fetch_add(secs, Ordering::SeqCst);
    }

    /// Set the simulated clock to a specific time.
    pub fn set(&self, unix_secs: u64) {
        self.current.store(unix_secs, Ordering::SeqCst);
    }

    /// Get current simulated time.
    pub fn current(&self) -> u64 {
        self.current.load(Ordering::SeqCst)
    }
}

impl TimeSource for SimulatedTimeSource {
    fn now(&self) -> TrustedTimestamp {
        TrustedTimestamp {
            unix_secs: self.current.load(Ordering::SeqCst),
            source: TimeSourceType::Simulated,
            accuracy_secs: 0,
        }
    }

    fn source_type(&self) -> TimeSourceType {
        TimeSourceType::Simulated
    }

    fn validate(&self) -> Result<(), TimeError> {
        Ok(())
    }
}

fn system_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SystemTimeSource ────────────────────────────────────────────

    #[test]
    fn system_returns_recent_timestamp() {
        let src = SystemTimeSource;
        let ts = src.now();
        assert!(ts.unix_secs > 1_700_000_000);
        assert_eq!(ts.source, TimeSourceType::System);
    }

    #[test]
    fn system_validates_ok() {
        let src = SystemTimeSource;
        assert!(src.validate().is_ok());
    }

    #[test]
    fn system_source_type() {
        assert_eq!(SystemTimeSource.source_type(), TimeSourceType::System);
    }

    // ── NtpTimeSource ───────────────────────────────────────────────

    #[test]
    fn ntp_not_synced_by_default() {
        let src = NtpTimeSource::default();
        assert!(!src.is_synced());
        assert!(src.validate().is_err());
    }

    #[test]
    fn ntp_validates_when_synced_and_low_drift() {
        let src = NtpTimeSource::new(5);
        src.set_sync_status(true, 1);
        assert!(src.is_synced());
        assert!(src.validate().is_ok());
    }

    #[test]
    fn ntp_rejects_high_drift() {
        let src = NtpTimeSource::new(5);
        src.set_sync_status(true, 10);
        let err = src.validate().unwrap_err();
        match err {
            TimeError::DriftExceeded {
                drift_secs,
                max_secs,
            } => {
                assert_eq!(drift_secs, 10);
                assert_eq!(max_secs, 5);
            }
            _ => panic!("expected DriftExceeded"),
        }
    }

    #[test]
    fn ntp_rejects_not_synced() {
        let src = NtpTimeSource::new(5);
        src.set_sync_status(false, 0);
        assert!(matches!(src.validate(), Err(TimeError::NtpNotSynced(_))));
    }

    #[test]
    fn ntp_returns_ntp_source_type() {
        let src = NtpTimeSource::default();
        assert_eq!(src.source_type(), TimeSourceType::Ntp);
        let ts = src.now();
        assert_eq!(ts.source, TimeSourceType::Ntp);
    }

    #[test]
    fn ntp_offset_recorded_in_accuracy() {
        let src = NtpTimeSource::new(10);
        src.set_sync_status(true, 3);
        let ts = src.now();
        assert_eq!(ts.accuracy_secs, 3);
    }

    #[test]
    fn ntp_sync_status_can_be_toggled() {
        let src = NtpTimeSource::new(5);
        src.set_sync_status(true, 1);
        assert!(src.validate().is_ok());
        src.set_sync_status(false, 0);
        assert!(src.validate().is_err());
        src.set_sync_status(true, 0);
        assert!(src.validate().is_ok());
    }

    // ── SimulatedTimeSource ─────────────────────────────────────────

    #[test]
    fn simulated_starts_at_given_time() {
        let src = SimulatedTimeSource::new(1_700_000_000);
        let ts = src.now();
        assert_eq!(ts.unix_secs, 1_700_000_000);
        assert_eq!(ts.source, TimeSourceType::Simulated);
    }

    #[test]
    fn simulated_advance() {
        let src = SimulatedTimeSource::new(1000);
        src.advance(60);
        assert_eq!(src.current(), 1060);
        src.advance(30);
        assert_eq!(src.current(), 1090);
    }

    #[test]
    fn simulated_set() {
        let src = SimulatedTimeSource::new(1000);
        src.set(2000);
        assert_eq!(src.now().unix_secs, 2000);
    }

    #[test]
    fn simulated_always_validates() {
        let src = SimulatedTimeSource::new(0);
        assert!(src.validate().is_ok());
    }

    #[test]
    fn simulated_source_type() {
        assert_eq!(
            SimulatedTimeSource::new(0).source_type(),
            TimeSourceType::Simulated
        );
    }

    // ── Trait object usage ──────────────────────────────────────────

    #[test]
    fn trait_object_system() {
        let src: Box<dyn TimeSource> = Box::new(SystemTimeSource);
        let ts = src.now();
        assert!(ts.unix_secs > 0);
        assert_eq!(src.source_type(), TimeSourceType::System);
    }

    #[test]
    fn trait_object_simulated() {
        let src: Box<dyn TimeSource> = Box::new(SimulatedTimeSource::new(42));
        assert_eq!(src.now().unix_secs, 42);
    }

    #[test]
    fn trait_object_ntp() {
        let ntp = NtpTimeSource::new(10);
        ntp.set_sync_status(true, 0);
        let src: Box<dyn TimeSource> = Box::new(ntp);
        assert!(src.validate().is_ok());
    }

    // ── TrustedTimestamp ────────────────────────────────────────────

    #[test]
    fn trusted_timestamp_serialization() {
        let ts = TrustedTimestamp {
            unix_secs: 1_700_000_000,
            source: TimeSourceType::Ntp,
            accuracy_secs: 1,
        };
        let json = serde_json::to_string(&ts).unwrap();
        let parsed: TrustedTimestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.unix_secs, 1_700_000_000);
        assert_eq!(parsed.source, TimeSourceType::Ntp);
        assert_eq!(parsed.accuracy_secs, 1);
    }

    #[test]
    fn time_error_display() {
        let err = TimeError::DriftExceeded {
            drift_secs: 10,
            max_secs: 5,
        };
        assert!(err.to_string().contains("10s"));
        assert!(err.to_string().contains("5s"));
    }

    #[test]
    fn time_source_type_display() {
        assert_eq!(TimeSourceType::System.to_string(), "system");
        assert_eq!(TimeSourceType::Ntp.to_string(), "ntp");
        assert_eq!(TimeSourceType::Simulated.to_string(), "simulated");
    }
}
