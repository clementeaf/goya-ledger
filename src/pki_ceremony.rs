//! Key Ceremony — formal procedure for CA key generation and activation.
//!
//! ETSI TS 102 042 and the Chilean PSC accreditation guide require that
//! CA key generation follows a documented ceremony with witnesses,
//! split custody, and an auditable record.

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use serde::{Deserialize, Serialize};

/// Role of a participant in the ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyRole {
    /// Ceremony administrator (leads the procedure).
    Administrator,
    /// Key custodian (holds a share of the split key).
    Custodian,
    /// Independent witness (observes and attests).
    Witness,
    /// Auditor (verifies compliance).
    Auditor,
    /// Notary (provides legal attestation).
    Notary,
}

impl std::fmt::Display for CeremonyRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Administrator => write!(f, "administrator"),
            Self::Custodian => write!(f, "custodian"),
            Self::Witness => write!(f, "witness"),
            Self::Auditor => write!(f, "auditor"),
            Self::Notary => write!(f, "notary"),
        }
    }
}

/// A participant in the key ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyParticipant {
    pub name: String,
    pub role: CeremonyRole,
    pub did: Option<String>,
    pub organization: Option<String>,
}

/// Steps in the key ceremony procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyStep {
    /// Verify secure environment (air-gapped, physical security).
    EnvironmentCheck,
    /// Generate the CA key pair.
    KeyGeneration,
    /// Witness key generation (participants attest).
    WitnessAttestation,
    /// Split the private key into custodian shares (M-of-N).
    KeySplit,
    /// Store key shares in separate secure locations.
    ShareDistribution,
    /// Verify the public key and certificate.
    KeyVerification,
    /// Activate the CA for operational use.
    Activation,
}

impl std::fmt::Display for CeremonyStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvironmentCheck => write!(f, "environment_check"),
            Self::KeyGeneration => write!(f, "key_generation"),
            Self::WitnessAttestation => write!(f, "witness_attestation"),
            Self::KeySplit => write!(f, "key_split"),
            Self::ShareDistribution => write!(f, "share_distribution"),
            Self::KeyVerification => write!(f, "key_verification"),
            Self::Activation => write!(f, "activation"),
        }
    }
}

/// A completed step with timestamp and notes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedStep {
    pub step: CeremonyStep,
    pub completed_at: u64,
    pub completed_by: String,
    pub notes: String,
}

/// Key ceremony configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyConfig {
    /// Minimum number of custodians required to reconstruct the key.
    pub threshold: u32,
    /// Total number of custodian shares.
    pub total_shares: u32,
    /// Whether a notary must be present.
    pub notary_required: bool,
    /// Minimum number of witnesses.
    pub min_witnesses: u32,
}

impl Default for CeremonyConfig {
    fn default() -> Self {
        Self {
            threshold: 2,
            total_shares: 3,
            notary_required: true,
            min_witnesses: 2,
        }
    }
}

/// Complete record of a key ceremony — the auditable artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyRecord {
    pub id: String,
    pub ceremony_type: String,
    pub config: CeremonyConfig,
    pub participants: Vec<CeremonyParticipant>,
    pub steps: Vec<CompletedStep>,
    pub key_fingerprint: String,
    pub key_algorithm: String,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub status: CeremonyStatus,
    pub record_hash: String,
}

/// Status of the ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyStatus {
    InProgress,
    Completed,
    Aborted,
}

impl std::fmt::Display for CeremonyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InProgress => write!(f, "in_progress"),
            Self::Completed => write!(f, "completed"),
            Self::Aborted => write!(f, "aborted"),
        }
    }
}

/// Builder for conducting a key ceremony.
pub struct KeyCeremony {
    id: String,
    ceremony_type: String,
    config: CeremonyConfig,
    participants: Vec<CeremonyParticipant>,
    steps: Vec<CompletedStep>,
    key_fingerprint: String,
    key_algorithm: String,
    started_at: u64,
}

impl KeyCeremony {
    pub fn new(id: &str, ceremony_type: &str, config: CeremonyConfig, started_at: u64) -> Self {
        Self {
            id: id.to_string(),
            ceremony_type: ceremony_type.to_string(),
            config,
            participants: Vec::new(),
            steps: Vec::new(),
            key_fingerprint: String::new(),
            key_algorithm: String::new(),
            started_at,
        }
    }

    pub fn add_participant(&mut self, participant: CeremonyParticipant) {
        self.participants.push(participant);
    }

    pub fn record_step(&mut self, step: CeremonyStep, by: &str, notes: &str, at: u64) {
        self.steps.push(CompletedStep {
            step,
            completed_at: at,
            completed_by: by.to_string(),
            notes: notes.to_string(),
        });
    }

    pub fn set_key_info(&mut self, fingerprint: &str, algorithm: &str) {
        self.key_fingerprint = fingerprint.to_string();
        self.key_algorithm = algorithm.to_string();
    }

    /// Validate ceremony completeness before finalizing.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        let custodians = self
            .participants
            .iter()
            .filter(|p| p.role == CeremonyRole::Custodian)
            .count() as u32;
        if custodians < self.config.total_shares {
            errors.push(format!(
                "need {} custodians, have {custodians}",
                self.config.total_shares
            ));
        }

        let witnesses = self
            .participants
            .iter()
            .filter(|p| p.role == CeremonyRole::Witness)
            .count() as u32;
        if witnesses < self.config.min_witnesses {
            errors.push(format!(
                "need {} witnesses, have {witnesses}",
                self.config.min_witnesses
            ));
        }

        if self.config.notary_required
            && !self
                .participants
                .iter()
                .any(|p| p.role == CeremonyRole::Notary)
        {
            errors.push("notary required but not present".into());
        }

        let required_steps = [
            CeremonyStep::EnvironmentCheck,
            CeremonyStep::KeyGeneration,
            CeremonyStep::WitnessAttestation,
            CeremonyStep::KeyVerification,
            CeremonyStep::Activation,
        ];
        for step in &required_steps {
            if !self.steps.iter().any(|s| s.step == *step) {
                errors.push(format!("missing required step: {step}"));
            }
        }

        if self.key_fingerprint.is_empty() {
            errors.push("key fingerprint not set".into());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Finalize the ceremony and produce an immutable record.
    pub fn finalize(self, completed_at: u64) -> Result<CeremonyRecord, Vec<String>> {
        self.validate()?;

        let mut record = CeremonyRecord {
            id: self.id,
            ceremony_type: self.ceremony_type,
            config: self.config,
            participants: self.participants,
            steps: self.steps,
            key_fingerprint: self.key_fingerprint,
            key_algorithm: self.key_algorithm,
            started_at: self.started_at,
            completed_at: Some(completed_at),
            status: CeremonyStatus::Completed,
            record_hash: String::new(),
        };

        record.record_hash = compute_record_hash(&record);
        Ok(record)
    }

    /// Abort the ceremony.
    pub fn abort(self, reason: &str, at: u64) -> CeremonyRecord {
        let mut record = CeremonyRecord {
            id: self.id,
            ceremony_type: self.ceremony_type,
            config: self.config,
            participants: self.participants,
            steps: self.steps,
            key_fingerprint: self.key_fingerprint,
            key_algorithm: self.key_algorithm,
            started_at: self.started_at,
            completed_at: Some(at),
            status: CeremonyStatus::Aborted,
            record_hash: String::new(),
        };

        record.steps.push(CompletedStep {
            step: CeremonyStep::EnvironmentCheck,
            completed_at: at,
            completed_by: "system".into(),
            notes: format!("ABORTED: {reason}"),
        });
        record.record_hash = compute_record_hash(&record);
        record
    }
}

/// Compute SHA-256 hash of the ceremony record for tamper detection.
fn compute_record_hash(record: &CeremonyRecord) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        record.id,
        record.ceremony_type,
        record.key_fingerprint,
        record.key_algorithm,
        record.started_at,
        record.completed_at.unwrap_or(0),
        record.participants.len(),
        record.steps.len(),
    );
    hex::encode(hash_with(HashAlgorithm::Sha256, canonical.as_bytes()))
}

/// Verify a ceremony record's hash integrity.
pub fn verify_record(record: &CeremonyRecord) -> bool {
    !record.record_hash.is_empty() && record.record_hash == compute_record_hash(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_ceremony() -> KeyCeremony {
        let mut c = KeyCeremony::new("ceremony-001", "root_ca", CeremonyConfig::default(), 1000);

        c.add_participant(CeremonyParticipant {
            name: "Admin".into(),
            role: CeremonyRole::Administrator,
            did: Some("did:goya:admin".into()),
            organization: Some("Goya".into()),
        });
        for i in 0..3 {
            c.add_participant(CeremonyParticipant {
                name: format!("Custodian {i}"),
                role: CeremonyRole::Custodian,
                did: None,
                organization: None,
            });
        }
        for i in 0..2 {
            c.add_participant(CeremonyParticipant {
                name: format!("Witness {i}"),
                role: CeremonyRole::Witness,
                did: None,
                organization: None,
            });
        }
        c.add_participant(CeremonyParticipant {
            name: "Notary".into(),
            role: CeremonyRole::Notary,
            did: None,
            organization: None,
        });

        c.record_step(
            CeremonyStep::EnvironmentCheck,
            "Admin",
            "air-gapped verified",
            1001,
        );
        c.record_step(
            CeremonyStep::KeyGeneration,
            "Admin",
            "ECDSA P-256 generated",
            1002,
        );
        c.record_step(
            CeremonyStep::WitnessAttestation,
            "Witness 0",
            "attested",
            1003,
        );
        c.record_step(CeremonyStep::KeySplit, "Admin", "2-of-3 Shamir split", 1004);
        c.record_step(
            CeremonyStep::ShareDistribution,
            "Admin",
            "shares distributed",
            1005,
        );
        c.record_step(
            CeremonyStep::KeyVerification,
            "Auditor",
            "pubkey verified",
            1006,
        );
        c.record_step(CeremonyStep::Activation, "Admin", "CA activated", 1007);

        c.set_key_info("sha256:abcdef1234567890", "ECDSA-P256");
        c
    }

    #[test]
    fn full_ceremony_validates() {
        let c = full_ceremony();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn finalize_produces_completed_record() {
        let c = full_ceremony();
        let record = c.finalize(2000).unwrap();
        assert_eq!(record.status, CeremonyStatus::Completed);
        assert_eq!(record.completed_at, Some(2000));
        assert!(!record.record_hash.is_empty());
    }

    #[test]
    fn record_hash_verifies() {
        let c = full_ceremony();
        let record = c.finalize(2000).unwrap();
        assert!(verify_record(&record));
    }

    #[test]
    fn tampered_record_fails_verification() {
        let c = full_ceremony();
        let mut record = c.finalize(2000).unwrap();
        record.key_fingerprint = "tampered".into();
        assert!(!verify_record(&record));
    }

    #[test]
    fn missing_custodians_fails_validation() {
        let mut c = KeyCeremony::new("c-1", "root_ca", CeremonyConfig::default(), 1000);
        c.set_key_info("fp", "algo");
        c.record_step(CeremonyStep::EnvironmentCheck, "a", "", 1001);
        c.record_step(CeremonyStep::KeyGeneration, "a", "", 1002);
        c.record_step(CeremonyStep::WitnessAttestation, "a", "", 1003);
        c.record_step(CeremonyStep::KeyVerification, "a", "", 1004);
        c.record_step(CeremonyStep::Activation, "a", "", 1005);

        let errs = c.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("custodians")));
    }

    #[test]
    fn missing_witnesses_fails_validation() {
        let mut c = KeyCeremony::new("c-2", "root_ca", CeremonyConfig::default(), 1000);
        for i in 0..3 {
            c.add_participant(CeremonyParticipant {
                name: format!("C{i}"),
                role: CeremonyRole::Custodian,
                did: None,
                organization: None,
            });
        }
        c.add_participant(CeremonyParticipant {
            name: "N".into(),
            role: CeremonyRole::Notary,
            did: None,
            organization: None,
        });
        c.set_key_info("fp", "algo");
        for step in [
            CeremonyStep::EnvironmentCheck,
            CeremonyStep::KeyGeneration,
            CeremonyStep::WitnessAttestation,
            CeremonyStep::KeyVerification,
            CeremonyStep::Activation,
        ] {
            c.record_step(step, "a", "", 1001);
        }

        let errs = c.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("witnesses")));
    }

    #[test]
    fn missing_notary_fails_validation() {
        let mut c = KeyCeremony::new("c-3", "root_ca", CeremonyConfig::default(), 1000);
        for i in 0..3 {
            c.add_participant(CeremonyParticipant {
                name: format!("C{i}"),
                role: CeremonyRole::Custodian,
                did: None,
                organization: None,
            });
        }
        for i in 0..2 {
            c.add_participant(CeremonyParticipant {
                name: format!("W{i}"),
                role: CeremonyRole::Witness,
                did: None,
                organization: None,
            });
        }
        c.set_key_info("fp", "algo");
        for step in [
            CeremonyStep::EnvironmentCheck,
            CeremonyStep::KeyGeneration,
            CeremonyStep::WitnessAttestation,
            CeremonyStep::KeyVerification,
            CeremonyStep::Activation,
        ] {
            c.record_step(step, "a", "", 1001);
        }

        let errs = c.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("notary")));
    }

    #[test]
    fn missing_step_fails_validation() {
        let mut c = KeyCeremony::new("c-4", "root_ca", CeremonyConfig::default(), 1000);
        for i in 0..3 {
            c.add_participant(CeremonyParticipant {
                name: format!("C{i}"),
                role: CeremonyRole::Custodian,
                did: None,
                organization: None,
            });
        }
        for i in 0..2 {
            c.add_participant(CeremonyParticipant {
                name: format!("W{i}"),
                role: CeremonyRole::Witness,
                did: None,
                organization: None,
            });
        }
        c.add_participant(CeremonyParticipant {
            name: "N".into(),
            role: CeremonyRole::Notary,
            did: None,
            organization: None,
        });
        c.set_key_info("fp", "algo");
        c.record_step(CeremonyStep::EnvironmentCheck, "a", "", 1001);

        let errs = c.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("key_generation")));
    }

    #[test]
    fn missing_fingerprint_fails_validation() {
        let mut c = KeyCeremony::new("c-5", "root_ca", CeremonyConfig::default(), 1000);
        for i in 0..3 {
            c.add_participant(CeremonyParticipant {
                name: format!("C{i}"),
                role: CeremonyRole::Custodian,
                did: None,
                organization: None,
            });
        }
        for i in 0..2 {
            c.add_participant(CeremonyParticipant {
                name: format!("W{i}"),
                role: CeremonyRole::Witness,
                did: None,
                organization: None,
            });
        }
        c.add_participant(CeremonyParticipant {
            name: "N".into(),
            role: CeremonyRole::Notary,
            did: None,
            organization: None,
        });
        for step in [
            CeremonyStep::EnvironmentCheck,
            CeremonyStep::KeyGeneration,
            CeremonyStep::WitnessAttestation,
            CeremonyStep::KeyVerification,
            CeremonyStep::Activation,
        ] {
            c.record_step(step, "a", "", 1001);
        }

        let errs = c.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("fingerprint")));
    }

    #[test]
    fn abort_produces_aborted_record() {
        let c = KeyCeremony::new("c-abort", "root_ca", CeremonyConfig::default(), 1000);
        let record = c.abort("security breach detected", 1500);
        assert_eq!(record.status, CeremonyStatus::Aborted);
        assert!(verify_record(&record));
    }

    #[test]
    fn finalize_fails_without_validation() {
        let c = KeyCeremony::new("c-empty", "root_ca", CeremonyConfig::default(), 1000);
        assert!(c.finalize(2000).is_err());
    }

    #[test]
    fn notary_not_required_config() {
        let cfg = CeremonyConfig {
            notary_required: false,
            ..Default::default()
        };
        let mut c = KeyCeremony::new("c-no-notary", "root_ca", cfg, 1000);
        for i in 0..3 {
            c.add_participant(CeremonyParticipant {
                name: format!("C{i}"),
                role: CeremonyRole::Custodian,
                did: None,
                organization: None,
            });
        }
        for i in 0..2 {
            c.add_participant(CeremonyParticipant {
                name: format!("W{i}"),
                role: CeremonyRole::Witness,
                did: None,
                organization: None,
            });
        }
        c.set_key_info("fp", "algo");
        for step in [
            CeremonyStep::EnvironmentCheck,
            CeremonyStep::KeyGeneration,
            CeremonyStep::WitnessAttestation,
            CeremonyStep::KeyVerification,
            CeremonyStep::Activation,
        ] {
            c.record_step(step, "a", "", 1001);
        }
        assert!(c.validate().is_ok());
    }

    #[test]
    fn serialization_roundtrip() {
        let c = full_ceremony();
        let record = c.finalize(2000).unwrap();
        let json = serde_json::to_string(&record).unwrap();
        let parsed: CeremonyRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, record.id);
        assert_eq!(parsed.record_hash, record.record_hash);
        assert!(verify_record(&parsed));
    }

    #[test]
    fn ceremony_role_display() {
        assert_eq!(CeremonyRole::Administrator.to_string(), "administrator");
        assert_eq!(CeremonyRole::Custodian.to_string(), "custodian");
        assert_eq!(CeremonyRole::Notary.to_string(), "notary");
    }

    #[test]
    fn ceremony_step_display() {
        assert_eq!(CeremonyStep::KeyGeneration.to_string(), "key_generation");
        assert_eq!(CeremonyStep::Activation.to_string(), "activation");
    }

    #[test]
    fn ceremony_status_display() {
        assert_eq!(CeremonyStatus::Completed.to_string(), "completed");
        assert_eq!(CeremonyStatus::Aborted.to_string(), "aborted");
    }

    #[test]
    fn default_config_values() {
        let cfg = CeremonyConfig::default();
        assert_eq!(cfg.threshold, 2);
        assert_eq!(cfg.total_shares, 3);
        assert!(cfg.notary_required);
        assert_eq!(cfg.min_witnesses, 2);
    }
}
