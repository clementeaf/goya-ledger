use crate::identity::signing::SigningAlgorithm;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecationEntry {
    pub algorithm: SigningAlgorithm,
    pub deprecated_at: u64,
    pub reject_after: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlgorithmPolicy {
    pub accepted: Vec<SigningAlgorithm>,
    pub deprecated: Vec<DeprecationEntry>,
    pub node_algorithm: SigningAlgorithm,
    pub node_capabilities: Vec<SigningAlgorithm>,
}

impl AlgorithmPolicy {
    pub fn new(node_algorithm: SigningAlgorithm) -> Self {
        let capabilities = vec![
            SigningAlgorithm::Ed25519,
            SigningAlgorithm::MlDsa65,
            SigningAlgorithm::SlhDsa128s,
            SigningAlgorithm::EcdsaP256,
            SigningAlgorithm::Rsa,
        ];
        let accepted = capabilities.clone();
        Self {
            accepted,
            deprecated: Vec::new(),
            node_algorithm,
            node_capabilities: capabilities,
        }
    }

    pub fn deprecate(
        &mut self,
        algorithm: SigningAlgorithm,
        current_time: u64,
        reject_after: u64,
        reason: String,
    ) -> Result<(), PolicyError> {
        if algorithm == self.node_algorithm {
            return Err(PolicyError::CannotDeprecateActive);
        }
        if self.is_deprecated(&algorithm) {
            return Err(PolicyError::AlreadyDeprecated);
        }
        if reject_after <= current_time {
            return Err(PolicyError::DeadlineInPast);
        }
        self.deprecated.push(DeprecationEntry {
            algorithm,
            deprecated_at: current_time,
            reject_after,
            reason,
        });
        Ok(())
    }

    pub fn is_deprecated(&self, algorithm: &SigningAlgorithm) -> bool {
        self.deprecated.iter().any(|d| d.algorithm == *algorithm)
    }

    pub fn is_rejected(&self, algorithm: &SigningAlgorithm, current_time: u64) -> bool {
        self.deprecated
            .iter()
            .any(|d| d.algorithm == *algorithm && current_time >= d.reject_after)
    }

    pub fn is_accepted(&self, algorithm: &SigningAlgorithm, current_time: u64) -> bool {
        self.accepted.contains(algorithm) && !self.is_rejected(algorithm, current_time)
    }

    pub fn active_algorithms(&self, current_time: u64) -> Vec<SigningAlgorithm> {
        self.accepted
            .iter()
            .filter(|a| !self.is_rejected(a, current_time))
            .copied()
            .collect()
    }

    pub fn status_map(&self, current_time: u64) -> HashMap<String, String> {
        self.accepted
            .iter()
            .map(|a| {
                let status = if self.is_rejected(a, current_time) {
                    "rejected"
                } else if self.is_deprecated(a) {
                    "deprecated"
                } else if *a == self.node_algorithm {
                    "active (node default)"
                } else {
                    "accepted"
                };
                (a.to_string(), status.to_string())
            })
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("cannot deprecate the node's active algorithm")]
    CannotDeprecateActive,
    #[error("algorithm already deprecated")]
    AlreadyDeprecated,
    #[error("reject_after deadline must be in the future")]
    DeadlineInPast,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_policy_accepts_all() {
        let policy = AlgorithmPolicy::new(SigningAlgorithm::MlDsa65);
        assert!(policy.is_accepted(&SigningAlgorithm::Ed25519, 1000));
        assert!(policy.is_accepted(&SigningAlgorithm::MlDsa65, 1000));
        assert!(!policy.is_deprecated(&SigningAlgorithm::Ed25519));
    }

    #[test]
    fn deprecate_marks_algorithm() {
        let mut policy = AlgorithmPolicy::new(SigningAlgorithm::MlDsa65);
        policy
            .deprecate(
                SigningAlgorithm::Ed25519,
                1000,
                2000,
                "quantum threat".into(),
            )
            .unwrap();
        assert!(policy.is_deprecated(&SigningAlgorithm::Ed25519));
        assert!(policy.is_accepted(&SigningAlgorithm::Ed25519, 1500));
        assert!(!policy.is_accepted(&SigningAlgorithm::Ed25519, 2000));
        assert!(policy.is_rejected(&SigningAlgorithm::Ed25519, 2000));
    }

    #[test]
    fn cannot_deprecate_active_algorithm() {
        let mut policy = AlgorithmPolicy::new(SigningAlgorithm::MlDsa65);
        let result = policy.deprecate(SigningAlgorithm::MlDsa65, 1000, 2000, "test".into());
        assert!(matches!(result, Err(PolicyError::CannotDeprecateActive)));
    }

    #[test]
    fn cannot_deprecate_twice() {
        let mut policy = AlgorithmPolicy::new(SigningAlgorithm::MlDsa65);
        policy
            .deprecate(SigningAlgorithm::Ed25519, 1000, 2000, "first".into())
            .unwrap();
        let result = policy.deprecate(SigningAlgorithm::Ed25519, 1000, 3000, "second".into());
        assert!(matches!(result, Err(PolicyError::AlreadyDeprecated)));
    }

    #[test]
    fn deadline_must_be_future() {
        let mut policy = AlgorithmPolicy::new(SigningAlgorithm::MlDsa65);
        let result = policy.deprecate(SigningAlgorithm::Ed25519, 1000, 500, "past".into());
        assert!(matches!(result, Err(PolicyError::DeadlineInPast)));
    }

    #[test]
    fn active_algorithms_excludes_rejected() {
        let mut policy = AlgorithmPolicy::new(SigningAlgorithm::MlDsa65);
        policy
            .deprecate(SigningAlgorithm::Ed25519, 1000, 2000, "quantum".into())
            .unwrap();
        let active = policy.active_algorithms(2500);
        assert!(!active.contains(&SigningAlgorithm::Ed25519));
        assert!(active.contains(&SigningAlgorithm::MlDsa65));
    }

    #[test]
    fn status_map_shows_all_states() {
        let mut policy = AlgorithmPolicy::new(SigningAlgorithm::MlDsa65);
        policy
            .deprecate(SigningAlgorithm::Ed25519, 1000, 2000, "quantum".into())
            .unwrap();

        let map = policy.status_map(1500);
        assert_eq!(map["Ed25519"], "deprecated");
        assert_eq!(map["ML-DSA-65"], "active (node default)");

        let map_after = policy.status_map(2500);
        assert_eq!(map_after["Ed25519"], "rejected");
    }
}
