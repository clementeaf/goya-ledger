use pqc_crypto_module::legacy::sha256::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct PrivateClaimsStore {
    entries: Mutex<HashMap<String, PrivateClaimsEntry>>,
}

struct PrivateClaimsEntry {
    claims: serde_json::Value,
    _salt: String,
}

impl Default for PrivateClaimsStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateClaimsStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn store(&self, credential_id: &str, claims: &serde_json::Value) -> (String, String) {
        let salt = uuid::Uuid::new_v4().to_string();
        let commitment = compute_commitment(claims, &salt);
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                credential_id.to_string(),
                PrivateClaimsEntry {
                    claims: claims.clone(),
                    _salt: salt.clone(),
                },
            );
        (commitment, salt)
    }

    pub fn retrieve(&self, credential_id: &str) -> Option<serde_json::Value> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(credential_id)
            .map(|e| e.claims.clone())
    }

    pub fn erase(&self, credential_id: &str) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(credential_id)
            .is_some()
    }
}

pub fn compute_commitment(claims: &serde_json::Value, salt: &str) -> String {
    let canonical = serde_json::to_vec(claims).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    hasher.update(salt.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_commitment(claims: &serde_json::Value, salt: &str, expected: &str) -> bool {
    compute_commitment(claims, salt) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_retrieve() {
        let store = PrivateClaimsStore::new();
        let claims = serde_json::json!({"given_name": "María", "rut": "12345678-5"});
        let (commitment, _salt) = store.store("cred-1", &claims);
        assert!(!commitment.is_empty());
        assert_eq!(store.retrieve("cred-1").unwrap(), claims);
    }

    #[test]
    fn erase_destroys_claims() {
        let store = PrivateClaimsStore::new();
        let claims = serde_json::json!({"name": "test"});
        store.store("cred-1", &claims);
        assert!(store.erase("cred-1"));
        assert!(store.retrieve("cred-1").is_none());
    }

    #[test]
    fn commitment_verifies() {
        let claims = serde_json::json!({"birth_date": "1990-01-15"});
        let salt = "random-salt-123";
        let commitment = compute_commitment(&claims, salt);
        assert!(verify_commitment(&claims, salt, &commitment));
        assert!(!verify_commitment(&claims, "wrong-salt", &commitment));
    }

    #[test]
    fn different_claims_different_commitment() {
        let salt = "same-salt";
        let c1 = compute_commitment(&serde_json::json!({"a": 1}), salt);
        let c2 = compute_commitment(&serde_json::json!({"a": 2}), salt);
        assert_ne!(c1, c2);
    }

    #[test]
    fn erase_nonexistent_returns_false() {
        let store = PrivateClaimsStore::new();
        assert!(!store.erase("nonexistent"));
    }
}
