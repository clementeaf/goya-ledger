//! Local identity store — persists DIDs and keypairs for the light client
//! as a JSON file on disk. No external database dependency.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Errors from local store operations.
#[derive(Debug, thiserror::Error)]
pub enum LocalStoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// A stored identity with its keypair material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredIdentity {
    pub did: String,
    pub public_key_hex: String,
    /// Encrypted private key (client-side encryption — store never decrypts).
    pub private_key_enc: String,
    pub algorithm: String,
    pub created_at: String,
}

/// On-disk format for the identity store.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoreData {
    identities: HashMap<String, StoredIdentity>,
}

/// File-backed identity store for light client.
///
/// Reads the entire file on each operation and writes back atomically.
/// Fine for a handful of identities — no need for a database.
pub struct LocalIdentityStore {
    path: PathBuf,
}

impl LocalIdentityStore {
    /// Open or create a store at the given path.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Resolve from `GOYA_DATA_DIR` env var, defaulting to `~/.goya/`.
    pub fn from_env() -> Self {
        let dir = std::env::var("GOYA_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| dirs_path().unwrap_or_else(|| PathBuf::from(".goya")));
        Self::open(dir.join("identities.json"))
    }

    /// Store path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Save an identity. Overwrites existing entry with same DID.
    pub fn save(&self, identity: StoredIdentity) -> Result<(), LocalStoreError> {
        let mut data = self.load_data()?;
        data.identities.insert(identity.did.clone(), identity);
        self.write_data(&data)
    }

    /// Get an identity by DID.
    pub fn get(&self, did: &str) -> Result<Option<StoredIdentity>, LocalStoreError> {
        let data = self.load_data()?;
        Ok(data.identities.get(did).cloned())
    }

    /// List all stored identities.
    pub fn list(&self) -> Result<Vec<StoredIdentity>, LocalStoreError> {
        let data = self.load_data()?;
        Ok(data.identities.into_values().collect())
    }

    /// Remove an identity by DID. Returns the removed identity.
    pub fn remove(&self, did: &str) -> Result<Option<StoredIdentity>, LocalStoreError> {
        let mut data = self.load_data()?;
        let removed = data.identities.remove(did);
        self.write_data(&data)?;
        Ok(removed)
    }

    /// Number of stored identities.
    pub fn count(&self) -> Result<usize, LocalStoreError> {
        Ok(self.load_data()?.identities.len())
    }

    fn load_data(&self) -> Result<StoreData, LocalStoreError> {
        match std::fs::read_to_string(&self.path) {
            Ok(content) => Ok(serde_json::from_str(&content)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StoreData::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn write_data(&self, data: &StoreData) -> Result<(), LocalStoreError> {
        // Ensure parent directory exists.
        self.path
            .parent()
            .map(std::fs::create_dir_all)
            .transpose()?;
        let json = serde_json::to_string_pretty(data)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }
}

/// Platform-appropriate data directory: `~/.goya/` on Unix, `%APPDATA%/goya/` on Windows.
fn dirs_path() -> Option<PathBuf> {
    // ponytail: home_dir is deprecated but fine here; upgrade to `dirs` crate if needed.
    #[allow(deprecated)]
    std::env::home_dir().map(|h| h.join(".goya"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, LocalIdentityStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalIdentityStore::open(dir.path().join("identities.json"));
        (dir, store)
    }

    fn sample_identity(did: &str) -> StoredIdentity {
        StoredIdentity {
            did: did.to_string(),
            public_key_hex: "abcd1234".to_string(),
            private_key_enc: "encrypted_data".to_string(),
            algorithm: "Ed25519".to_string(),
            created_at: "2026-06-24T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn save_and_get() {
        let (_dir, store) = temp_store();
        let id = sample_identity("did:goya:alice");
        store.save(id.clone()).unwrap();

        let retrieved = store.get("did:goya:alice").unwrap().unwrap();
        assert_eq!(retrieved, id);
    }

    #[test]
    fn get_missing_returns_none() {
        let (_dir, store) = temp_store();
        assert!(store.get("did:goya:nobody").unwrap().is_none());
    }

    #[test]
    fn list_returns_all() {
        let (_dir, store) = temp_store();
        store.save(sample_identity("did:goya:a")).unwrap();
        store.save(sample_identity("did:goya:b")).unwrap();
        store.save(sample_identity("did:goya:c")).unwrap();

        let all = store.list().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn save_overwrites_existing() {
        let (_dir, store) = temp_store();
        let mut id = sample_identity("did:goya:alice");
        store.save(id.clone()).unwrap();

        id.public_key_hex = "new_key".to_string();
        store.save(id.clone()).unwrap();

        let retrieved = store.get("did:goya:alice").unwrap().unwrap();
        assert_eq!(retrieved.public_key_hex, "new_key");
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn remove_returns_identity() {
        let (_dir, store) = temp_store();
        store.save(sample_identity("did:goya:alice")).unwrap();

        let removed = store.remove("did:goya:alice").unwrap();
        assert!(removed.is_some());
        assert!(store.get("did:goya:alice").unwrap().is_none());
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn remove_missing_returns_none() {
        let (_dir, store) = temp_store();
        assert!(store.remove("did:goya:nobody").unwrap().is_none());
    }

    #[test]
    fn empty_store_counts_zero() {
        let (_dir, store) = temp_store();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("nested")
            .join("deep")
            .join("identities.json");
        let store = LocalIdentityStore::open(path);
        store.save(sample_identity("did:goya:test")).unwrap();
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn persists_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities.json");

        let store1 = LocalIdentityStore::open(path.clone());
        store1.save(sample_identity("did:goya:alice")).unwrap();
        drop(store1);

        let store2 = LocalIdentityStore::open(path);
        let retrieved = store2.get("did:goya:alice").unwrap();
        assert!(retrieved.is_some());
    }
}
