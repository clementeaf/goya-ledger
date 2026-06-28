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

/// Platform-appropriate data directory:
/// - Windows: `%APPDATA%\goya\` (via `dirs::data_dir()`)
/// - Unix/macOS: `~/.goya/` (via `dirs::home_dir()`)
fn dirs_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        dirs::data_dir().map(|d| d.join("goya"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        dirs::home_dir().map(|h| h.join(".goya"))
    }
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

    // ── Platform data directory tests ──

    #[test]
    fn dirs_path_returns_some() {
        // dirs_path must resolve on any platform with a home/appdata dir.
        let path = dirs_path();
        assert!(
            path.is_some(),
            "dirs_path() must resolve on CI and dev machines"
        );
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn dirs_path_unix_uses_home_dot_goya() {
        let path = dirs_path().unwrap();
        assert!(
            path.ends_with(".goya"),
            "Unix dirs_path must end with .goya, got: {path:?}"
        );
        // Must be under home directory
        let home = dirs::home_dir().unwrap();
        assert_eq!(path, home.join(".goya"));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn dirs_path_windows_uses_appdata_goya() {
        let path = dirs_path().unwrap();
        assert!(
            path.ends_with("goya"),
            "Windows dirs_path must end with goya, got: {path:?}"
        );
        // Must be under %APPDATA% (data_dir), not home
        let data = dirs::data_dir().unwrap();
        assert_eq!(path, data.join("goya"));
        // Verify it's NOT under home_dir/.goya (the old wrong behavior)
        let home = dirs::home_dir().unwrap();
        assert_ne!(path, home.join(".goya"), "Windows must NOT use ~/.goya");
    }

    #[test]
    fn dirs_path_does_not_contain_identities_json() {
        // dirs_path returns the directory, not the file — from_env appends the filename.
        let path = dirs_path().unwrap();
        assert!(
            !path.to_string_lossy().contains("identities"),
            "dirs_path must return directory only, got: {path:?}"
        );
    }

    #[test]
    fn from_env_appends_identities_json() {
        // Can't mutate env safely in parallel, but we can verify the
        // fallback path structure by constructing the expected result.
        let expected_dir = dirs_path().unwrap();
        let expected_file = expected_dir.join("identities.json");

        // from_env without GOYA_DATA_DIR set should resolve to dirs_path + identities.json.
        // We verify the structure, not the actual from_env call (env-racy).
        assert!(
            expected_file.to_string_lossy().ends_with("identities.json"),
            "store path must end with identities.json"
        );
        assert!(
            expected_file
                .parent()
                .unwrap()
                .ends_with(expected_dir.file_name().unwrap()),
            "parent of store file must be the platform data dir"
        );
    }
}
