//! Tauri IPC commands — bridge between frontend and light client.
//!
//! Each command is a plain async fn that can be tested independently.
//! Tauri's `#[command]` macro is applied in `main.rs` via re-export.

use chrono::Utc;
use rust_bc::light_client::local_store::{LocalIdentityStore, StoredIdentity};
use rust_bc::light_client::proxy::SeedProxy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Shared error type for all commands.
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandError {
    pub message: String,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<rust_bc::light_client::proxy::ProxyError> for CommandError {
    fn from(e: rust_bc::light_client::proxy::ProxyError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

impl From<rust_bc::light_client::local_store::LocalStoreError> for CommandError {
    fn from(e: rust_bc::light_client::local_store::LocalStoreError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

// ── Response types ──

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct IdentityInfo {
    pub did: String,
    pub public_key_hex: String,
    pub algorithm: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NotarizeResult {
    pub hash: String,
    pub timestamp: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub seed_url: String,
    pub connected: bool,
    pub chain_height: Option<u64>,
    pub local_identities: usize,
}

// ── Commands ──

/// Create a new DID identity and persist locally.
pub fn create_identity(
    store: &LocalIdentityStore,
    algorithm: &str,
) -> Result<IdentityInfo, CommandError> {
    let keypair = generate_keypair(algorithm);
    let did = format!("did:goya:{}", &keypair.public_key_hex[..16]);
    let now = Utc::now().to_rfc3339();

    let stored = StoredIdentity {
        did: did.clone(),
        public_key_hex: keypair.public_key_hex.clone(),
        private_key_enc: keypair.private_key_enc,
        algorithm: algorithm.to_string(),
        created_at: now.clone(),
    };
    store.save(stored)?;

    Ok(IdentityInfo {
        did,
        public_key_hex: keypair.public_key_hex,
        algorithm: algorithm.to_string(),
        created_at: now,
    })
}

/// List all locally stored identities.
pub fn list_identities(store: &LocalIdentityStore) -> Result<Vec<IdentityInfo>, CommandError> {
    let identities = store
        .list()?
        .into_iter()
        .map(|s| IdentityInfo {
            did: s.did,
            public_key_hex: s.public_key_hex,
            algorithm: s.algorithm,
            created_at: s.created_at,
        })
        .collect();
    Ok(identities)
}

/// Hash a document (bytes) and return the SHA-256 hex digest.
pub fn hash_document(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Submit a notarization to the seed node.
pub async fn notarize_document(
    proxy: &SeedProxy,
    file_name: &str,
    file_bytes: &[u8],
) -> Result<NotarizeResult, CommandError> {
    let hash = hash_document(file_bytes);
    let now = Utc::now().to_rfc3339();

    let body = serde_json::json!({
        "hash": hash,
        "metadata": {
            "file_name": file_name,
            "timestamp": now,
        }
    });

    let resp = proxy
        .post_raw("/api/v1/notarize", body.to_string().as_bytes())
        .await;

    match resp {
        Ok(_) => Ok(NotarizeResult {
            hash,
            timestamp: now,
            status: "registered".to_string(),
        }),
        Err(e) => Err(CommandError {
            message: format!("notarization failed: {e}"),
        }),
    }
}

/// Verify a hash exists on the seed node.
pub async fn verify_notarization(
    proxy: &SeedProxy,
    hash: &str,
) -> Result<serde_json::Value, CommandError> {
    let path = format!("/api/v1/notarize/verify/{hash}");
    proxy
        .get::<serde_json::Value>(&path)
        .await
        .map_err(CommandError::from)
}

/// Query seed node status and local identity count.
pub async fn get_node_status(
    proxy: &SeedProxy,
    store: &LocalIdentityStore,
) -> Result<NodeStatus, CommandError> {
    let local_count = store.count().unwrap_or(0);
    let health: Result<serde_json::Value, _> = proxy.get("/api/v1/health").await;

    let (connected, chain_height) = match health {
        Ok(resp) => {
            let height = resp
                .pointer("/data/blockchain/height")
                .and_then(|v| v.as_u64());
            (true, height)
        }
        Err(_) => (false, None),
    };

    Ok(NodeStatus {
        seed_url: proxy.base_url().to_string(),
        connected,
        chain_height,
        local_identities: local_count,
    })
}

// ── Internal helpers ──

struct KeypairOutput {
    public_key_hex: String,
    private_key_enc: String,
}

fn generate_keypair(algorithm: &str) -> KeypairOutput {
    match algorithm {
        "Ed25519" | "ed25519" => {
            use ed25519_dalek::SigningKey;
            use rand::rngs::OsRng;

            let signing_key = SigningKey::generate(&mut OsRng);
            let public_key = signing_key.verifying_key();
            KeypairOutput {
                public_key_hex: hex::encode(public_key.as_bytes()),
                // ponytail: store raw hex for now; add client-side encryption when Tauri app has password flow.
                private_key_enc: hex::encode(signing_key.to_bytes()),
            }
        }
        _ => {
            // Default to Ed25519 for unknown algorithms
            generate_keypair("Ed25519")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, LocalIdentityStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalIdentityStore::open(dir.path().join("test_ids.json"));
        (dir, store)
    }

    #[test]
    fn create_identity_persists_and_returns() {
        let (_dir, store) = temp_store();
        let result = create_identity(&store, "Ed25519").unwrap();

        assert!(result.did.starts_with("did:goya:"));
        assert!(!result.public_key_hex.is_empty());
        assert_eq!(result.algorithm, "Ed25519");
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn create_multiple_identities() {
        let (_dir, store) = temp_store();

        let ids: Vec<IdentityInfo> = (0..3)
            .map(|_| create_identity(&store, "Ed25519").unwrap())
            .collect();

        assert_eq!(store.count().unwrap(), 3);
        // All DIDs unique
        let unique_dids: std::collections::HashSet<_> = ids.iter().map(|i| &i.did).collect();
        assert_eq!(unique_dids.len(), 3);
    }

    #[test]
    fn list_identities_returns_all() {
        let (_dir, store) = temp_store();
        (0..3).for_each(|_| {
            create_identity(&store, "Ed25519").unwrap();
        });

        let list = list_identities(&store).unwrap();
        assert_eq!(list.len(), 3);
        list.iter().for_each(|id| {
            assert!(id.did.starts_with("did:goya:"));
        });
    }

    #[test]
    fn list_empty_store() {
        let (_dir, store) = temp_store();
        let list = list_identities(&store).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn hash_document_is_deterministic() {
        let data = b"hello goya ledger";
        let hash1 = hash_document(data);
        let hash2 = hash_document(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn hash_document_different_inputs() {
        let h1 = hash_document(b"file_a");
        let h2 = hash_document(b"file_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn generate_keypair_ed25519_valid() {
        let kp = generate_keypair("Ed25519");
        assert_eq!(kp.public_key_hex.len(), 64); // 32 bytes = 64 hex
        assert_eq!(kp.private_key_enc.len(), 64);
    }

    #[test]
    fn generate_keypair_unique() {
        let kp1 = generate_keypair("Ed25519");
        let kp2 = generate_keypair("Ed25519");
        assert_ne!(kp1.public_key_hex, kp2.public_key_hex);
    }

    #[test]
    fn unknown_algorithm_falls_back_to_ed25519() {
        let kp = generate_keypair("unknown_algo");
        assert_eq!(kp.public_key_hex.len(), 64);
    }

    #[tokio::test]
    async fn node_status_offline_seed() {
        let (_dir, store) = temp_store();
        create_identity(&store, "Ed25519").unwrap();

        let proxy = SeedProxy::new("http://localhost:1".into()); // unreachable
        let status = get_node_status(&proxy, &store).await.unwrap();

        assert!(!status.connected);
        assert!(status.chain_height.is_none());
        assert_eq!(status.local_identities, 1);
    }
}
