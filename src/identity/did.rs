//! DID (Decentralized Identifier) document model
//!
//! Canonical DID format: `did:goya:{pubkey_hex[..16]}`
//!
//! The DID is derived deterministically from the first 8 bytes (16 hex chars)
//! of the public key. This makes DIDs self-verifying: anyone can confirm that
//! a DID belongs to a public key by comparing strings, with no store lookup.

use hex;
use pqc_crypto_module::legacy::sha256::{Digest, Sha256};

/// Derive a canonical DID from a hex-encoded public key.
///
/// Format: `did:goya:{pubkey_hex[..16]}`
///
/// # Panics
/// Panics if `pubkey_hex` is shorter than 16 characters.
pub fn did_from_pubkey_hex(pubkey_hex: &str) -> String {
    format!("did:goya:{}", &pubkey_hex[..16])
}

/// Verify that a DID matches a hex-encoded public key.
pub fn did_matches_pubkey(did: &str, pubkey_hex: &str) -> bool {
    pubkey_hex.len() >= 16 && did == did_from_pubkey_hex(pubkey_hex)
}

/// DID representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidDocument {
    /// Decentralized Identifier (format: did:goya:abc123...)
    pub did: String,
    /// Unix timestamp when DID was created
    pub created_at: u64,
    /// Unix timestamp when DID was last updated
    pub updated_at: u64,
    /// DID status: active, revoked, suspended
    pub status: DidStatus,
    /// Public key hash (hex encoded)
    pub public_key_hash: String,
    /// Credential IDs associated with this DID
    pub credentials: Vec<String>,
    /// Additional metadata
    pub metadata: DidMetadata,
}

/// DID status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidStatus {
    #[allow(dead_code)]
    /// DID is active and usable
    Active,
    #[allow(dead_code)]
    /// DID has been revoked
    Revoked,
    #[allow(dead_code)]
    /// DID is temporarily suspended
    Suspended,
}

/// Additional metadata for a DID
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidMetadata {
    /// Human-readable name (optional)
    pub name: Option<String>,
    /// Email address (optional)
    pub email: Option<String>,
    /// Jurisdiction for compliance purposes
    pub jurisdiction: Option<String>,
}

impl DidDocument {
    #[allow(dead_code)]
    /// Create a new DID document
    pub fn new(public_key_hash: String, timestamp: u64) -> Self {
        let did = Self::create_did(&public_key_hash);

        DidDocument {
            did,
            created_at: timestamp,
            updated_at: timestamp,
            status: DidStatus::Active,
            public_key_hash,
            credentials: Vec::new(),
            metadata: DidMetadata {
                name: None,
                email: None,
                jurisdiction: None,
            },
        }
    }

    /// Create DID string from public key hash
    /// Format: did:goya:<hex_pubkey_hash>
    pub fn create_did(pubkey_hash: &str) -> String {
        format!("did:goya:{pubkey_hash}")
    }

    #[allow(dead_code)]
    /// Generate a DID from raw public key bytes
    pub fn from_public_key(pubkey: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(pubkey);
        let result = hasher.finalize();
        let pubkey_hash = hex::encode(&result[..16]); // Use first 128 bits
        Self::create_did(&pubkey_hash)
    }

    #[allow(dead_code)]
    /// Add a credential to this DID
    pub fn add_credential(&mut self, credential_id: String) {
        if !self.credentials.contains(&credential_id) {
            self.credentials.push(credential_id);
        }
    }

    #[allow(dead_code)]
    /// Remove a credential from this DID
    pub fn remove_credential(&mut self, credential_id: &str) {
        self.credentials.retain(|id| id != credential_id);
    }

    #[allow(dead_code)]
    /// Revoke this DID
    pub fn revoke(&mut self, timestamp: u64) {
        self.status = DidStatus::Revoked;
        self.updated_at = timestamp;
    }

    #[allow(dead_code)]
    /// Suspend this DID
    pub fn suspend(&mut self, timestamp: u64) {
        self.status = DidStatus::Suspended;
        self.updated_at = timestamp;
    }

    #[allow(dead_code)]
    /// Reactivate this DID
    pub fn reactivate(&mut self, timestamp: u64) {
        self.status = DidStatus::Active;
        self.updated_at = timestamp;
    }

    #[allow(dead_code)]
    /// Check if DID is active
    pub fn is_active(&self) -> bool {
        self.status == DidStatus::Active
    }

    #[allow(dead_code)]
    /// Parse a DID string and validate format
    pub fn parse(did_str: &str) -> Result<(), String> {
        if !did_str.starts_with("did:goya:") {
            return Err("Invalid DID prefix".to_string());
        }

        let parts: Vec<&str> = did_str.split(':').collect();
        if parts.len() != 3 {
            return Err("Invalid DID format".to_string());
        }

        if parts[2].is_empty() {
            return Err("DID hash cannot be empty".to_string());
        }

        // Validate hex encoding
        if hex::decode(parts[2]).is_err() {
            return Err("Invalid DID hash encoding".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_creation() {
        let did = DidDocument::new("abc123def456".to_string(), 1000);
        assert_eq!(did.did, "did:goya:abc123def456");
        assert_eq!(did.created_at, 1000);
        assert!(did.is_active());
    }

    #[test]
    fn test_did_format_creation() {
        let did = DidDocument::create_did("test123");
        assert_eq!(did, "did:goya:test123");
    }

    #[test]
    fn test_did_from_pubkey() {
        let pubkey = [1u8; 32];
        let did = DidDocument::from_public_key(&pubkey);
        assert!(did.starts_with("did:goya:"));
        assert!(did.len() > 7); // "did:goya:" + hash
    }

    #[test]
    fn test_add_credential() {
        let mut did = DidDocument::new("abc123".to_string(), 1000);
        did.add_credential("cred1".to_string());
        assert!(did.credentials.contains(&"cred1".to_string()));
    }

    #[test]
    fn test_remove_credential() {
        let mut did = DidDocument::new("abc123".to_string(), 1000);
        did.add_credential("cred1".to_string());
        did.remove_credential("cred1");
        assert!(!did.credentials.contains(&"cred1".to_string()));
    }

    #[test]
    fn test_revoke_did() {
        let mut did = DidDocument::new("abc123".to_string(), 1000);
        did.revoke(2000);
        assert_eq!(did.status, DidStatus::Revoked);
        assert_eq!(did.updated_at, 2000);
    }

    #[test]
    fn test_suspend_did() {
        let mut did = DidDocument::new("abc123".to_string(), 1000);
        did.suspend(2000);
        assert_eq!(did.status, DidStatus::Suspended);
    }

    #[test]
    fn test_reactivate_did() {
        let mut did = DidDocument::new("abc123".to_string(), 1000);
        did.revoke(2000);
        did.reactivate(3000);
        assert!(did.is_active());
    }

    #[test]
    fn test_parse_valid_did() {
        let result = DidDocument::parse("did:goya:abc123");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_prefix() {
        let result = DidDocument::parse("did:eth:abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_hash() {
        let result = DidDocument::parse("did:goya:");
        assert!(result.is_err());
    }

    #[test]
    fn test_did_uniqueness_from_keys() {
        let pubkey1 = [1u8; 32];
        let pubkey2 = [2u8; 32];
        let did1 = DidDocument::from_public_key(&pubkey1);
        let did2 = DidDocument::from_public_key(&pubkey2);
        assert_ne!(did1, did2);
    }

    // ── Canonical DID functions ──

    #[test]
    fn canonical_did_from_pubkey_hex() {
        let pubkey_hex = "aabbccdd11223344ffffffffffffffff";
        assert_eq!(did_from_pubkey_hex(pubkey_hex), "did:goya:aabbccdd11223344");
    }

    #[test]
    fn canonical_did_matches_pubkey() {
        let pubkey_hex = "aabbccdd11223344ffffffffffffffff";
        let did = did_from_pubkey_hex(pubkey_hex);
        assert!(did_matches_pubkey(&did, pubkey_hex));
    }

    #[test]
    fn canonical_did_rejects_wrong_pubkey() {
        let did = "did:goya:aabbccdd11223344";
        let wrong_key = "1111111111111111ffffffffffffffff";
        assert!(!did_matches_pubkey(did, wrong_key));
    }

    #[test]
    fn canonical_did_rejects_short_pubkey() {
        let did = "did:goya:aabbccdd11223344";
        assert!(!did_matches_pubkey(did, "aabb"));
    }

    #[test]
    fn canonical_did_deterministic() {
        let key = "606024501eda68c20bd7b65841d0c580aaaaaa";
        assert_eq!(did_from_pubkey_hex(key), did_from_pubkey_hex(key));
    }
}
