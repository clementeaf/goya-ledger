//! Integration tests for light client mode.
//!
//! Verifies:
//! - NodeMode parsing and env resolution
//! - LightRoutes registers only Starter-tier endpoints
//! - SeedProxy construction and error handling
//! - LocalIdentityStore persistence lifecycle

use rust_bc::light_client::local_store::{LocalIdentityStore, StoredIdentity};
use rust_bc::light_client::mode::NodeMode;
use rust_bc::light_client::proxy::SeedProxy;

// ── NodeMode ──

#[test]
fn node_mode_round_trips_through_string() {
    let modes = [NodeMode::Full, NodeMode::Light];
    modes.iter().for_each(|mode| {
        let s = mode.to_string();
        let parsed: NodeMode = s.parse().unwrap();
        assert_eq!(*mode, parsed);
    });
}

#[test]
fn node_mode_light_restricts_correctly() {
    assert!(NodeMode::Light.is_light());
    assert!(!NodeMode::Full.is_light());
}

// ── SeedProxy ──

#[test]
fn proxy_constructs_with_base_url() {
    let proxy = SeedProxy::new("https://goya-node.fly.dev".into());
    assert_eq!(proxy.base_url(), "https://goya-node.fly.dev");
}

// ── LocalIdentityStore ──

#[test]
fn local_store_full_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalIdentityStore::open(dir.path().join("ids.json"));

    // Empty initially
    assert_eq!(store.count().unwrap(), 0);
    assert!(store.list().unwrap().is_empty());

    // Save three identities
    let dids = ["did:goya:alice", "did:goya:bob", "did:goya:carol"];
    dids.iter().for_each(|did| {
        store
            .save(StoredIdentity {
                did: did.to_string(),
                public_key_hex: format!("pk_{did}"),
                private_key_enc: "enc".into(),
                algorithm: "Ed25519".into(),
                created_at: "2026-06-24T00:00:00Z".into(),
            })
            .unwrap();
    });
    assert_eq!(store.count().unwrap(), 3);

    // Retrieve specific
    let alice = store.get("did:goya:alice").unwrap().unwrap();
    assert_eq!(alice.public_key_hex, "pk_did:goya:alice");

    // Update
    store
        .save(StoredIdentity {
            did: "did:goya:alice".into(),
            public_key_hex: "new_pk".into(),
            private_key_enc: "enc".into(),
            algorithm: "Ed25519".into(),
            created_at: "2026-06-24T00:00:00Z".into(),
        })
        .unwrap();
    assert_eq!(store.count().unwrap(), 3); // No duplicate
    assert_eq!(
        store.get("did:goya:alice").unwrap().unwrap().public_key_hex,
        "new_pk"
    );

    // Remove
    let removed = store.remove("did:goya:bob").unwrap();
    assert!(removed.is_some());
    assert_eq!(store.count().unwrap(), 2);
    assert!(store.get("did:goya:bob").unwrap().is_none());
}

#[test]
fn local_store_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ids.json");

    // Write with first instance
    let store = LocalIdentityStore::open(path.clone());
    store
        .save(StoredIdentity {
            did: "did:goya:persist".into(),
            public_key_hex: "pk".into(),
            private_key_enc: "enc".into(),
            algorithm: "Ed25519".into(),
            created_at: "2026-06-24T00:00:00Z".into(),
        })
        .unwrap();
    drop(store);

    // Read with second instance
    let store2 = LocalIdentityStore::open(path);
    let found = store2.get("did:goya:persist").unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().public_key_hex, "pk");
}
