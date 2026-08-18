use crate::crypto::hasher::hash;
use crate::signature::{validate_fes_fea, SignedEnvelope};
use crate::tsa::{TimeStampRequest, TsaProvider};

use super::store::LexChainStore;
use super::types::*;

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum LexChainError {
    #[error("contract not found: {0}")]
    NotFound(String),
    #[error("party not found: {0}")]
    PartyNotFound(String),
    #[error("party already signed: {0}")]
    AlreadySigned(String),
    #[error("invalid state: expected {expected}, got {got}")]
    InvalidState { expected: String, got: String },
    #[error("signature validation failed: {0}")]
    SignatureError(String),
    #[error("notarization failed: {0}")]
    NotarizationFailed(String),
    #[error("contract requires at least one party")]
    NoParties,
    #[error("DID not registered: {0}")]
    DidNotRegistered(String),
    #[error("archival failed: {0}")]
    ArchivalFailed(String),
    #[error("contract expired")]
    Expired,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn content_hash(def: &ContractDefinition) -> String {
    let canonical = serde_json::to_string(def).unwrap_or_default();
    hex::encode(hash(canonical.as_bytes()))
}

pub fn deploy(
    store: &LexChainStore,
    definition: ContractDefinition,
) -> Result<LexContract, LexChainError> {
    if definition.parties.is_empty() {
        return Err(LexChainError::NoParties);
    }

    let id = format!("lxc-{}", uuid::Uuid::new_v4());
    let parties = definition
        .parties
        .iter()
        .map(PartyState::from_definition)
        .collect();
    let hash = content_hash(&definition);

    let contract = LexContract {
        id: id.clone(),
        definition,
        state: ContractState::PendingSignatures,
        parties,
        created_at: now_secs(),
        content_hash: hash,
        tsa_token: None,
        block_height: None,
    };

    store.save(contract.clone());
    Ok(contract)
}

pub fn sign(
    store: &LexChainStore,
    contract_id: &str,
    req: &SignRequest,
) -> Result<LexContract, LexChainError> {
    let mut contract = store
        .get(contract_id)
        .ok_or_else(|| LexChainError::NotFound(contract_id.to_string()))?;

    if contract.state != ContractState::PendingSignatures {
        return Err(LexChainError::InvalidState {
            expected: "pending_signatures".into(),
            got: contract.state.to_string(),
        });
    }

    if contract.is_expired(now_secs()) {
        contract.state = ContractState::Expired;
        store.save(contract);
        return Err(LexChainError::Expired);
    }

    if store.backend().read_identity(&req.did).is_err() {
        return Err(LexChainError::DidNotRegistered(req.did.clone()));
    }

    let party = contract
        .party_by_did(&req.did)
        .ok_or_else(|| LexChainError::PartyNotFound(req.did.clone()))?;

    if party.signed {
        return Err(LexChainError::AlreadySigned(req.did.clone()));
    }

    let sig_level = party.signature_level;
    let algorithm =
        crate::signature::verify::infer_algorithm_from_key(&req.public_key).unwrap_or_default();

    validate_fes_fea(
        sig_level,
        algorithm,
        &req.biometric_evidence,
        &req.public_key,
    )
    .map_err(|e| LexChainError::SignatureError(e.to_string()))?;

    let envelope = SignedEnvelope {
        level: sig_level,
        signer: req.did.clone(),
        content_hash: contract.content_hash.clone(),
        signature: req.signature.clone(),
        public_key: req.public_key.clone(),
        signature_algorithm: algorithm,
        biometric_evidence: req.biometric_evidence.clone(),
        signed_at: now_secs(),
    };

    envelope
        .validate_structure()
        .map_err(|e| LexChainError::SignatureError(e.to_string()))?;

    let payload = envelope.signing_payload();
    if !crate::signature::verify_signature(
        algorithm,
        &req.public_key,
        payload.as_bytes(),
        &req.signature,
    ) {
        return Err(LexChainError::SignatureError(
            "cryptographic signature verification failed".into(),
        ));
    }

    let party_mut = contract.party_by_did_mut(&req.did).unwrap();
    party_mut.signed = true;
    party_mut.envelope = Some(envelope);

    if contract.all_signed() {
        contract.state = ContractState::FullySigned;
    }

    store.save(contract.clone());
    Ok(contract)
}

pub fn notarize(
    store: &LexChainStore,
    contract_id: &str,
    tsa: &TsaProvider,
) -> Result<LexContract, LexChainError> {
    let mut contract = store
        .get(contract_id)
        .ok_or_else(|| LexChainError::NotFound(contract_id.to_string()))?;

    if contract.state != ContractState::FullySigned {
        return Err(LexChainError::InvalidState {
            expected: "fully_signed".into(),
            got: contract.state.to_string(),
        });
    }

    let req = TimeStampRequest {
        hash_algorithm: crate::crypto::hasher::HashAlgorithm::Sha256,
        message_imprint: contract.content_hash.clone(),
        nonce: Some(now_secs()),
        require_ordering: false,
    };

    let resp = tsa.issue(&req);
    if resp.status != 0 {
        return Err(LexChainError::NotarizationFailed(resp.status_string));
    }

    contract.tsa_token = resp.token;
    contract.state = ContractState::Notarized;

    store.save(contract.clone());
    Ok(contract)
}

pub fn archive(store: &LexChainStore, contract_id: &str) -> Result<LexContract, LexChainError> {
    let mut contract = store
        .get(contract_id)
        .ok_or_else(|| LexChainError::NotFound(contract_id.to_string()))?;

    if contract.state != ContractState::Notarized && contract.state != ContractState::FullySigned {
        return Err(LexChainError::InvalidState {
            expected: "fully_signed or notarized".into(),
            got: contract.state.to_string(),
        });
    }

    let backend = store.backend();
    let height = backend.get_latest_height().unwrap_or(0);

    let tx = crate::storage::traits::Transaction {
        id: format!("lxc-archive:{}", contract.id),
        block_height: height,
        timestamp: now_secs(),
        input_did: contract
            .parties
            .first()
            .map(|p| p.did.clone())
            .unwrap_or_default(),
        output_recipient: "lexchain:archive".to_string(),
        amount: 0,
        state: "confirmed".to_string(),
    };

    backend
        .write_transaction(&tx)
        .map_err(|e| LexChainError::ArchivalFailed(e.to_string()))?;

    contract.block_height = Some(height);
    contract.state = ContractState::Archived;

    store.save(contract.clone());
    Ok(contract)
}

/// Check and expire contracts past their deadline. Returns expired contract IDs.
pub fn expire_pending(store: &LexChainStore) -> Vec<String> {
    let now = now_secs();
    let mut expired = Vec::new();
    for mut contract in store.list() {
        if contract.is_expired(now) {
            contract.state = ContractState::Expired;
            store.save(contract.clone());
            expired.push(contract.id);
        }
    }
    expired
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{
        MlDsaSigningProvider, SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
    };
    use crate::signature::{BiometricEvidence, SignatureLevel};
    use crate::storage::traits::IdentityRecord;

    fn test_store() -> LexChainStore {
        LexChainStore::new()
    }

    fn register_did(store: &LexChainStore, did: &str) {
        store
            .backend()
            .write_identity(&IdentityRecord {
                did: did.to_string(),
                public_key: "deadbeef".to_string(),
                created_at: 0,
                updated_at: 0,
                status: "active".to_string(),
            })
            .unwrap();
    }

    fn fes_definition() -> ContractDefinition {
        ContractDefinition {
            contract_type: "service_agreement".into(),
            parties: vec![PartyDefinition {
                role: "client".into(),
                did: "did:goya:alice".into(),
                signature_level: SignatureLevel::Simple,
            }],
            payload: serde_json::json!({"terms": "test"}),
            require_notarization: false,
            deadline_secs: None,
        }
    }

    fn two_party_definition() -> ContractDefinition {
        ContractDefinition {
            contract_type: "service_agreement".into(),
            parties: vec![
                PartyDefinition {
                    role: "provider".into(),
                    did: "did:goya:alice".into(),
                    signature_level: SignatureLevel::Simple,
                },
                PartyDefinition {
                    role: "client".into(),
                    did: "did:goya:bob".into(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            payload: serde_json::json!({"terms": "mutual agreement"}),
            require_notarization: true,
            deadline_secs: None,
        }
    }

    fn sign_as(contract: &LexContract, provider: &dyn SigningProvider) -> SignRequest {
        let content_hash = &contract.content_hash;
        let did = &contract.parties.iter().find(|p| !p.signed).unwrap().did;
        let pk_hex = hex::encode(provider.public_key());
        let payload = format!("fes:{}:{}", did, content_hash);
        let sig = provider.sign(payload.as_bytes()).unwrap();
        SignRequest {
            did: did.clone(),
            signature: hex::encode(&sig),
            public_key: pk_hex,
            biometric_evidence: vec![],
        }
    }

    #[test]
    fn deploy_creates_pending_contract() {
        let store = test_store();
        let contract = deploy(&store, fes_definition()).unwrap();
        assert_eq!(contract.state, ContractState::PendingSignatures);
        assert_eq!(contract.parties.len(), 1);
        assert!(!contract.parties[0].signed);
        assert!(store.get(&contract.id).is_some());
    }

    #[test]
    fn deploy_rejects_no_parties() {
        let store = test_store();
        let mut def = fes_definition();
        def.parties.clear();
        assert!(matches!(deploy(&store, def), Err(LexChainError::NoParties)));
    }

    #[test]
    fn sign_advances_to_fully_signed() {
        let store = test_store();
        register_did(&store, "did:goya:alice");
        let contract = deploy(&store, fes_definition()).unwrap();
        let provider = SoftwareSigningProvider::generate();
        let req = sign_as(&contract, &provider);
        let updated = sign(&store, &contract.id, &req).unwrap();
        assert_eq!(updated.state, ContractState::FullySigned);
        assert!(updated.parties[0].signed);
        assert!(updated.parties[0].envelope.is_some());
    }

    #[test]
    fn sign_rejects_unregistered_did() {
        let store = test_store();
        let contract = deploy(&store, fes_definition()).unwrap();
        let provider = SoftwareSigningProvider::generate();
        let req = sign_as(&contract, &provider);
        assert!(matches!(
            sign(&store, &contract.id, &req),
            Err(LexChainError::DidNotRegistered(_))
        ));
    }

    #[test]
    fn sign_rejects_unknown_party() {
        let store = test_store();
        register_did(&store, "did:goya:unknown");
        let contract = deploy(&store, fes_definition()).unwrap();
        let provider = SoftwareSigningProvider::generate();
        let mut req = sign_as(&contract, &provider);
        req.did = "did:goya:unknown".into();
        assert!(matches!(
            sign(&store, &contract.id, &req),
            Err(LexChainError::PartyNotFound(_))
        ));
    }

    #[test]
    fn sign_rejects_after_fully_signed() {
        let store = test_store();
        register_did(&store, "did:goya:alice");
        let contract = deploy(&store, fes_definition()).unwrap();
        let provider = SoftwareSigningProvider::generate();
        let req = sign_as(&contract, &provider);
        let signed = sign(&store, &contract.id, &req).unwrap();
        assert_eq!(signed.state, ContractState::FullySigned);
        assert!(matches!(
            sign(&store, &contract.id, &req),
            Err(LexChainError::InvalidState { .. })
        ));
    }

    #[test]
    fn two_party_flow_pending_until_both_sign() {
        let store = test_store();
        register_did(&store, "did:goya:alice");
        register_did(&store, "did:goya:bob");
        let contract = deploy(&store, two_party_definition()).unwrap();

        let alice = SoftwareSigningProvider::generate();
        let req_a = sign_as(&contract, &alice);
        let after_alice = sign(&store, &contract.id, &req_a).unwrap();
        assert_eq!(after_alice.state, ContractState::PendingSignatures);

        let bob = SoftwareSigningProvider::generate();
        let req_b = SignRequest {
            did: "did:goya:bob".into(),
            signature: {
                let payload = format!("fes:did:goya:bob:{}", contract.content_hash);
                hex::encode(bob.sign(payload.as_bytes()).unwrap())
            },
            public_key: hex::encode(bob.public_key()),
            biometric_evidence: vec![],
        };
        let after_bob = sign(&store, &contract.id, &req_b).unwrap();
        assert_eq!(after_bob.state, ContractState::FullySigned);
    }

    #[test]
    fn notarize_requires_fully_signed() {
        let store = test_store();
        let contract = deploy(&store, fes_definition()).unwrap();
        let signer = std::sync::Arc::new(SoftwareSigningProvider::generate());
        let tsa = TsaProvider::new(signer, "did:goya:tsa".into());
        assert!(matches!(
            notarize(&store, &contract.id, &tsa),
            Err(LexChainError::InvalidState { .. })
        ));
    }

    #[test]
    fn full_lifecycle_deploy_sign_notarize_archive() {
        let store = test_store();
        register_did(&store, "did:goya:alice");
        let contract = deploy(&store, fes_definition()).unwrap();

        let provider = SoftwareSigningProvider::generate();
        let req = sign_as(&contract, &provider);
        let signed = sign(&store, &contract.id, &req).unwrap();
        assert_eq!(signed.state, ContractState::FullySigned);

        let signer = std::sync::Arc::new(SoftwareSigningProvider::generate());
        let tsa = TsaProvider::new(signer, "did:goya:tsa".into());
        let notarized = notarize(&store, &contract.id, &tsa).unwrap();
        assert_eq!(notarized.state, ContractState::Notarized);
        assert!(notarized.tsa_token.is_some());

        let archived = archive(&store, &contract.id).unwrap();
        assert_eq!(archived.state, ContractState::Archived);
        assert!(archived.block_height.is_some());

        let tx = store
            .backend()
            .read_transaction(&format!("lxc-archive:{}", contract.id))
            .unwrap();
        assert_eq!(tx.state, "confirmed");
    }

    #[test]
    fn pqc_fea_lifecycle() {
        let store = test_store();
        register_did(&store, "did:goya:notary");
        let def = ContractDefinition {
            contract_type: "notarial_deed".into(),
            parties: vec![PartyDefinition {
                role: "notary".into(),
                did: "did:goya:notary".into(),
                signature_level: SignatureLevel::Advanced,
            }],
            payload: serde_json::json!({"document": "deed"}),
            require_notarization: true,
            deadline_secs: None,
        };
        let contract = deploy(&store, def).unwrap();

        let provider = MlDsaSigningProvider::generate();
        let pk_hex = hex::encode(provider.public_key());
        let bio_commitment = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let evidence = vec![BiometricEvidence {
            evidence_type: crate::signature::BiometricType::Fingerprint,
            commitment: bio_commitment.into(),
            captured_at: now_secs(),
            capture_device: Some("scanner-1".into()),
        }];
        let bio_hash = crate::signature::compute_biometrics_hash(&evidence);
        let payload = format!("fea:did:goya:notary:{}:{}", contract.content_hash, bio_hash);
        let sig = provider.sign(payload.as_bytes()).unwrap();

        let req = SignRequest {
            did: "did:goya:notary".into(),
            signature: hex::encode(&sig),
            public_key: pk_hex,
            biometric_evidence: evidence,
        };

        let signed = sign(&store, &contract.id, &req).unwrap();
        assert_eq!(signed.state, ContractState::FullySigned);
        assert_eq!(
            signed.parties[0]
                .envelope
                .as_ref()
                .unwrap()
                .signature_algorithm,
            SigningAlgorithm::MlDsa65
        );
    }

    #[test]
    fn archive_writes_transaction_to_store() {
        let store = test_store();
        register_did(&store, "did:goya:alice");
        let contract = deploy(&store, fes_definition()).unwrap();

        let provider = SoftwareSigningProvider::generate();
        let req = sign_as(&contract, &provider);
        sign(&store, &contract.id, &req).unwrap();

        let archived = archive(&store, &contract.id).unwrap();
        assert_eq!(archived.state, ContractState::Archived);

        let tx_id = format!("lxc-archive:{}", contract.id);
        let tx = store.backend().read_transaction(&tx_id).unwrap();
        assert_eq!(tx.output_recipient, "lexchain:archive");
        assert_eq!(tx.input_did, "did:goya:alice");
    }

    #[test]
    fn archive_rejects_pending_contract() {
        let store = test_store();
        let contract = deploy(&store, fes_definition()).unwrap();
        assert!(matches!(
            archive(&store, &contract.id),
            Err(LexChainError::InvalidState { .. })
        ));
    }

    #[test]
    fn persistence_roundtrip() {
        let store = test_store();
        register_did(&store, "did:goya:alice");
        let contract = deploy(&store, fes_definition()).unwrap();
        let id = contract.id.clone();

        let loaded = store.get(&id).unwrap();
        assert_eq!(loaded.definition.contract_type, "service_agreement");
        assert_eq!(loaded.parties.len(), 1);
    }

    fn expired_definition() -> ContractDefinition {
        ContractDefinition {
            contract_type: "urgent_agreement".into(),
            parties: vec![PartyDefinition {
                role: "client".into(),
                did: "did:goya:alice".into(),
                signature_level: SignatureLevel::Simple,
            }],
            payload: serde_json::json!({"terms": "expires fast"}),
            require_notarization: false,
            deadline_secs: Some(1),
        }
    }

    #[test]
    fn contract_without_deadline_never_expires() {
        let store = test_store();
        let contract = deploy(&store, fes_definition()).unwrap();
        assert!(!contract.is_expired(contract.created_at + 999_999));
    }

    #[test]
    fn contract_with_deadline_expires_after_timeout() {
        let store = test_store();
        let contract = deploy(&store, expired_definition()).unwrap();
        assert!(!contract.is_expired(contract.created_at));
        assert!(!contract.is_expired(contract.created_at + 1));
        assert!(contract.is_expired(contract.created_at + 2));
    }

    #[test]
    fn sign_rejects_expired_contract() {
        let store = test_store();
        register_did(&store, "did:goya:alice");
        let mut def = fes_definition();
        def.deadline_secs = Some(0);
        let contract = deploy(&store, def).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let provider = SoftwareSigningProvider::generate();
        let req = sign_as(&contract, &provider);
        let result = sign(&store, &contract.id, &req);
        assert!(matches!(result, Err(LexChainError::Expired)));

        let updated = store.get(&contract.id).unwrap();
        assert_eq!(updated.state, ContractState::Expired);
    }

    #[test]
    fn expire_pending_sweeps_expired_contracts() {
        let store = test_store();
        let mut def = fes_definition();
        def.deadline_secs = Some(0);
        deploy(&store, def).unwrap();

        let no_deadline = deploy(&store, fes_definition()).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let expired_ids = expire_pending(&store);
        assert_eq!(expired_ids.len(), 1);

        let still_pending = store.get(&no_deadline.id).unwrap();
        assert_eq!(still_pending.state, ContractState::PendingSignatures);
    }

    #[test]
    fn signed_contract_with_deadline_does_not_expire() {
        let store = test_store();
        register_did(&store, "did:goya:alice");
        let mut def = fes_definition();
        def.deadline_secs = Some(3600);
        let contract = deploy(&store, def).unwrap();

        let provider = SoftwareSigningProvider::generate();
        let req = sign_as(&contract, &provider);
        let signed = sign(&store, &contract.id, &req).unwrap();
        assert_eq!(signed.state, ContractState::FullySigned);
        assert!(!signed.is_expired(signed.created_at + 7200));
    }

    #[test]
    fn deadline_preserved_in_json_roundtrip() {
        let def = ContractDefinition {
            contract_type: "test".into(),
            parties: vec![PartyDefinition {
                role: "a".into(),
                did: "did:goya:a".into(),
                signature_level: SignatureLevel::Simple,
            }],
            payload: serde_json::json!({}),
            require_notarization: false,
            deadline_secs: Some(259200),
        };
        let json = serde_json::to_string(&def).unwrap();
        let parsed: ContractDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.deadline_secs, Some(259200));
    }

    #[test]
    fn deadline_absent_in_json_defaults_to_none() {
        let json = r#"{"type":"test","parties":[],"payload":{}}"#;
        let parsed: ContractDefinition = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.deadline_secs, None);
    }
}
