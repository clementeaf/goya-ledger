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

pub fn archive(
    store: &LexChainStore,
    contract_id: &str,
    block_height: u64,
) -> Result<LexContract, LexChainError> {
    let mut contract = store
        .get(contract_id)
        .ok_or_else(|| LexChainError::NotFound(contract_id.to_string()))?;

    if contract.state != ContractState::Notarized && contract.state != ContractState::FullySigned {
        return Err(LexChainError::InvalidState {
            expected: "fully_signed or notarized".into(),
            got: contract.state.to_string(),
        });
    }

    contract.block_height = Some(block_height);
    contract.state = ContractState::Archived;

    store.save(contract.clone());
    Ok(contract)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{
        MlDsaSigningProvider, SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
    };
    use crate::signature::{BiometricEvidence, SignatureLevel};

    fn test_store() -> LexChainStore {
        LexChainStore::new()
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
        let contract = deploy(&store, fes_definition()).unwrap();
        let provider = SoftwareSigningProvider::generate();
        let req = sign_as(&contract, &provider);
        let updated = sign(&store, &contract.id, &req).unwrap();
        assert_eq!(updated.state, ContractState::FullySigned);
        assert!(updated.parties[0].signed);
        assert!(updated.parties[0].envelope.is_some());
    }

    #[test]
    fn sign_rejects_unknown_did() {
        let store = test_store();
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

        let archived = archive(&store, &contract.id, 42).unwrap();
        assert_eq!(archived.state, ContractState::Archived);
        assert_eq!(archived.block_height, Some(42));
    }

    #[test]
    fn pqc_fea_lifecycle() {
        let store = test_store();
        let def = ContractDefinition {
            contract_type: "notarial_deed".into(),
            parties: vec![PartyDefinition {
                role: "notary".into(),
                did: "did:goya:notary".into(),
                signature_level: SignatureLevel::Advanced,
            }],
            payload: serde_json::json!({"document": "deed"}),
            require_notarization: true,
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
}
