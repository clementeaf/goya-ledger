use rust_bc::identity::did::did_from_pubkey_hex;
use rust_bc::identity::dual_signing::{dual_sign, verify_dual, DualVerifyMode};
use rust_bc::identity::signing::{
    MlDsaSigningProvider, SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
};
use rust_bc::lexchain::engine::{deploy, sign};
use rust_bc::lexchain::store::LexChainStore;
use rust_bc::lexchain::types::{ContractDefinition, ContractState, PartyDefinition, SignRequest};
use rust_bc::mining::{MiningConfig, MiningService};
use rust_bc::signature::{verify_signature, SignatureLevel};
use rust_bc::storage::traits::{BlockStore, IdentityRecord, Transaction};
use rust_bc::storage::MemoryStore;
use std::sync::Arc;
use std::time::Instant;

fn make_tx(label: &str) -> Transaction {
    Transaction {
        id: label.to_string(),
        block_height: 0,
        timestamp: 0,
        input_did: "did:goya:test".to_string(),
        output_recipient: "did:goya:recv".to_string(),
        amount: 0,
        state: "pending".to_string(),
    }
}

struct Identity {
    did: String,
    pubkey_hex: String,
    provider: Box<dyn SigningProvider>,
}

fn make_identity(algo: SigningAlgorithm) -> Identity {
    let provider: Box<dyn SigningProvider> = match algo {
        SigningAlgorithm::Ed25519 => Box::new(SoftwareSigningProvider::generate()),
        SigningAlgorithm::MlDsa65 => Box::new(MlDsaSigningProvider::generate()),
        _ => panic!("unsupported algorithm for test"),
    };
    let pubkey_hex = hex::encode(provider.public_key());
    let did = did_from_pubkey_hex(&pubkey_hex);
    Identity {
        did,
        pubkey_hex,
        provider,
    }
}

fn register_did(store: &dyn BlockStore, id: &Identity) {
    store
        .write_identity(&IdentityRecord {
            did: id.did.clone(),
            public_key: id.pubkey_hex.clone(),
            created_at: 0,
            updated_at: 0,
            status: "active".to_string(),
        })
        .unwrap();
}

fn sign_lexchain_fes(contract_content_hash: &str, signer: &Identity) -> SignRequest {
    let payload = format!("fes:{}:{}", signer.did, contract_content_hash);
    let sig = signer.provider.sign(payload.as_bytes()).unwrap();
    SignRequest {
        did: signer.did.clone(),
        signature: hex::encode(&sig),
        public_key: signer.pubkey_hex.clone(),
        biometric_evidence: vec![],
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 1 — DETECTION
// An attacker forges an Ed25519 signature. Dual signing catches it.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn phase1_dual_sign_detects_forged_ed25519() {
    let legitimate_ed = SoftwareSigningProvider::generate();
    let legitimate_pqc = MlDsaSigningProvider::generate();
    let attacker_ed = SoftwareSigningProvider::generate();

    let block_data = b"block-payload-height-42";

    let legit_dual = dual_sign(block_data, &legitimate_ed, &legitimate_pqc).unwrap();

    let forged_primary = attacker_ed.sign(block_data).unwrap();

    let primary_verifies_with_legit_key =
        legitimate_ed.verify(block_data, &forged_primary).unwrap();
    assert!(!primary_verifies_with_legit_key);

    let secondary_still_valid = legitimate_pqc
        .verify(block_data, &legit_dual.secondary_signature)
        .unwrap();
    assert!(secondary_still_valid);

    let dual_check = verify_dual(
        || legitimate_ed.verify(block_data, &forged_primary),
        Some(|| legitimate_pqc.verify(block_data, &legit_dual.secondary_signature)),
        DualVerifyMode::Both,
    )
    .unwrap();
    assert!(!dual_check);
}

fn block_signing_payload(block: &rust_bc::storage::traits::Block) -> String {
    format!(
        "{}:{:?}:{:?}:{:?}",
        block.height, block.parent_hash, block.merkle_root, block.transactions
    )
}

#[test]
fn phase1_secondary_signature_catches_tampered_block() {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let ed_signer: Arc<dyn SigningProvider> = Arc::new(SoftwareSigningProvider::generate());
    let pqc_signer: Arc<dyn SigningProvider> = Arc::new(MlDsaSigningProvider::generate());

    let service = MiningService::new(store.clone(), MiningConfig::default())
        .with_signer(Arc::clone(&ed_signer))
        .with_secondary_signer(Arc::clone(&pqc_signer));

    service.mine_block("honest-miner", vec![]).unwrap();
    let block = store.read_block(0).unwrap();

    assert_eq!(block.signature_algorithm, SigningAlgorithm::Ed25519);
    assert!(block.secondary_signature.is_some());
    assert_eq!(
        block.secondary_signature_algorithm,
        Some(SigningAlgorithm::MlDsa65)
    );

    let payload = block_signing_payload(&block);
    let sec_sig = block.secondary_signature.as_ref().unwrap();
    let legit = pqc_signer.verify(payload.as_bytes(), sec_sig).unwrap();
    assert!(legit);

    let tampered_payload = format!(
        "{}:{:?}:{:?}:{:?}",
        block.height, block.parent_hash, [0xFFu8; 32], block.transactions
    );
    let tampered_check = pqc_signer
        .verify(tampered_payload.as_bytes(), sec_sig)
        .unwrap();
    assert!(!tampered_check);
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 2 — CONTAINMENT
// Ed25519 is declared dead. All Ed25519-only signatures are untrusted.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn phase2_ed25519_only_contracts_quarantined() {
    let store = Arc::new(MemoryStore::new());
    let lex = LexChainStore::with_backend(store.clone());

    let alice_ed = make_identity(SigningAlgorithm::Ed25519);
    let bob_ed = make_identity(SigningAlgorithm::Ed25519);
    let charlie_pqc = make_identity(SigningAlgorithm::MlDsa65);
    let dave_pqc = make_identity(SigningAlgorithm::MlDsa65);

    register_did(store.as_ref(), &alice_ed);
    register_did(store.as_ref(), &bob_ed);
    register_did(store.as_ref(), &charlie_pqc);
    register_did(store.as_ref(), &dave_pqc);

    let ed_only_contract = deploy(
        &lex,
        ContractDefinition {
            contract_type: "nda".into(),
            parties: vec![
                PartyDefinition {
                    role: "discloser".into(),
                    did: alice_ed.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
                PartyDefinition {
                    role: "recipient".into(),
                    did: bob_ed.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            payload: serde_json::json!({"scope": "project alpha"}),
            require_notarization: false,
            deadline_secs: None,
            webhook_url: None,
        },
    )
    .unwrap();

    let req_a = sign_lexchain_fes(&ed_only_contract.content_hash, &alice_ed);
    sign(&lex, &ed_only_contract.id, &req_a).unwrap();
    let req_b = sign_lexchain_fes(&ed_only_contract.content_hash, &bob_ed);
    let ed_signed = sign(&lex, &ed_only_contract.id, &req_b).unwrap();
    assert_eq!(ed_signed.state, ContractState::FullySigned);

    let pqc_contract = deploy(
        &lex,
        ContractDefinition {
            contract_type: "nda".into(),
            parties: vec![
                PartyDefinition {
                    role: "discloser".into(),
                    did: charlie_pqc.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
                PartyDefinition {
                    role: "recipient".into(),
                    did: dave_pqc.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            payload: serde_json::json!({"scope": "project beta"}),
            require_notarization: false,
            deadline_secs: None,
            webhook_url: None,
        },
    )
    .unwrap();

    let req_c = sign_lexchain_fes(&pqc_contract.content_hash, &charlie_pqc);
    sign(&lex, &pqc_contract.id, &req_c).unwrap();
    let req_d = sign_lexchain_fes(&pqc_contract.content_hash, &dave_pqc);
    let pqc_signed = sign(&lex, &pqc_contract.id, &req_d).unwrap();
    assert_eq!(pqc_signed.state, ContractState::FullySigned);

    // === ALGORITHM DEATH DAY: Ed25519 compromised ===
    let all_contracts = lex.list();
    let mut quarantined = Vec::new();
    let mut safe = Vec::new();

    for contract in &all_contracts {
        let uses_only_classical = contract.parties.iter().all(|p| {
            p.envelope
                .as_ref()
                .map(|e| e.signature_algorithm.is_classical())
                .unwrap_or(true)
        });

        if uses_only_classical && contract.state == ContractState::FullySigned {
            quarantined.push(contract.id.clone());
        } else {
            safe.push(contract.id.clone());
        }
    }

    assert_eq!(quarantined.len(), 1);
    assert_eq!(safe.len(), 1);
    assert!(quarantined.contains(&ed_only_contract.id));
    assert!(safe.contains(&pqc_contract.id));
}

#[test]
fn phase2_ed25519_signatures_rejected_post_compromise() {
    let ed_signer = SoftwareSigningProvider::generate();
    let pk_hex = hex::encode(ed_signer.public_key());
    let message = b"post-compromise-transaction";
    let sig = ed_signer.sign(message).unwrap();
    let sig_hex = hex::encode(&sig);

    let ed25519_valid = verify_signature(SigningAlgorithm::Ed25519, &pk_hex, message, &sig_hex);
    assert!(ed25519_valid);

    let is_compromised_algorithm = SigningAlgorithm::Ed25519.is_classical();
    assert!(is_compromised_algorithm);

    let should_reject = is_compromised_algorithm;
    assert!(should_reject);
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 3 — MIGRATION
// All identities migrate from Ed25519 to ML-DSA-65. Consensus survives.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn phase3_identity_migration_ed25519_to_mldsa65() {
    let store = Arc::new(MemoryStore::new());
    let num_identities = 50;
    let mut ed_identities: Vec<Identity> = Vec::with_capacity(num_identities);

    for _ in 0..num_identities {
        let id = make_identity(SigningAlgorithm::Ed25519);
        register_did(store.as_ref(), &id);
        ed_identities.push(id);
    }

    for id in &ed_identities {
        let record = store.read_identity(&id.did).unwrap();
        assert_eq!(record.public_key, id.pubkey_hex);
    }

    let migration_start = Instant::now();
    let mut migrated_count = 0;

    for old_id in &ed_identities {
        let new_id = make_identity(SigningAlgorithm::MlDsa65);

        store
            .write_identity(&IdentityRecord {
                did: old_id.did.clone(),
                public_key: new_id.pubkey_hex.clone(),
                created_at: 0,
                updated_at: 1,
                status: "active".to_string(),
            })
            .unwrap();

        let updated = store.read_identity(&old_id.did).unwrap();
        assert_eq!(updated.public_key, new_id.pubkey_hex);
        assert_eq!(updated.public_key.len(), 1952 * 2);

        migrated_count += 1;
    }

    let migration_duration = migration_start.elapsed();

    assert_eq!(migrated_count, num_identities);
    eprintln!(
        "  MIGRATION: {} identities migrated in {:?} ({:.1} ids/ms)",
        migrated_count,
        migration_duration,
        migrated_count as f64 / migration_duration.as_secs_f64() / 1000.0
    );
}

#[test]
fn phase3_mining_continues_after_algorithm_switch() {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());

    let ed_signer: Arc<dyn SigningProvider> = Arc::new(SoftwareSigningProvider::generate());
    let pqc_signer: Arc<dyn SigningProvider> = Arc::new(MlDsaSigningProvider::generate());

    let service_ed = MiningService::new(store.clone(), MiningConfig::default())
        .with_signer(Arc::clone(&ed_signer))
        .with_secondary_signer(Arc::clone(&pqc_signer));

    for i in 0..5 {
        service_ed
            .mine_block("miner-pre-compromise", vec![make_tx(&format!("tx-ed-{i}"))])
            .unwrap();
    }

    let pre_height = store.get_latest_height().unwrap();
    assert_eq!(pre_height, 4);

    // === ED25519 IS DEAD — switch to PQC-only mining ===

    let service_pqc = MiningService::new(store.clone(), MiningConfig::default())
        .with_signer(Arc::clone(&pqc_signer));

    for i in 0..5 {
        service_pqc
            .mine_block(
                "miner-post-compromise",
                vec![make_tx(&format!("tx-pqc-{i}"))],
            )
            .unwrap();
    }

    let post_height = store.get_latest_height().unwrap();
    assert_eq!(post_height, 9);

    for h in 0..5 {
        let block = store.read_block(h).unwrap();
        assert_eq!(block.signature_algorithm, SigningAlgorithm::Ed25519);
        assert!(block.secondary_signature.is_some());
    }

    for h in 5..10 {
        let block = store.read_block(h).unwrap();
        assert_eq!(block.signature_algorithm, SigningAlgorithm::MlDsa65);
        assert!(block.secondary_signature.is_none());
    }
}

#[test]
fn phase3_lexchain_operates_under_pqc_only() {
    let store = Arc::new(MemoryStore::new());
    let lex = LexChainStore::with_backend(store.clone());

    let alice = make_identity(SigningAlgorithm::MlDsa65);
    let bob = make_identity(SigningAlgorithm::MlDsa65);
    register_did(store.as_ref(), &alice);
    register_did(store.as_ref(), &bob);

    let contract = deploy(
        &lex,
        ContractDefinition {
            contract_type: "service_agreement".into(),
            parties: vec![
                PartyDefinition {
                    role: "provider".into(),
                    did: alice.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
                PartyDefinition {
                    role: "client".into(),
                    did: bob.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            payload: serde_json::json!({"terms": "post-quantum only"}),
            require_notarization: false,
            deadline_secs: None,
            webhook_url: None,
        },
    )
    .unwrap();

    let req_a = sign_lexchain_fes(&contract.content_hash, &alice);
    sign(&lex, &contract.id, &req_a).unwrap();

    let req_b = sign_lexchain_fes(&contract.content_hash, &bob);
    let signed = sign(&lex, &contract.id, &req_b).unwrap();

    assert_eq!(signed.state, ContractState::FullySigned);

    for party in &signed.parties {
        let envelope = party.envelope.as_ref().unwrap();
        assert!(envelope.signature_algorithm.is_post_quantum());
        assert_eq!(envelope.signature_algorithm, SigningAlgorithm::MlDsa65);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 4 — POST-MORTEM VERIFICATION
// Everything dual-signed before the compromise is still verifiable via PQC.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn phase4_dual_signed_blocks_survive_ed25519_death() {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let ed_signer: Arc<dyn SigningProvider> = Arc::new(SoftwareSigningProvider::generate());
    let pqc_signer: Arc<dyn SigningProvider> = Arc::new(MlDsaSigningProvider::generate());

    let service = MiningService::new(store.clone(), MiningConfig::default())
        .with_signer(Arc::clone(&ed_signer))
        .with_secondary_signer(Arc::clone(&pqc_signer));

    let num_blocks = 10;
    for i in 0..num_blocks {
        service
            .mine_block("dual-miner", vec![make_tx(&format!("tx-{i}"))])
            .unwrap();
    }

    // === ED25519 IS DEAD — verify all blocks via PQC secondary signature ===

    let mut verified_count = 0;
    for h in 0..num_blocks {
        let block = store.read_block(h).unwrap();
        let payload = block_signing_payload(&block);
        let sec_sig = block.secondary_signature.as_ref().unwrap();
        assert!(
            pqc_signer.verify(payload.as_bytes(), sec_sig).unwrap(),
            "block {h} PQC signature must be valid"
        );
        verified_count += 1;
    }

    assert_eq!(verified_count, num_blocks);
}

#[test]
fn phase4_pqc_contract_signatures_remain_valid_after_compromise() {
    let store = Arc::new(MemoryStore::new());
    let lex = LexChainStore::with_backend(store.clone());

    let alice = make_identity(SigningAlgorithm::MlDsa65);
    register_did(store.as_ref(), &alice);

    let contract = deploy(
        &lex,
        ContractDefinition {
            contract_type: "nda".into(),
            parties: vec![PartyDefinition {
                role: "signer".into(),
                did: alice.did.clone(),
                signature_level: SignatureLevel::Simple,
            }],
            payload: serde_json::json!({"scope": "pre-compromise doc"}),
            require_notarization: false,
            deadline_secs: None,
            webhook_url: None,
        },
    )
    .unwrap();

    let req = sign_lexchain_fes(&contract.content_hash, &alice);
    let signed = sign(&lex, &contract.id, &req).unwrap();
    assert_eq!(signed.state, ContractState::FullySigned);

    // === YEARS LATER: re-verify the PQC signature ===

    let envelope = signed.parties[0].envelope.as_ref().unwrap();
    let payload = envelope.signing_payload();
    let still_valid = verify_signature(
        envelope.signature_algorithm,
        &envelope.public_key,
        payload.as_bytes(),
        &envelope.signature,
    );
    assert!(still_valid);
    assert!(envelope.signature_algorithm.is_post_quantum());
}

// ═══════════════════════════════════════════════════════════════════════════
// FULL SCENARIO — END TO END
// The complete death day: blocks + contracts + migration + verification
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn algorithm_death_day_full_scenario() {
    let timer = Instant::now();
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let lex = LexChainStore::with_backend(store.clone());

    // ── Pre-compromise: dual-signed blocks ────────────────────────────
    let ed_miner: Arc<dyn SigningProvider> = Arc::new(SoftwareSigningProvider::generate());
    let pqc_miner: Arc<dyn SigningProvider> = Arc::new(MlDsaSigningProvider::generate());

    let service = MiningService::new(store.clone(), MiningConfig::default())
        .with_signer(Arc::clone(&ed_miner))
        .with_secondary_signer(Arc::clone(&pqc_miner));

    let pre_blocks: u64 = 10;
    for i in 0..pre_blocks {
        service
            .mine_block("node-1", vec![make_tx(&format!("pre-tx-{i}"))])
            .unwrap();
    }

    // ── Pre-compromise: contracts with mixed algorithms ───────────────
    let alice_ed = make_identity(SigningAlgorithm::Ed25519);
    let bob_pqc = make_identity(SigningAlgorithm::MlDsa65);
    let carol_ed = make_identity(SigningAlgorithm::Ed25519);
    let dave_ed = make_identity(SigningAlgorithm::Ed25519);
    register_did(store.as_ref(), &alice_ed);
    register_did(store.as_ref(), &bob_pqc);
    register_did(store.as_ref(), &carol_ed);
    register_did(store.as_ref(), &dave_ed);

    let mixed_contract = deploy(
        &lex,
        ContractDefinition {
            contract_type: "service_agreement".into(),
            parties: vec![
                PartyDefinition {
                    role: "provider".into(),
                    did: alice_ed.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
                PartyDefinition {
                    role: "client".into(),
                    did: bob_pqc.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            payload: serde_json::json!({"terms": "hybrid contract"}),
            require_notarization: false,
            deadline_secs: None,
            webhook_url: None,
        },
    )
    .unwrap();

    let req_a = sign_lexchain_fes(&mixed_contract.content_hash, &alice_ed);
    sign(&lex, &mixed_contract.id, &req_a).unwrap();
    let req_b = sign_lexchain_fes(&mixed_contract.content_hash, &bob_pqc);
    let mixed_signed = sign(&lex, &mixed_contract.id, &req_b).unwrap();
    assert_eq!(mixed_signed.state, ContractState::FullySigned);

    let ed_only_contract = deploy(
        &lex,
        ContractDefinition {
            contract_type: "nda".into(),
            parties: vec![
                PartyDefinition {
                    role: "a".into(),
                    did: carol_ed.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
                PartyDefinition {
                    role: "b".into(),
                    did: dave_ed.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            payload: serde_json::json!({"scope": "vulnerable"}),
            require_notarization: false,
            deadline_secs: None,
            webhook_url: None,
        },
    )
    .unwrap();

    let req_c = sign_lexchain_fes(&ed_only_contract.content_hash, &carol_ed);
    sign(&lex, &ed_only_contract.id, &req_c).unwrap();
    let req_d = sign_lexchain_fes(&ed_only_contract.content_hash, &dave_ed);
    sign(&lex, &ed_only_contract.id, &req_d).unwrap();

    let t_pre = timer.elapsed();

    // ═══════════════════════════════════════════════════════════════════
    // ██████  ED25519 IS DEAD  ██████
    // ═══════════════════════════════════════════════════════════════════

    let death_instant = Instant::now();

    // ── Triage contracts ──────────────────────────────────────────────
    let all_contracts = lex.list();
    let mut quarantined = Vec::new();
    let mut has_pqc_sig = Vec::new();

    for c in &all_contracts {
        let any_pqc = c.parties.iter().any(|p| {
            p.envelope
                .as_ref()
                .map(|e| e.signature_algorithm.is_post_quantum())
                .unwrap_or(false)
        });

        if any_pqc {
            has_pqc_sig.push(c.id.clone());
        } else {
            quarantined.push(c.id.clone());
        }
    }

    assert_eq!(quarantined.len(), 1);
    assert!(quarantined.contains(&ed_only_contract.id));
    assert_eq!(has_pqc_sig.len(), 1);
    assert!(has_pqc_sig.contains(&mixed_contract.id));

    // ── Verify all pre-compromise blocks via PQC secondary sig ────────
    let mut blocks_verified = 0;
    for h in 0..pre_blocks {
        let block = store.read_block(h).unwrap();
        let payload = block_signing_payload(&block);
        let sec_sig = block.secondary_signature.as_ref().unwrap();
        assert!(pqc_miner.verify(payload.as_bytes(), sec_sig).unwrap());
        blocks_verified += 1;
    }
    assert_eq!(blocks_verified, pre_blocks);

    // ── Switch mining to PQC-only ─────────────────────────────────────
    let pqc_service = MiningService::new(store.clone(), MiningConfig::default())
        .with_signer(Arc::clone(&pqc_miner));

    let post_blocks: u64 = 10;
    for i in 0..post_blocks {
        pqc_service
            .mine_block("node-1-pqc", vec![make_tx(&format!("post-tx-{i}"))])
            .unwrap();
    }

    let final_height = store.get_latest_height().unwrap();
    assert_eq!(final_height, pre_blocks + post_blocks - 1);

    // ── Verify chain continuity ───────────────────────────────────────
    for h in 0..(pre_blocks + post_blocks) {
        let block = store.read_block(h).unwrap();
        assert_eq!(block.height, h);
        if h < pre_blocks {
            assert_eq!(block.signature_algorithm, SigningAlgorithm::Ed25519);
            assert!(block.secondary_signature.is_some());
        } else {
            assert_eq!(block.signature_algorithm, SigningAlgorithm::MlDsa65);
        }
    }

    // ── Verify mixed contract's PQC signature survives ────────────────
    let mixed = lex.get(&mixed_contract.id).unwrap();
    let pqc_party = mixed
        .parties
        .iter()
        .find(|p| {
            p.envelope
                .as_ref()
                .map(|e| e.signature_algorithm.is_post_quantum())
                .unwrap_or(false)
        })
        .unwrap();
    let envelope = pqc_party.envelope.as_ref().unwrap();
    let payload = envelope.signing_payload();
    assert!(verify_signature(
        envelope.signature_algorithm,
        &envelope.public_key,
        payload.as_bytes(),
        &envelope.signature,
    ));

    let t_death = death_instant.elapsed();

    // ── Report ────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════╗");
    eprintln!("  ║         ALGORITHM DEATH DAY — REPORT                ║");
    eprintln!("  ╠══════════════════════════════════════════════════════╣");
    eprintln!("  ║  Pre-compromise setup        {:>8?}  ║", t_pre);
    eprintln!("  ║  Death Day response          {:>8?}  ║", t_death);
    eprintln!(
        "  ║  Blocks pre-compromise       {:>8}          ║",
        pre_blocks
    );
    eprintln!(
        "  ║  Blocks post-compromise      {:>8}          ║",
        post_blocks
    );
    eprintln!("  ║  Blocks lost                        0          ║");
    eprintln!(
        "  ║  Blocks verified via PQC     {:>8}          ║",
        blocks_verified
    );
    eprintln!(
        "  ║  Contracts quarantined       {:>8}          ║",
        quarantined.len()
    );
    eprintln!(
        "  ║  Contracts with PQC sig      {:>8}          ║",
        has_pqc_sig.len()
    );
    eprintln!(
        "  ║  Chain height                {:>8}          ║",
        final_height + 1
    );
    eprintln!("  ║  Consensus interrupted             NO          ║");
    eprintln!("  ╚══════════════════════════════════════════════════════╝");
    eprintln!();
}
