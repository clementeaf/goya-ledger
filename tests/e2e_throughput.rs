use std::time::Instant;

use rust_bc::consensus::bft::quorum::SignatureVerifier;
use rust_bc::consensus::bft::round::{BftRound, RoundEvent, RoundState};
use rust_bc::consensus::bft::types::{BftPhase, VoteMessage};
use rust_bc::endorsement::types::Endorsement;
use rust_bc::identity::signing::{
    MlDsaSigningProvider, SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
};
use rust_bc::storage::traits::Transaction;
use rust_bc::storage::MemoryWorldState;
use rust_bc::storage::WorldState;
use rust_bc::transaction::endorsed::EndorsedTransaction;
use rust_bc::transaction::executor::execute_block_parallel;
use rust_bc::transaction::proposal::TransactionProposal;
use rust_bc::transaction::rwset::{KVRead, KVWrite, ReadWriteSet};

#[derive(Clone)]
struct CryptoVerifier {
    algorithm: SigningAlgorithm,
    keys: Vec<(String, Vec<u8>)>,
}

impl SignatureVerifier for CryptoVerifier {
    fn verify(&self, voter_id: &str, data: &[u8], sig: &[u8]) -> bool {
        let Some((_, pk)) = self.keys.iter().find(|(id, _)| id == voter_id) else {
            return false;
        };
        rust_bc::signature::verify_signature(
            self.algorithm,
            &hex::encode(pk),
            data,
            &hex::encode(sig),
        )
    }
}

fn make_endorsed_with_sig(
    id: &str,
    key: &str,
    version: u64,
    provider: &dyn SigningProvider,
) -> EndorsedTransaction {
    let rw = ReadWriteSet {
        reads: vec![KVRead {
            key: key.into(),
            version,
        }],
        writes: vec![KVWrite {
            key: key.into(),
            value: vec![1u8; 32],
        }],
    };
    let payload = format!("tx:{id}:{key}");
    let sig = provider.sign(payload.as_bytes()).unwrap();
    EndorsedTransaction {
        proposal: TransactionProposal {
            tx: Transaction {
                id: id.into(),
                block_height: 0,
                timestamp: 0,
                input_did: "did:goya:sender".into(),
                output_recipient: "did:goya:recv".into(),
                amount: 1,
                state: "pending".into(),
            },
            creator_did: "did:goya:creator".into(),
            creator_signature: sig,
            rwset: rw.clone(),
            signature_algorithm: provider.algorithm(),
        },
        endorsements: vec![Endorsement {
            signer_did: "did:goya:endorser".into(),
            org_id: "Org1".into(),
            signature: vec![1u8; 64],
            payload_hash: [0u8; 32],
            timestamp: 0,
            signature_algorithm: Default::default(),
        }],
        rwset: rw,
    }
}

struct PipelineResult {
    blocks: usize,
    txs_per_block: usize,
    total_ms: f64,
    bft_ms: f64,
    exec_ms: f64,
    sign_ms: f64,
}

impl PipelineResult {
    fn total_txs(&self) -> usize {
        self.blocks * self.txs_per_block
    }
    fn tps(&self) -> f64 {
        self.total_txs() as f64 / (self.total_ms / 1000.0)
    }
    fn blocks_per_sec(&self) -> f64 {
        self.blocks as f64 / (self.total_ms / 1000.0)
    }
    fn latency_per_block_ms(&self) -> f64 {
        self.total_ms / self.blocks as f64
    }
}

fn run_pipeline(algo: SigningAlgorithm, blocks: usize, txs_per_block: usize) -> PipelineResult {
    pqc_crypto_module::api::initialize_approved_mode().ok();

    let validators: Vec<Box<dyn SigningProvider>> = (0..4)
        .map(|_| -> Box<dyn SigningProvider> {
            match algo {
                SigningAlgorithm::Ed25519 => Box::new(SoftwareSigningProvider::generate()),
                SigningAlgorithm::MlDsa65 => Box::new(MlDsaSigningProvider::generate()),
                _ => unreachable!(),
            }
        })
        .collect();

    let validator_ids: Vec<String> = (0..4).map(|i| format!("v{i}")).collect();
    let verifier = CryptoVerifier {
        algorithm: algo,
        keys: validator_ids
            .iter()
            .zip(validators.iter())
            .map(|(id, p)| (id.clone(), p.public_key()))
            .collect(),
    };

    let tx_signer = match algo {
        SigningAlgorithm::Ed25519 => {
            Box::new(SoftwareSigningProvider::generate()) as Box<dyn SigningProvider>
        }
        SigningAlgorithm::MlDsa65 => Box::new(MlDsaSigningProvider::generate()),
        _ => unreachable!(),
    };

    let state = MemoryWorldState::new();
    let mut bft_total = std::time::Duration::ZERO;
    let mut exec_total = std::time::Duration::ZERO;
    let mut sign_total = std::time::Duration::ZERO;

    let total_start = Instant::now();

    for block_num in 0..blocks as u64 {
        let bh = {
            let mut h = [0u8; 32];
            h[..8].copy_from_slice(&block_num.to_le_bytes());
            h
        };

        let bft_start = Instant::now();
        let leader_idx = (block_num as usize) % 4;
        let mut r = BftRound::new(
            block_num,
            validator_ids[leader_idx].clone(),
            validator_ids[leader_idx].clone(),
            validator_ids.clone(),
            verifier.clone(),
        );
        r.process(RoundEvent::StartAsLeader { block_hash: bh });

        for phase in [BftPhase::Prepare, BftPhase::PreCommit, BftPhase::Commit] {
            for (i, provider) in validators.iter().enumerate().take(3) {
                let payload =
                    VoteMessage::signing_payload_v2(phase, &bh, block_num, &validator_ids[i]);
                let sig = provider.sign(&payload).unwrap();
                r.process(RoundEvent::Vote(VoteMessage {
                    block_hash: bh,
                    round: block_num,
                    phase,
                    voter_id: validator_ids[i].clone(),
                    signature: sig,
                }));
            }
        }
        assert_eq!(r.state(), RoundState::Decided);
        bft_total += bft_start.elapsed();

        let sign_start = Instant::now();
        let txs: Vec<EndorsedTransaction> = (0..txs_per_block)
            .map(|i| {
                let key = format!("b{block_num}_k{i}");
                state.put(&key, b"v1").unwrap();
                make_endorsed_with_sig(&format!("b{block_num}_tx{i}"), &key, 1, tx_signer.as_ref())
            })
            .collect();
        sign_total += sign_start.elapsed();

        let exec_start = Instant::now();
        let result = execute_block_parallel(&txs, &state);
        assert_eq!(result.committed_count, txs_per_block);
        exec_total += exec_start.elapsed();
    }

    let total_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    PipelineResult {
        blocks,
        txs_per_block,
        total_ms,
        bft_ms: bft_total.as_secs_f64() * 1000.0,
        exec_ms: exec_total.as_secs_f64() * 1000.0,
        sign_ms: sign_total.as_secs_f64() * 1000.0,
    }
}

#[test]
fn e2e_throughput_ed25519_vs_mldsa65() {
    let blocks = 20;
    let txs = 100;

    let ed = run_pipeline(SigningAlgorithm::Ed25519, blocks, txs);
    let ml = run_pipeline(SigningAlgorithm::MlDsa65, blocks, txs);

    eprintln!();
    eprintln!("  ╔═══════════════════════════════════════════════════════════════════════════╗");
    eprintln!(
        "  ║  END-TO-END THROUGHPUT — Real Crypto ({blocks} blocks x {txs} txs)                  ║"
    );
    eprintln!("  ║  BFT consensus + tx signing + parallel execution + world state            ║");
    eprintln!("  ╠═══════════════════╤═══════════════════╤═══════════════════╤═══════════════╣");
    eprintln!("  ║                   │ Ed25519           │ ML-DSA-65         │ Overhead      ║");
    eprintln!("  ╠═══════════════════╪═══════════════════╪═══════════════════╪═══════════════╣");
    eprintln!(
        "  ║  TPS              │ {:>13.0}     │ {:>13.0}     │ {:>9.1}x    ║",
        ed.tps(),
        ml.tps(),
        ed.tps() / ml.tps()
    );
    eprintln!(
        "  ║  Blocks/sec       │ {:>13.0}     │ {:>13.0}     │ {:>9.1}x    ║",
        ed.blocks_per_sec(),
        ml.blocks_per_sec(),
        ed.blocks_per_sec() / ml.blocks_per_sec()
    );
    eprintln!(
        "  ║  Block latency    │ {:>11.2} ms  │ {:>11.2} ms  │ {:>9.1}x    ║",
        ed.latency_per_block_ms(),
        ml.latency_per_block_ms(),
        ml.latency_per_block_ms() / ed.latency_per_block_ms()
    );
    eprintln!("  ╠═══════════════════╪═══════════════════╪═══════════════════╪═══════════════╣");
    eprintln!("  ║  TIME BREAKDOWN:  │                   │                   │               ║");
    eprintln!(
        "  ║  BFT consensus    │ {:>11.2} ms  │ {:>11.2} ms  │ {:>9.1}x    ║",
        ed.bft_ms,
        ml.bft_ms,
        ml.bft_ms / ed.bft_ms
    );
    eprintln!(
        "  ║  Tx signing       │ {:>11.2} ms  │ {:>11.2} ms  │ {:>9.1}x    ║",
        ed.sign_ms,
        ml.sign_ms,
        ml.sign_ms / ed.sign_ms
    );
    eprintln!(
        "  ║  Execution        │ {:>11.2} ms  │ {:>11.2} ms  │ {:>9.1}x    ║",
        ed.exec_ms,
        ml.exec_ms,
        ml.exec_ms / ed.exec_ms
    );
    eprintln!("  ╠═══════════════════╧═══════════════════╧═══════════════════╧═══════════════╣");

    let ed_bft_pct = ed.bft_ms / ed.total_ms * 100.0;
    let ed_sign_pct = ed.sign_ms / ed.total_ms * 100.0;
    let ed_exec_pct = ed.exec_ms / ed.total_ms * 100.0;
    let ml_bft_pct = ml.bft_ms / ml.total_ms * 100.0;
    let ml_sign_pct = ml.sign_ms / ml.total_ms * 100.0;
    let ml_exec_pct = ml.exec_ms / ml.total_ms * 100.0;

    eprintln!("  ║  % OF TOTAL:                                                              ║");
    eprintln!(
        "  ║  Ed25519:  BFT {:>5.1}%  Sign {:>5.1}%  Exec {:>5.1}%                       ║",
        ed_bft_pct, ed_sign_pct, ed_exec_pct
    );
    eprintln!(
        "  ║  ML-DSA:   BFT {:>5.1}%  Sign {:>5.1}%  Exec {:>5.1}%                       ║",
        ml_bft_pct, ml_sign_pct, ml_exec_pct
    );
    eprintln!("  ╠═══════════════════════════════════════════════════════════════════════════╣");

    let bottleneck = if ml_bft_pct > ml_sign_pct && ml_bft_pct > ml_exec_pct {
        "BFT CONSENSUS"
    } else if ml_sign_pct > ml_exec_pct {
        "TX SIGNING"
    } else {
        "EXECUTION"
    };
    eprintln!("  ║  BOTTLENECK (ML-DSA-65): {:<50}  ║", bottleneck);
    eprintln!("  ╚═══════════════════════════════════════════════════════════════════════════╝");
    eprintln!();

    assert!(
        ml.tps() > 1000.0,
        "ML-DSA-65 end-to-end TPS must exceed 1000, got {:.0}",
        ml.tps()
    );
    assert!(
        ml.latency_per_block_ms() < 100.0,
        "ML-DSA-65 block latency must be <100ms, got {:.2}ms",
        ml.latency_per_block_ms()
    );
}

#[test]
fn e2e_scaling_txs_per_block() {
    let tx_counts = [10, 50, 100, 200, 500];

    eprintln!();
    eprintln!("  ╔═══════════════════════════════════════════════════════════════╗");
    eprintln!("  ║  SCALING: TPS vs Block Size (ML-DSA-65, 10 blocks)           ║");
    eprintln!("  ╠═══════════════╤═══════════════╤═══════════════╤═════════════╣");
    eprintln!("  ║  Txs/Block    │ TPS           │ Block lat(ms) │ Bottleneck  ║");
    eprintln!("  ╠═══════════════╪═══════════════╪═══════════════╪═════════════╣");

    for n in tx_counts {
        let r = run_pipeline(SigningAlgorithm::MlDsa65, 10, n);
        let bottleneck = if r.bft_ms > r.sign_ms && r.bft_ms > r.exec_ms {
            "BFT"
        } else if r.sign_ms > r.exec_ms {
            "Sign"
        } else {
            "Exec"
        };
        eprintln!(
            "  ║  {:>11}  │ {:>11.0}  │ {:>11.2}  │ {:>9}  ║",
            n,
            r.tps(),
            r.latency_per_block_ms(),
            bottleneck
        );
    }

    eprintln!("  ╚═══════════════╧═══════════════╧═══════════════╧═════════════╝");
    eprintln!();
}
