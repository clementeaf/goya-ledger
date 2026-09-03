use std::time::Instant;

use rust_bc::consensus::bft::quorum::SignatureVerifier;
use rust_bc::consensus::bft::round::{BftRound, RoundEvent, RoundState};
use rust_bc::consensus::bft::types::{BftPhase, VoteMessage};
use rust_bc::identity::signing::{
    MlDsaSigningProvider, SigningAlgorithm, SigningProvider, SlhDsaSigningProvider,
    SoftwareSigningProvider,
};

const ITERATIONS: usize = 100;
const PAYLOAD: &[u8] = b"benchmark-payload-for-pqc-comparative-analysis-2026";

struct BenchResult {
    algorithm: &'static str,
    keygen_us: f64,
    sign_us: f64,
    verify_us: f64,
    pubkey_bytes: usize,
    sig_bytes: usize,
}

fn bench_provider(
    name: &'static str,
    gen: fn() -> Box<dyn SigningProvider>,
    iterations: usize,
) -> BenchResult {
    pqc_crypto_module::api::initialize_approved_mode().ok();

    let start = Instant::now();
    let providers: Vec<_> = (0..iterations).map(|_| gen()).collect();
    let keygen_total = start.elapsed();

    let sigs: Vec<Vec<u8>> = providers.iter().map(|p| p.sign(PAYLOAD).unwrap()).collect();

    let start = Instant::now();
    for p in &providers {
        p.sign(PAYLOAD).unwrap();
    }
    let sign_total = start.elapsed();

    let start = Instant::now();
    for (p, sig) in providers.iter().zip(sigs.iter()) {
        assert!(p.verify(PAYLOAD, sig).unwrap());
    }
    let verify_total = start.elapsed();

    BenchResult {
        algorithm: name,
        keygen_us: keygen_total.as_micros() as f64 / iterations as f64,
        sign_us: sign_total.as_micros() as f64 / iterations as f64,
        verify_us: verify_total.as_micros() as f64 / iterations as f64,
        pubkey_bytes: providers[0].public_key().len(),
        sig_bytes: sigs[0].len(),
    }
}

#[test]
fn pqc_comparative_sign_verify_benchmark() {
    let ed25519 = bench_provider(
        "Ed25519",
        || Box::new(SoftwareSigningProvider::generate()),
        ITERATIONS,
    );

    let mldsa = bench_provider(
        "ML-DSA-65",
        || Box::new(MlDsaSigningProvider::generate()),
        ITERATIONS,
    );

    let slhdsa = bench_provider(
        "SLH-DSA-128s",
        || Box::new(SlhDsaSigningProvider::generate()),
        ITERATIONS / 10,
    );

    let results = [&ed25519, &mldsa, &slhdsa];

    eprintln!();
    eprintln!(
        "  ╔════════════════════════════════════════════════════════════════════════════════╗"
    );
    eprintln!("  ║  PQC Comparative Benchmark — Sign / Verify / KeyGen                          ║");
    eprintln!(
        "  ║  {} iterations (SLH-DSA: {})                                                ║",
        ITERATIONS,
        ITERATIONS / 10
    );
    eprintln!(
        "  ╠══════════════╤════════════╤════════════╤════════════╤══════════╤═══════════════╣"
    );
    eprintln!(
        "  ║  Algorithm   │ KeyGen(µs) │  Sign(µs)  │ Verify(µs) │  PK(B)  │   Sig(B)      ║"
    );
    eprintln!(
        "  ╠══════════════╪════════════╪════════════╪════════════╪══════════╪═══════════════╣"
    );
    for r in &results {
        eprintln!(
            "  ║  {:<12} │ {:>10.1} │ {:>10.1} │ {:>10.1} │ {:>7} │ {:>13} ║",
            r.algorithm, r.keygen_us, r.sign_us, r.verify_us, r.pubkey_bytes, r.sig_bytes
        );
    }
    eprintln!(
        "  ╠══════════════╧════════════╧════════════╧════════════╧══════════╧═══════════════╣"
    );

    let sign_overhead = mldsa.sign_us / ed25519.sign_us;
    let verify_overhead = mldsa.verify_us / ed25519.verify_us;
    let sig_size_ratio = mldsa.sig_bytes as f64 / ed25519.sig_bytes as f64;

    eprintln!(
        "  ║  OVERHEAD (ML-DSA-65 vs Ed25519):                                             ║"
    );
    eprintln!(
        "  ║    Sign:   {:.1}x                                                             ║",
        sign_overhead
    );
    eprintln!(
        "  ║    Verify: {:.1}x                                                             ║",
        verify_overhead
    );
    eprintln!(
        "  ║    Sig size: {:.1}x ({} B vs {} B)                                            ║",
        sig_size_ratio, mldsa.sig_bytes, ed25519.sig_bytes
    );
    eprintln!(
        "  ╚════════════════════════════════════════════════════════════════════════════════╝"
    );
    eprintln!();

    assert_eq!(ed25519.sig_bytes, 64);
    assert_eq!(mldsa.sig_bytes, 3309);
    assert_eq!(slhdsa.sig_bytes, 7856);
    assert_eq!(ed25519.pubkey_bytes, 32);
    assert_eq!(mldsa.pubkey_bytes, 1952);
    assert_eq!(slhdsa.pubkey_bytes, 32);
}

#[test]
fn pqc_block_size_impact() {
    pqc_crypto_module::api::initialize_approved_mode().ok();

    let endorsement_counts = [1, 3, 5, 10, 20];

    let base_block_bytes: usize = 32 + 32 + 8 + 8 + 64;

    eprintln!();
    eprintln!(
        "  ╔════════════════════════════════════════════════════════════════════════════════╗"
    );
    eprintln!(
        "  ║  Block Size Impact — Endorsement Count x Signature Algorithm                  ║"
    );
    eprintln!(
        "  ╠════════════════╤════════════════╤════════════════╤════════════════════════════╣"
    );
    eprintln!(
        "  ║  Endorsements  │ Ed25519 (KB)   │ ML-DSA-65 (KB) │ Overhead                   ║"
    );
    eprintln!(
        "  ╠════════════════╪════════════════╪════════════════╪════════════════════════════╣"
    );

    for n in endorsement_counts {
        let ed_block = base_block_bytes + 64 + n * (64 + 32 + 64);
        let ml_block = base_block_bytes + 3309 + n * (3309 + 32 + 1952);

        let ed_kb = ed_block as f64 / 1024.0;
        let ml_kb = ml_block as f64 / 1024.0;
        let ratio = ml_kb / ed_kb;

        eprintln!(
            "  ║  {:>12}  │ {:>12.1}  │ {:>12.1}  │ {:>10.1}x                   ║",
            n, ed_kb, ml_kb, ratio
        );
    }
    eprintln!(
        "  ╚════════════════╧════════════════╧════════════════╧════════════════════════════╝"
    );
    eprintln!();

    let ml_20_endorsements = base_block_bytes + 3309 + 20 * (3309 + 32 + 1952);
    assert!(
        ml_20_endorsements < 200_000,
        "ML-DSA-65 block with 20 endorsements must be under 200KB, got {} bytes",
        ml_20_endorsements
    );
}

#[derive(Clone)]
struct RealVerifier {
    algorithm: SigningAlgorithm,
    providers: Vec<(String, Vec<u8>)>,
}

impl SignatureVerifier for RealVerifier {
    fn verify(&self, voter_id: &str, data: &[u8], sig: &[u8]) -> bool {
        let Some((_, pk)) = self.providers.iter().find(|(id, _)| id == voter_id) else {
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

#[test]
fn pqc_bft_round_latency_comparative() {
    pqc_crypto_module::api::initialize_approved_mode().ok();

    let rounds = 20;

    let ed_latency = bft_rounds_with_algorithm(SigningAlgorithm::Ed25519, rounds);
    let ml_latency = bft_rounds_with_algorithm(SigningAlgorithm::MlDsa65, rounds);

    let overhead = ml_latency / ed_latency;

    eprintln!();
    eprintln!("  ╔════════════════════════════════════════════════════════════════╗");
    eprintln!(
        "  ║  BFT Round Latency — Real Cryptography ({} rounds)           ║",
        rounds
    );
    eprintln!("  ╠══════════════════════╤═════════════════════════════════════════╣");
    eprintln!(
        "  ║  Ed25519             │ {:>10.2} ms/round                      ║",
        ed_latency
    );
    eprintln!(
        "  ║  ML-DSA-65           │ {:>10.2} ms/round                      ║",
        ml_latency
    );
    eprintln!(
        "  ║  Overhead            │ {:>10.1}x                              ║",
        overhead
    );
    eprintln!("  ╠══════════════════════╧═════════════════════════════════════════╣");
    eprintln!("  ║  3 phases x 3 votes = 9 sign + 9 verify per round            ║");
    eprintln!("  ╚════════════════════════════════════════════════════════════════╝");
    eprintln!();

    assert!(
        ml_latency < 500.0,
        "ML-DSA-65 BFT round must complete in <500ms, got {:.2}ms",
        ml_latency
    );
}

fn bft_rounds_with_algorithm(algo: SigningAlgorithm, rounds: usize) -> f64 {
    let validators: Vec<Box<dyn SigningProvider>> = (0..4)
        .map(|_| match algo {
            SigningAlgorithm::Ed25519 => {
                Box::new(SoftwareSigningProvider::generate()) as Box<dyn SigningProvider>
            }
            SigningAlgorithm::MlDsa65 => {
                Box::new(MlDsaSigningProvider::generate()) as Box<dyn SigningProvider>
            }
            _ => unreachable!(),
        })
        .collect();

    let validator_ids: Vec<String> = (0..4).map(|i| format!("v{i}")).collect();
    let validator_pks: Vec<(String, Vec<u8>)> = validator_ids
        .iter()
        .zip(validators.iter())
        .map(|(id, p)| (id.clone(), p.public_key()))
        .collect();

    let verifier = RealVerifier {
        algorithm: algo,
        providers: validator_pks,
    };

    let start = Instant::now();

    for round in 0..rounds as u64 {
        let bh = {
            let mut h = [0u8; 32];
            h[..8].copy_from_slice(&round.to_le_bytes());
            h
        };

        let leader_idx = (round as usize) % 4;
        let mut r = BftRound::new(
            round,
            validator_ids[leader_idx].clone(),
            validator_ids[leader_idx].clone(),
            validator_ids.clone(),
            verifier.clone(),
        );

        r.process(RoundEvent::StartAsLeader { block_hash: bh });

        for phase in [BftPhase::Prepare, BftPhase::PreCommit, BftPhase::Commit] {
            for (i, provider) in validators.iter().enumerate().take(3) {
                let payload = VoteMessage::signing_payload_v2(phase, &bh, round, &validator_ids[i]);
                let sig = provider.sign(&payload).unwrap();
                let vote = VoteMessage {
                    block_hash: bh,
                    round,
                    phase,
                    voter_id: validator_ids[i].clone(),
                    signature: sig,
                };
                r.process(RoundEvent::Vote(vote));
            }
        }

        assert_eq!(r.state(), RoundState::Decided, "round {round} must decide");
    }

    let total_ms = start.elapsed().as_secs_f64() * 1000.0;
    total_ms / rounds as f64
}

#[test]
fn pqc_hybrid_signature_overhead() {
    pqc_crypto_module::api::initialize_approved_mode().ok();

    let iterations = 50;

    let classical = SoftwareSigningProvider::generate();
    let pqc = MlDsaSigningProvider::generate();

    let signer = "did:goya:bench";
    let content_hash = "aa".repeat(32);
    let payload_fes = format!("fes:{signer}:{content_hash}");

    let start = Instant::now();
    for _ in 0..iterations {
        classical.sign(payload_fes.as_bytes()).unwrap();
    }
    let classical_only_us = start.elapsed().as_micros() as f64 / iterations as f64;

    let start = Instant::now();
    for _ in 0..iterations {
        classical.sign(payload_fes.as_bytes()).unwrap();
        pqc.sign(payload_fes.as_bytes()).unwrap();
    }
    let hybrid_sign_us = start.elapsed().as_micros() as f64 / iterations as f64;

    let classical_sig = classical.sign(payload_fes.as_bytes()).unwrap();
    let pqc_sig = pqc.sign(payload_fes.as_bytes()).unwrap();

    let start = Instant::now();
    for _ in 0..iterations {
        classical
            .verify(payload_fes.as_bytes(), &classical_sig)
            .unwrap();
    }
    let classical_verify_us = start.elapsed().as_micros() as f64 / iterations as f64;

    let start = Instant::now();
    for _ in 0..iterations {
        classical
            .verify(payload_fes.as_bytes(), &classical_sig)
            .unwrap();
        pqc.verify(payload_fes.as_bytes(), &pqc_sig).unwrap();
    }
    let hybrid_verify_us = start.elapsed().as_micros() as f64 / iterations as f64;

    let sign_overhead = hybrid_sign_us / classical_only_us;
    let verify_overhead = hybrid_verify_us / classical_verify_us;

    eprintln!();
    eprintln!("  ╔════════════════════════════════════════════════════════════════╗");
    eprintln!("  ║  Hybrid Signature Overhead (ANSSI-compliant)                  ║");
    eprintln!("  ║  Ed25519 + ML-DSA-65 dual signature                           ║");
    eprintln!("  ╠══════════════════════╤═════════════════════════════════════════╣");
    eprintln!(
        "  ║  Classical sign       │ {:>10.1} µs                            ║",
        classical_only_us
    );
    eprintln!(
        "  ║  Hybrid sign          │ {:>10.1} µs                            ║",
        hybrid_sign_us
    );
    eprintln!(
        "  ║  Sign overhead        │ {:>10.1}x                              ║",
        sign_overhead
    );
    eprintln!("  ╠══════════════════════╪═════════════════════════════════════════╣");
    eprintln!(
        "  ║  Classical verify     │ {:>10.1} µs                            ║",
        classical_verify_us
    );
    eprintln!(
        "  ║  Hybrid verify        │ {:>10.1} µs                            ║",
        hybrid_verify_us
    );
    eprintln!(
        "  ║  Verify overhead      │ {:>10.1}x                              ║",
        verify_overhead
    );
    eprintln!("  ╠══════════════════════╪═════════════════════════════════════════╣");
    eprintln!(
        "  ║  Bandwidth            │ {} B (64 + 3309 + 1952 pk)             ║",
        64 + 3309 + 1952
    );
    eprintln!("  ╚══════════════════════╧═════════════════════════════════════════╝");
    eprintln!();

    assert!(
        hybrid_sign_us < 50_000.0,
        "Hybrid sign must complete in <50ms, got {:.0}µs",
        hybrid_sign_us
    );
    assert!(
        hybrid_verify_us < 10_000.0,
        "Hybrid verify must complete in <10ms, got {:.0}µs",
        hybrid_verify_us
    );
}

#[test]
fn pqc_kem_benchmark() {
    pqc_crypto_module::api::initialize_approved_mode().ok();

    let iterations = 100;

    let start = Instant::now();
    let keypairs: Vec<_> = (0..iterations)
        .map(|_| pqc_crypto_module::api::generate_mlkem_keypair().unwrap())
        .collect();
    let keygen_us = start.elapsed().as_micros() as f64 / iterations as f64;

    let start = Instant::now();
    let encapsulated: Vec<_> = keypairs
        .iter()
        .map(|kp| pqc_crypto_module::api::mlkem_encapsulate(&kp.public_key).unwrap())
        .collect();
    let encap_us = start.elapsed().as_micros() as f64 / iterations as f64;

    let start = Instant::now();
    for (kp, (ct, _)) in keypairs.iter().zip(encapsulated.iter()) {
        let _ = pqc_crypto_module::api::mlkem_decapsulate(&kp.private_key, ct).unwrap();
    }
    let decap_us = start.elapsed().as_micros() as f64 / iterations as f64;

    let pk_bytes = keypairs[0].public_key.as_bytes().len();
    let ct_bytes = encapsulated[0].0.as_bytes().len();
    let ss_bytes = encapsulated[0].1.as_bytes().len();

    eprintln!();
    eprintln!("  ╔════════════════════════════════════════════════════════════════╗");
    eprintln!("  ║  ML-KEM-768 Benchmark (FIPS 203) — TLS Key Exchange           ║");
    eprintln!("  ╠══════════════════════╤═════════════════════════════════════════╣");
    eprintln!(
        "  ║  KeyGen              │ {:>10.1} µs                            ║",
        keygen_us
    );
    eprintln!(
        "  ║  Encapsulate         │ {:>10.1} µs                            ║",
        encap_us
    );
    eprintln!(
        "  ║  Decapsulate         │ {:>10.1} µs                            ║",
        decap_us
    );
    eprintln!("  ╠══════════════════════╪═════════════════════════════════════════╣");
    eprintln!(
        "  ║  Public key          │ {:>10} B                              ║",
        pk_bytes
    );
    eprintln!(
        "  ║  Ciphertext          │ {:>10} B                              ║",
        ct_bytes
    );
    eprintln!(
        "  ║  Shared secret       │ {:>10} B                              ║",
        ss_bytes
    );
    eprintln!("  ╠══════════════════════╧═════════════════════════════════════════╣");
    eprintln!(
        "  ║  TLS overhead vs X25519: +{} B per handshake (pk+ct)          ║",
        pk_bytes + ct_bytes - 64
    );
    eprintln!("  ╚════════════════════════════════════════════════════════════════╝");
    eprintln!();

    assert_eq!(pk_bytes, 1184);
    assert_eq!(ct_bytes, 1088);
    assert_eq!(ss_bytes, 32);
}
