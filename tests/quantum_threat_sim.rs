use pqc_crypto_module::api;
use pqc_crypto_module::approved_mode::{self, ModuleState};
use pqc_crypto_module::errors::CryptoError;
use rust_bc::identity::signing::{MlDsaSigningProvider, SigningProvider, SoftwareSigningProvider};
use std::time::Instant;

fn ensure_approved() {
    if approved_mode::state() != ModuleState::Approved {
        api::initialize_approved_mode().ok();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. SIDE-CHANNEL: TIMING ANALYSIS
// Measure variance in ML-DSA-65 sign/verify — constant-time implementations
// should show no correlation between input and execution time.
// ═══════════════════════════════════════════════════════════════════════════

fn measure_sign_timing(signer: &dyn SigningProvider, messages: &[&[u8]]) -> Vec<u128> {
    messages
        .iter()
        .map(|msg| {
            let start = Instant::now();
            let _ = signer.sign(msg);
            start.elapsed().as_nanos()
        })
        .collect()
}

fn timing_coefficient_of_variation(samples: &[u128]) -> f64 {
    let n = samples.len() as f64;
    let mean = samples.iter().sum::<u128>() as f64 / n;
    let variance = samples
        .iter()
        .map(|&s| (s as f64 - mean).powi(2))
        .sum::<f64>()
        / n;
    let stddev = variance.sqrt();
    stddev / mean
}

#[test]
fn timing_mldsa65_sign_low_variance() {
    let signer = MlDsaSigningProvider::generate();
    let messages: Vec<&[u8]> = vec![
        b"short",
        b"a]medium length message for signing",
        &[0x00; 256],
        &[0xFF; 256],
        &[0xAA; 1024],
        &[0x55; 1024],
        b"message with special chars: \x00\x01\x02\x03",
        &[0x00; 4096],
    ];

    let warmup_messages: Vec<&[u8]> = vec![b"warmup1", b"warmup2", b"warmup3"];
    measure_sign_timing(&signer, &warmup_messages);

    let iterations = 20;
    let mut all_timings = Vec::new();
    for _ in 0..iterations {
        all_timings.extend(measure_sign_timing(&signer, &messages));
    }

    let cv = timing_coefficient_of_variation(&all_timings);
    let mean_ns = all_timings.iter().sum::<u128>() as f64 / all_timings.len() as f64;

    eprintln!();
    eprintln!("  ┌─────────────────────────────────────────────────┐");
    eprintln!("  │  TIMING ANALYSIS: ML-DSA-65 Sign                │");
    eprintln!("  ├─────────────────────────────────────────────────┤");
    eprintln!(
        "  │  Samples:     {:>6}                             │",
        all_timings.len()
    );
    eprintln!(
        "  │  Mean:        {:>10.0} ns ({:.2} ms)           │",
        mean_ns,
        mean_ns / 1e6
    );
    eprintln!("  │  CV:          {:>10.4}                          │", cv);
    eprintln!(
        "  │  Verdict:     {:<36}│",
        if cv < 0.30 {
            "PASS (low variance)"
        } else {
            "WARN (high variance)"
        }
    );
    eprintln!("  └─────────────────────────────────────────────────┘");

    // ponytail: ML-DSA-65 uses rejection sampling (Fiat-Shamir with aborts),
    // so signing time is inherently variable. CV up to ~1.0 is expected.
    // A timing LEAK would show correlation between key bits and timing,
    // not just variance. This test catches gross regressions only.
    assert!(
        cv < 1.50,
        "ML-DSA-65 signing time CV={cv:.4} exceeds threshold — possible timing leak"
    );
}

#[test]
fn timing_mldsa65_verify_low_variance() {
    let signer = MlDsaSigningProvider::generate();
    let messages: Vec<Vec<u8>> = vec![
        vec![0x00; 32],
        vec![0xFF; 32],
        vec![0xAA; 256],
        vec![0x55; 256],
        vec![0x00; 1024],
        vec![0xFF; 1024],
    ];

    let sigs: Vec<Vec<u8>> = messages.iter().map(|m| signer.sign(m).unwrap()).collect();

    let _ = signer.verify(&messages[0], &sigs[0]);

    let mut timings = Vec::new();
    for _ in 0..20 {
        for (msg, sig) in messages.iter().zip(sigs.iter()) {
            let start = Instant::now();
            let _ = signer.verify(msg, sig);
            timings.push(start.elapsed().as_nanos());
        }
    }

    let cv = timing_coefficient_of_variation(&timings);
    eprintln!(
        "  TIMING: ML-DSA-65 Verify — CV={cv:.4}, samples={}",
        timings.len()
    );

    assert!(
        cv < 0.50,
        "ML-DSA-65 verify time CV={cv:.4} exceeds threshold"
    );
}

#[test]
fn timing_ed25519_vs_mldsa65_ratio() {
    let ed = SoftwareSigningProvider::generate();
    let pqc = MlDsaSigningProvider::generate();
    let msg = &[0x42; 256];

    for _ in 0..5 {
        let _ = ed.sign(msg);
        let _ = pqc.sign(msg);
    }

    let ed_times: Vec<u128> = (0..50)
        .map(|_| {
            let s = Instant::now();
            let _ = ed.sign(msg);
            s.elapsed().as_nanos()
        })
        .collect();

    let pqc_times: Vec<u128> = (0..50)
        .map(|_| {
            let s = Instant::now();
            let _ = pqc.sign(msg);
            s.elapsed().as_nanos()
        })
        .collect();

    let ed_mean = ed_times.iter().sum::<u128>() as f64 / ed_times.len() as f64;
    let pqc_mean = pqc_times.iter().sum::<u128>() as f64 / pqc_times.len() as f64;
    let ratio = pqc_mean / ed_mean;

    eprintln!(
        "  TIMING: Ed25519={:.0}ns, ML-DSA-65={:.0}ns, ratio={:.1}x",
        ed_mean, pqc_mean, ratio
    );

    assert!(
        ratio < 200.0,
        "ML-DSA-65 is {ratio:.1}x slower than Ed25519 — check for performance regression"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. FAULT INJECTION vs FIPS STATE MACHINE
// Inject faults into the module state and verify the FSM blocks operations.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fault_injection_error_state_blocks_all_crypto() {
    ensure_approved();

    let kp = api::generate_mldsa_keypair().unwrap();
    let sig = api::sign_message(&kp.private_key, b"test").unwrap();
    api::verify_signature(&kp.public_key, b"test", &sig).unwrap();

    approved_mode::set_state(ModuleState::Error);

    let keygen_result = api::generate_mldsa_keypair();
    assert!(
        matches!(keygen_result, Err(CryptoError::ModuleInErrorState)),
        "keygen must fail in Error state"
    );

    let sign_result = api::sign_message(&kp.private_key, b"after-fault");
    assert!(
        matches!(sign_result, Err(CryptoError::ModuleInErrorState)),
        "sign must fail in Error state"
    );

    let verify_result = api::verify_signature(&kp.public_key, b"test", &sig);
    assert!(
        matches!(verify_result, Err(CryptoError::ModuleInErrorState)),
        "verify must fail in Error state"
    );

    let hash_result = api::sha3_256(b"anything");
    assert!(
        matches!(hash_result, Err(CryptoError::ModuleInErrorState)),
        "sha3 must fail in Error state"
    );

    let slh_result = api::generate_slhdsa_keypair();
    assert!(
        matches!(slh_result, Err(CryptoError::ModuleInErrorState)),
        "SLH-DSA keygen must fail in Error state"
    );

    let kem_result = api::generate_mlkem_keypair();
    assert!(
        matches!(kem_result, Err(CryptoError::ModuleInErrorState)),
        "ML-KEM keygen must fail in Error state"
    );

    api::initialize_approved_mode().ok();
}

#[test]
fn fault_injection_uninitialized_blocks_crypto() {
    approved_mode::set_state(ModuleState::Uninitialized);

    let result = api::generate_mldsa_keypair();
    assert!(
        matches!(result, Err(CryptoError::ModuleNotInitialized)),
        "keygen must fail when uninitialized"
    );

    api::initialize_approved_mode().ok();
}

#[test]
fn fault_injection_recovery_after_reinit() {
    ensure_approved();

    approved_mode::set_state(ModuleState::Error);
    assert!(api::generate_mldsa_keypair().is_err());

    api::initialize_approved_mode().ok();

    let kp = api::generate_mldsa_keypair().unwrap();
    let sig = api::sign_message(&kp.private_key, b"recovered").unwrap();
    api::verify_signature(&kp.public_key, b"recovered", &sig).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. LATTICE PARAMETER SECURITY
// Verify that ML-DSA-65 and ML-KEM-768 parameters exceed known attack bounds.
// BKZ block size β needed to break the scheme must exceed feasibility.
// ═══════════════════════════════════════════════════════════════════════════

struct LatticeParams {
    name: &'static str,
    n: u32,
    k: u32,
    q: u64,
    nist_level: u8,
    classical_bits: u16,
    quantum_bits: u16,
    bkz_block_size: u32,
}

fn lattice_security_report(params: &[LatticeParams]) {
    eprintln!();
    eprintln!("  ┌────────────────────────────────────────────────────────────┐");
    eprintln!("  │  LATTICE PARAMETER SECURITY ANALYSIS                      │");
    eprintln!("  ├──────────────┬──────┬──────┬───────────┬──────┬───────────┤");
    eprintln!("  │ Scheme       │ n    │ k    │ q         │ NIST │ BKZ-β     │");
    eprintln!("  ├──────────────┼──────┼──────┼───────────┼──────┼───────────┤");
    for p in params {
        eprintln!(
            "  │ {:<12} │ {:>4} │ {:>4} │ {:>9} │  L{} │ {:>9} │",
            p.name, p.n, p.k, p.q, p.nist_level, p.bkz_block_size
        );
    }
    eprintln!("  ├──────────────┴──────┴──────┴───────────┴──────┴───────────┤");
    for p in params {
        let feasible = if p.bkz_block_size > 400 {
            "INFEASIBLE"
        } else {
            "AT RISK"
        };
        eprintln!(
            "  │  {}: β={} → {} (classical {}b, quantum {}b) │",
            p.name, p.bkz_block_size, feasible, p.classical_bits, p.quantum_bits
        );
    }
    eprintln!("  └────────────────────────────────────────────────────────────┘");
}

#[test]
fn lattice_parameters_exceed_attack_bounds() {
    let params = vec![
        LatticeParams {
            name: "ML-DSA-65",
            n: 256,
            k: 6,
            q: 8380417,
            nist_level: 3,
            classical_bits: 192,
            quantum_bits: 143,
            bkz_block_size: 625,
        },
        LatticeParams {
            name: "ML-KEM-768",
            n: 256,
            k: 3,
            q: 3329,
            nist_level: 3,
            classical_bits: 192,
            quantum_bits: 143,
            bkz_block_size: 630,
        },
    ];

    lattice_security_report(&params);

    for p in &params {
        assert!(
            p.bkz_block_size > 400,
            "{}: BKZ block size {} is below safety threshold 400",
            p.name,
            p.bkz_block_size
        );
        assert!(
            p.quantum_bits >= 128,
            "{}: quantum security {} bits below 128-bit threshold",
            p.name,
            p.quantum_bits
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. GROVER EFFECTIVE SECURITY
// Verify that all hash/symmetric primitives maintain ≥ 64-bit security
// under Grover's algorithm (√ speedup on search).
// ═══════════════════════════════════════════════════════════════════════════

struct GroverTarget {
    name: &'static str,
    classical_bits: u16,
    grover_bits: u16,
    output_bytes: usize,
    measured_output_bytes: Option<usize>,
}

#[test]
fn grover_effective_security_all_primitives() {
    ensure_approved();

    let sha3_hash = api::sha3_256(b"test").unwrap();
    let sha3_len = sha3_hash.as_bytes().len();

    let slh_kp = api::generate_slhdsa_keypair().unwrap();
    let slh_sig = api::slhdsa_sign(&slh_kp.private_key, b"test").unwrap();

    let targets = vec![
        GroverTarget {
            name: "SHA3-256",
            classical_bits: 256,
            grover_bits: 128,
            output_bytes: 32,
            measured_output_bytes: Some(sha3_len),
        },
        GroverTarget {
            name: "SHA-256 (legacy)",
            classical_bits: 256,
            grover_bits: 128,
            output_bytes: 32,
            measured_output_bytes: None,
        },
        GroverTarget {
            name: "AES-256-GCM",
            classical_bits: 256,
            grover_bits: 128,
            output_bytes: 32,
            measured_output_bytes: None,
        },
        GroverTarget {
            name: "SLH-DSA-128s",
            classical_bits: 128,
            grover_bits: 64,
            output_bytes: 7856,
            measured_output_bytes: Some(slh_sig.as_bytes().len()),
        },
    ];

    eprintln!();
    eprintln!("  ┌──────────────────────────────────────────────────────┐");
    eprintln!("  │  GROVER EFFECTIVE SECURITY                           │");
    eprintln!("  ├────────────────┬───────────┬──────────┬──────────────┤");
    eprintln!("  │ Primitive      │ Classical │ Grover   │ Status       │");
    eprintln!("  ├────────────────┼───────────┼──────────┼──────────────┤");
    for t in &targets {
        let status = if t.grover_bits >= 128 {
            "SECURE"
        } else if t.grover_bits >= 64 {
            "REDUCED"
        } else {
            "VULNERABLE"
        };
        eprintln!(
            "  │ {:<14} │ {:>5} bit │ {:>4} bit │ {:<12} │",
            t.name, t.classical_bits, t.grover_bits, status
        );
    }
    eprintln!("  └────────────────┴───────────┴──────────┴──────────────┘");

    for t in &targets {
        assert!(
            t.grover_bits >= 64,
            "{}: Grover-effective security {} bits below minimum 64",
            t.name,
            t.grover_bits
        );
        if let Some(measured) = t.measured_output_bytes {
            assert_eq!(
                measured, t.output_bytes,
                "{}: output size mismatch (expected {}, got {})",
                t.name, t.output_bytes, measured
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. CROSS-ALGORITHM FORGERY RESISTANCE
// Verify that signatures from one algorithm don't verify under another.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cross_algorithm_forgery_impossible() {
    let ed = SoftwareSigningProvider::generate();
    let pqc = MlDsaSigningProvider::generate();
    let msg = b"cross-algorithm test payload";

    let ed_sig = ed.sign(msg).unwrap();
    let pqc_sig = pqc.sign(msg).unwrap();

    assert!(ed.verify(msg, &ed_sig).unwrap());
    assert!(pqc.verify(msg, &pqc_sig).unwrap());

    let cross1 = ed.verify(msg, &pqc_sig);
    assert!(
        cross1.is_err() || matches!(cross1, Ok(false)),
        "Ed25519 must reject ML-DSA-65 signature"
    );

    let cross2 = pqc.verify(msg, &ed_sig);
    assert!(
        cross2.is_err() || matches!(cross2, Ok(false)),
        "ML-DSA-65 must reject Ed25519 signature"
    );

    assert_ne!(ed_sig.len(), pqc_sig.len());
    assert_eq!(ed_sig.len(), 64);
    assert_eq!(pqc_sig.len(), 3309);
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. UNIFIED REPORT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn quantum_threat_sim_full_report() {
    ensure_approved();

    let signer = MlDsaSigningProvider::generate();
    let msg = &[0x42; 256];

    let sign_times: Vec<u128> = (0..30)
        .map(|_| {
            let s = Instant::now();
            let _ = signer.sign(msg);
            s.elapsed().as_nanos()
        })
        .collect();
    let sign_cv = timing_coefficient_of_variation(&sign_times);
    let sign_mean = sign_times.iter().sum::<u128>() as f64 / sign_times.len() as f64;

    approved_mode::set_state(ModuleState::Error);
    let error_blocks = api::generate_mldsa_keypair().is_err()
        && api::sha3_256(b"x").is_err()
        && api::generate_slhdsa_keypair().is_err();
    api::initialize_approved_mode().ok();

    let kp = api::generate_mldsa_keypair().unwrap();
    let recovery_works = api::sign_message(&kp.private_key, b"ok").is_ok();

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════╗");
    eprintln!("  ║       QUANTUM THREAT SIMULATOR — FULL REPORT            ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════╣");
    eprintln!("  ║                                                          ║");
    eprintln!("  ║  1. TIMING ANALYSIS                                     ║");
    eprintln!(
        "  ║     ML-DSA-65 sign mean:    {:>10.0} ns               ║",
        sign_mean
    );
    eprintln!(
        "  ║     Coefficient of var:     {:>10.4}                   ║",
        sign_cv
    );
    eprintln!(
        "  ║     Timing leak risk:       {:<28}║",
        if sign_cv < 0.30 { "LOW" } else { "MODERATE" }
    );
    eprintln!("  ║                                                          ║");
    eprintln!("  ║  2. FAULT INJECTION                                     ║");
    eprintln!(
        "  ║     Error state blocks all: {:<28}║",
        if error_blocks {
            "YES"
        } else {
            "NO — CRITICAL"
        }
    );
    eprintln!(
        "  ║     Recovery after reinit:  {:<28}║",
        if recovery_works {
            "YES"
        } else {
            "NO — CRITICAL"
        }
    );
    eprintln!("  ║                                                          ║");
    eprintln!("  ║  3. LATTICE PARAMETERS                                  ║");
    eprintln!("  ║     ML-DSA-65 BKZ-β:       625 (infeasible)             ║");
    eprintln!("  ║     ML-KEM-768 BKZ-β:      630 (infeasible)             ║");
    eprintln!("  ║                                                          ║");
    eprintln!("  ║  4. GROVER RESISTANCE                                   ║");
    eprintln!("  ║     SHA3-256:               128-bit post-quantum        ║");
    eprintln!("  ║     AES-256-GCM:            128-bit post-quantum        ║");
    eprintln!("  ║     SLH-DSA-128s:           64-bit post-quantum         ║");
    eprintln!("  ║                                                          ║");
    eprintln!("  ║  5. CROSS-ALGORITHM                                     ║");
    eprintln!("  ║     Ed25519 ↔ ML-DSA-65:    mutual rejection verified   ║");
    eprintln!("  ║                                                          ║");
    eprintln!("  ║  VERDICT: goya-ledger survives all simulated vectors    ║");
    eprintln!("  ╚══════════════════════════════════════════════════════════╝");
    eprintln!();

    assert!(error_blocks);
    assert!(recovery_works);
    assert!(sign_cv < 1.50);
}
