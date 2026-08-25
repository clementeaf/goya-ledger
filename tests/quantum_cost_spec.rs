use rust_bc::identity::signing::SigningProvider;
use std::fmt;

struct QuantumCostEntry {
    primitive: &'static str,
    standard: &'static str,
    nist_level: u8,
    classical_security_bits: u16,
    usage_in_goya: &'static str,
    key_sizes: &'static str,
    best_quantum_attack: &'static str,
    logical_qubits: u64,
    gate_operations_log2: u16,
    physical_qubits_estimate: u64,
    wall_clock_years_at_1ghz: f64,
    usd_cost_estimate: &'static str,
    citation: &'static str,
    quantum_security_bits: u16,
}

impl fmt::Display for QuantumCostEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  ║  {:─<56}║", "")?;
        writeln!(f, "  ║  {:<56}║", self.primitive)?;
        writeln!(f, "  ║    Standard:             {:<30}║", self.standard)?;
        writeln!(f, "  ║    NIST Level:            {:<30}║", self.nist_level)?;
        writeln!(
            f,
            "  ║    Classical security:    {:<30}║",
            format!("{} bits", self.classical_security_bits)
        )?;
        writeln!(
            f,
            "  ║    Quantum security:      {:<30}║",
            format!("{} bits", self.quantum_security_bits)
        )?;
        writeln!(f, "  ║    Key sizes:             {:<30}║", self.key_sizes)?;
        writeln!(
            f,
            "  ║    Usage:                 {:<30}║",
            self.usage_in_goya
        )?;
        writeln!(
            f,
            "  ║    Best quantum attack:   {:<30}║",
            self.best_quantum_attack
        )?;
        writeln!(
            f,
            "  ║    Logical qubits:        {:<30}║",
            format!("{}", self.logical_qubits)
        )?;
        writeln!(
            f,
            "  ║    Gate operations:        {:<30}║",
            format!("2^{}", self.gate_operations_log2)
        )?;
        writeln!(
            f,
            "  ║    Physical qubits (est):  {:<30}║",
            format!("~{}", format_large(self.physical_qubits_estimate))
        )?;
        writeln!(
            f,
            "  ║    Wall-clock (1 GHz):     {:<30}║",
            format_years(self.wall_clock_years_at_1ghz)
        )?;
        writeln!(
            f,
            "  ║    USD cost (projected):   {:<30}║",
            self.usd_cost_estimate
        )?;
        writeln!(f, "  ║    Citation:               {:<30}║", self.citation)?;
        Ok(())
    }
}

fn format_large(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1e9)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1e3)
    } else {
        format!("{n}")
    }
}

fn format_years(y: f64) -> String {
    if y < 1.0 {
        format!("{:.1} days", y * 365.25)
    } else if y > 1e15 {
        format!("{:.1e} years", y)
    } else if y > 1e9 {
        format!("{:.1}B years", y / 1e9)
    } else if y > 1e6 {
        format!("{:.1}M years", y / 1e6)
    } else if y > 1e3 {
        format!("{:.1}K years", y / 1e3)
    } else {
        format!("{:.1} years", y)
    }
}

fn goya_primitives() -> Vec<QuantumCostEntry> {
    vec![
        QuantumCostEntry {
            primitive: "Ed25519 (COMPROMISED IN SCENARIO)",
            standard: "RFC 8032 / Curve25519",
            nist_level: 1,
            classical_security_bits: 128,
            usage_in_goya: "Legacy block sigs, DIDs",
            key_sizes: "pk=32B, sk=32B, sig=64B",
            best_quantum_attack: "Shor's (ECDLP)",
            logical_qubits: 2330,
            gate_operations_log2: 37,
            physical_qubits_estimate: 4_000_000,
            wall_clock_years_at_1ghz: 0.012,
            usd_cost_estimate: "$10M-$100M (2035 est.)",
            citation: "Roetteler et al. 2017, Häner et al. 2020",
            quantum_security_bits: 0,
        },
        QuantumCostEntry {
            primitive: "ML-DSA-65 (PRIMARY PQC SIGNATURE)",
            standard: "FIPS 204",
            nist_level: 3,
            classical_security_bits: 192,
            usage_in_goya: "Block sigs, BFT votes, LexChain",
            key_sizes: "pk=1952B, sk=4032B, sig=3309B",
            best_quantum_attack: "Quantum BKZ (Module-LWE)",
            logical_qubits: 16_000,
            gate_operations_log2: 143,
            physical_qubits_estimate: 30_000_000,
            wall_clock_years_at_1ghz: 3.5e25,
            usd_cost_estimate: "Infeasible (>age of universe)",
            citation: "NIST PQC Report 2024, Albrecht et al. 2023",
            quantum_security_bits: 143,
        },
        QuantumCostEntry {
            primitive: "SLH-DSA-SHAKE-128s (BACKUP SIGNATURE)",
            standard: "FIPS 205",
            nist_level: 1,
            classical_security_bits: 128,
            usage_in_goya: "Backup sig scheme (hash-based)",
            key_sizes: "pk=32B, sk=64B, sig=7856B",
            best_quantum_attack: "Grover (hash preimage)",
            logical_qubits: 6_400,
            gate_operations_log2: 64,
            physical_qubits_estimate: 12_000_000,
            wall_clock_years_at_1ghz: 584.9,
            usd_cost_estimate: ">$1T (2040 est.)",
            citation: "Bernstein 2009, NIST SP 800-208",
            quantum_security_bits: 64,
        },
        QuantumCostEntry {
            primitive: "ML-KEM-768 (TLS KEY EXCHANGE)",
            standard: "FIPS 203",
            nist_level: 3,
            classical_security_bits: 192,
            usage_in_goya: "X25519+ML-KEM-768 hybrid TLS",
            key_sizes: "pk=1184B, sk=2400B, ct=1088B, ss=32B",
            best_quantum_attack: "Quantum BKZ (Module-LWE)",
            logical_qubits: 15_000,
            gate_operations_log2: 143,
            physical_qubits_estimate: 28_000_000,
            wall_clock_years_at_1ghz: 3.5e25,
            usd_cost_estimate: "Infeasible (>age of universe)",
            citation: "NIST PQC Report 2024, Albrecht et al. 2023",
            quantum_security_bits: 143,
        },
        QuantumCostEntry {
            primitive: "SHA3-256 (APPROVED HASH)",
            standard: "FIPS 202",
            nist_level: 3,
            classical_security_bits: 256,
            usage_in_goya: "Block hashing, content hashing",
            key_sizes: "output=32B (256 bits)",
            best_quantum_attack: "Grover (preimage)",
            logical_qubits: 7_680,
            gate_operations_log2: 128,
            physical_qubits_estimate: 14_000_000,
            wall_clock_years_at_1ghz: 1.08e22,
            usd_cost_estimate: "Infeasible (>age of universe)",
            citation: "Amy et al. 2016, Grassl et al. 2016",
            quantum_security_bits: 128,
        },
        QuantumCostEntry {
            primitive: "SHA-256 (LEGACY HASH)",
            standard: "FIPS 180-4",
            nist_level: 1,
            classical_security_bits: 256,
            usage_in_goya: "Legacy block hash, DID, TLS pins",
            key_sizes: "output=32B (256 bits)",
            best_quantum_attack: "Grover (preimage)",
            logical_qubits: 2_048,
            gate_operations_log2: 128,
            physical_qubits_estimate: 4_000_000,
            wall_clock_years_at_1ghz: 1.08e22,
            usd_cost_estimate: "Infeasible (>age of universe)",
            citation: "Amy et al. 2016",
            quantum_security_bits: 128,
        },
        QuantumCostEntry {
            primitive: "AES-256-GCM (WALLET ENCRYPTION)",
            standard: "NIST SP 800-38D",
            nist_level: 5,
            classical_security_bits: 256,
            usage_in_goya: "Desktop wallet key encryption",
            key_sizes: "key=32B, nonce=12B, tag=16B",
            best_quantum_attack: "Grover (key search)",
            logical_qubits: 6_681,
            gate_operations_log2: 128,
            physical_qubits_estimate: 13_000_000,
            wall_clock_years_at_1ghz: 1.08e22,
            usd_cost_estimate: "Infeasible (>age of universe)",
            citation: "Grassl et al. 2016",
            quantum_security_bits: 128,
        },
    ]
}

#[test]
fn quantum_cost_specification() {
    let primitives = goya_primitives();

    let vulnerable: Vec<&QuantumCostEntry> = primitives
        .iter()
        .filter(|p| p.quantum_security_bits == 0)
        .collect();
    let resistant: Vec<&QuantumCostEntry> = primitives
        .iter()
        .filter(|p| p.quantum_security_bits > 0 && p.quantum_security_bits < 128)
        .collect();
    let secure: Vec<&QuantumCostEntry> = primitives
        .iter()
        .filter(|p| p.quantum_security_bits >= 128)
        .collect();

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════╗");
    eprintln!("  ║     QUANTUM COST SPECIFICATION — goya-ledger            ║");
    eprintln!("  ║     Cost to break each cryptographic primitive with      ║");
    eprintln!("  ║     the best known quantum algorithm.                    ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════╣");

    if !vulnerable.is_empty() {
        eprintln!("  ║                                                          ║");
        eprintln!("  ║  ████ VULNERABLE (broken by quantum computer) ████       ║");
        for p in &vulnerable {
            eprint!("{p}");
        }
    }

    if !resistant.is_empty() {
        eprintln!("  ║                                                          ║");
        eprintln!("  ║  ▓▓▓▓ REDUCED SECURITY (Grover halves key bits) ▓▓▓▓    ║");
        for p in &resistant {
            eprint!("{p}");
        }
    }

    if !secure.is_empty() {
        eprintln!("  ║                                                          ║");
        eprintln!("  ║  ░░░░ QUANTUM SECURE (≥128-bit quantum security) ░░░░   ║");
        for p in &secure {
            eprint!("{p}");
        }
    }

    eprintln!("  ║                                                          ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════╣");
    eprintln!("  ║  SUMMARY                                                ║");
    eprintln!(
        "  ║    Vulnerable primitives:     {:>3}                       ║",
        vulnerable.len()
    );
    eprintln!(
        "  ║    Reduced security:          {:>3}                       ║",
        resistant.len()
    );
    eprintln!(
        "  ║    Quantum secure:            {:>3}                       ║",
        secure.len()
    );

    let min_qubits_to_break: u64 = primitives
        .iter()
        .filter(|p| p.quantum_security_bits == 0)
        .map(|p| p.logical_qubits)
        .min()
        .unwrap_or(0);
    let min_qubits_pqc: u64 = primitives
        .iter()
        .filter(|p| p.quantum_security_bits >= 128)
        .map(|p| p.logical_qubits)
        .min()
        .unwrap_or(0);

    eprintln!("  ║                                                          ║");
    eprintln!(
        "  ║    Min qubits to break Ed25519:  {:>7} logical         ║",
        format_large(min_qubits_to_break)
    );
    eprintln!(
        "  ║    Min qubits to break PQC:      {:>7} logical         ║",
        format_large(min_qubits_pqc)
    );
    eprintln!(
        "  ║    Quantum hardness ratio:        {:>7.0}x                ║",
        min_qubits_pqc as f64 / min_qubits_to_break.max(1) as f64
    );
    eprintln!("  ║                                                          ║");
    eprintln!("  ║  HARDWARE PROJECTION (2035)                              ║");
    eprintln!("  ║    IBM Roadmap:           ~100K physical qubits          ║");
    eprintln!("  ║    Error correction:       ~1000 physical per logical    ║");
    eprintln!("  ║    Available logical:      ~100 logical qubits           ║");
    eprintln!("  ║    Ed25519 needs:          ~2330 logical qubits          ║");
    eprintln!("  ║    ML-DSA-65 needs:        ~16000 logical qubits         ║");
    eprintln!("  ║    VERDICT:  Ed25519 safe until ~2040, ML-DSA-65         ║");
    eprintln!("  ║              infeasible beyond foreseeable hardware       ║");
    eprintln!("  ╚══════════════════════════════════════════════════════════╝");
    eprintln!();

    assert_eq!(vulnerable.len(), 1, "only Ed25519 is quantum-vulnerable");
    assert_eq!(
        resistant.len(),
        1,
        "only SLH-DSA-128s has reduced quantum security"
    );
    assert!(
        secure.len() >= 4,
        "ML-DSA-65, ML-KEM-768, SHA3-256, SHA-256, AES-256 are quantum-secure"
    );
    let min_gates_ed25519: u16 = primitives
        .iter()
        .filter(|p| p.quantum_security_bits == 0)
        .map(|p| p.gate_operations_log2)
        .min()
        .unwrap_or(0);
    let min_gates_pqc: u16 = primitives
        .iter()
        .filter(|p| p.quantum_security_bits >= 128)
        .map(|p| p.gate_operations_log2)
        .min()
        .unwrap_or(0);
    assert!(
        min_gates_pqc > min_gates_ed25519 * 2,
        "PQC gate cost must vastly exceed classical attack cost"
    );
}

#[test]
fn verify_goya_parameter_sizes_match_nist() {
    pqc_crypto_module::api::initialize_approved_mode().ok();
    assert_eq!(
        rust_bc::identity::signing::SoftwareSigningProvider::generate()
            .public_key()
            .len(),
        32
    );
    assert_eq!(
        rust_bc::identity::signing::SoftwareSigningProvider::generate()
            .sign(b"test")
            .unwrap()
            .len(),
        64
    );

    assert_eq!(
        rust_bc::identity::signing::MlDsaSigningProvider::generate()
            .public_key()
            .len(),
        1952
    );
    assert_eq!(
        rust_bc::identity::signing::MlDsaSigningProvider::generate()
            .sign(b"test")
            .unwrap()
            .len(),
        3309
    );

    let slh_kp = pqc_crypto_module::api::generate_slhdsa_keypair().unwrap();
    assert_eq!(slh_kp.public_key.as_bytes().len(), 32);
    let slh_sig = pqc_crypto_module::api::slhdsa_sign(&slh_kp.private_key, b"test").unwrap();
    assert_eq!(slh_sig.as_bytes().len(), 7856);

    let kem_kp = pqc_crypto_module::api::generate_mlkem_keypair().unwrap();
    assert_eq!(kem_kp.public_key.as_bytes().len(), 1184);
    let (ct, ss) = pqc_crypto_module::api::mlkem_encapsulate(&kem_kp.public_key).unwrap();
    assert_eq!(ct.as_bytes().len(), 1088);
    assert_eq!(ss.as_bytes().len(), 32);
}

#[test]
fn quantum_cost_system_composition_analysis() {
    let primitives = goya_primitives();

    let weakest_quantum: &QuantumCostEntry = primitives
        .iter()
        .filter(|p| p.quantum_security_bits > 0)
        .min_by_key(|p| p.quantum_security_bits)
        .unwrap();

    assert_eq!(
        weakest_quantum.primitive,
        "SLH-DSA-SHAKE-128s (BACKUP SIGNATURE)"
    );
    assert_eq!(weakest_quantum.quantum_security_bits, 64);

    let primary_sigs: Vec<&QuantumCostEntry> = primitives
        .iter()
        .filter(|p| p.primitive.contains("ML-DSA") || p.primitive.contains("ML-KEM"))
        .collect();

    for p in &primary_sigs {
        assert!(
            p.quantum_security_bits >= 128,
            "{} has only {}-bit quantum security",
            p.primitive,
            p.quantum_security_bits
        );
    }

    let composition_security = primary_sigs
        .iter()
        .map(|p| p.quantum_security_bits)
        .min()
        .unwrap();
    assert_eq!(composition_security, 143);

    eprintln!();
    eprintln!("  COMPOSITION ANALYSIS:");
    eprintln!(
        "    Weakest PQC primitive:     {} ({}-bit quantum)",
        weakest_quantum.primitive, weakest_quantum.quantum_security_bits
    );
    eprintln!(
        "    Primary system security:   {composition_security}-bit quantum (ML-DSA-65 + ML-KEM-768)"
    );
    eprintln!("    SLH-DSA-128s backup:       64-bit quantum (hash-based, independent assumption)");
    eprintln!(
        "    To break goya-ledger:      attacker must break BOTH lattice AND hash assumptions"
    );
    eprintln!();
}
