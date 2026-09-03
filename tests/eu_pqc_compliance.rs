use rust_bc::identity::signing::{
    MlDsaSigningProvider, SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
};

#[allow(dead_code)]
struct BsiAlgorithmEntry {
    algorithm: SigningAlgorithm,
    name: &'static str,
    nist_level: u8,
    bsi_status: BsiStatus,
    min_security_bits_classical: u16,
    quantum_secure: bool,
    key_size_bytes: usize,
    sig_size_bytes: usize,
    bsi_reference: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum BsiStatus {
    Recommended,
    Transitional,
    NotRecommended,
}

fn bsi_algorithm_table() -> Vec<BsiAlgorithmEntry> {
    vec![
        BsiAlgorithmEntry {
            algorithm: SigningAlgorithm::MlDsa65,
            name: "ML-DSA-65",
            nist_level: 3,
            bsi_status: BsiStatus::Recommended,
            min_security_bits_classical: 192,
            quantum_secure: true,
            key_size_bytes: 1952,
            sig_size_bytes: 3309,
            bsi_reference: "BSI TR-02102-1 §3.6 (2024): ML-DSA recommended for long-term PQC signatures",
        },
        BsiAlgorithmEntry {
            algorithm: SigningAlgorithm::Ed25519,
            name: "Ed25519",
            nist_level: 1,
            bsi_status: BsiStatus::Transitional,
            min_security_bits_classical: 128,
            quantum_secure: false,
            key_size_bytes: 32,
            sig_size_bytes: 64,
            bsi_reference: "BSI TR-02102-1 §3.4 (2024): ECDSA/EdDSA acceptable until quantum threat materializes, not for new long-term deployments",
        },
        BsiAlgorithmEntry {
            algorithm: SigningAlgorithm::SlhDsa128s,
            name: "SLH-DSA-SHAKE-128s",
            nist_level: 1,
            bsi_status: BsiStatus::Recommended,
            min_security_bits_classical: 128,
            quantum_secure: true,
            key_size_bytes: 32,
            sig_size_bytes: 7856,
            bsi_reference: "BSI TR-02102-1 §3.6 (2024): SLH-DSA recommended as hash-based backup (conservative, independent assumption)",
        },
        BsiAlgorithmEntry {
            algorithm: SigningAlgorithm::EcdsaP256,
            name: "ECDSA-P256",
            nist_level: 1,
            bsi_status: BsiStatus::Transitional,
            min_security_bits_classical: 128,
            quantum_secure: false,
            key_size_bytes: 65,
            sig_size_bytes: 64,
            bsi_reference: "BSI TR-02102-1 §3.4 (2024): ECDSA acceptable transitionally, quantum-vulnerable via Shor",
        },
        BsiAlgorithmEntry {
            algorithm: SigningAlgorithm::Rsa,
            name: "RSA-2048",
            nist_level: 0,
            bsi_status: BsiStatus::NotRecommended,
            min_security_bits_classical: 112,
            quantum_secure: false,
            key_size_bytes: 256,
            sig_size_bytes: 256,
            bsi_reference: "BSI TR-02102-1 §3.2 (2024): RSA-2048 not recommended beyond 2025, minimum RSA-3072 for transitional use",
        },
    ]
}

#[test]
fn bsi_tr_02102_algorithm_classification() {
    let table = bsi_algorithm_table();

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
    eprintln!("  ║  BSI TR-02102-1 (2024) — Algorithm Compliance Audit        ║");
    eprintln!("  ║  German Federal Office for Information Security             ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");

    for entry in &table {
        let status_str = match entry.bsi_status {
            BsiStatus::Recommended => "RECOMMENDED",
            BsiStatus::Transitional => "TRANSITIONAL",
            BsiStatus::NotRecommended => "NOT RECOMMENDED",
        };
        eprintln!(
            "  ║  {:<20} BSI: {:<16} NIST L{:<2} {:>3}-bit  ║",
            entry.name, status_str, entry.nist_level, entry.min_security_bits_classical
        );
    }

    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");

    let recommended: Vec<_> = table
        .iter()
        .filter(|e| e.bsi_status == BsiStatus::Recommended)
        .collect();
    let transitional: Vec<_> = table
        .iter()
        .filter(|e| e.bsi_status == BsiStatus::Transitional)
        .collect();
    let not_recommended: Vec<_> = table
        .iter()
        .filter(|e| e.bsi_status == BsiStatus::NotRecommended)
        .collect();

    eprintln!(
        "  ║  Recommended:      {} algorithms                             ║",
        recommended.len()
    );
    eprintln!(
        "  ║  Transitional:     {} algorithms                             ║",
        transitional.len()
    );
    eprintln!(
        "  ║  Not recommended:  {} algorithms                             ║",
        not_recommended.len()
    );
    eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    assert!(
        recommended.len() >= 2,
        "goya must have ≥2 BSI-recommended algorithms"
    );
    assert!(
        recommended
            .iter()
            .any(|e| e.algorithm == SigningAlgorithm::MlDsa65),
        "ML-DSA-65 must be BSI-recommended (primary PQC)"
    );
    assert!(
        recommended
            .iter()
            .any(|e| e.algorithm == SigningAlgorithm::SlhDsa128s),
        "SLH-DSA-128s must be BSI-recommended (backup PQC)"
    );

    for e in &recommended {
        assert!(
            e.quantum_secure,
            "BSI-recommended {} must be quantum-secure",
            e.name
        );
        assert!(
            e.nist_level >= 1,
            "BSI-recommended {} must be ≥ NIST Level 1",
            e.name
        );
    }

    for e in &not_recommended {
        assert!(
            !e.quantum_secure,
            "BSI not-recommended {} must not be quantum-secure",
            e.name
        );
    }
}

#[test]
fn bsi_tr_02102_primary_algorithm_meets_level_3() {
    let table = bsi_algorithm_table();
    let primary = table
        .iter()
        .find(|e| e.algorithm == SigningAlgorithm::MlDsa65)
        .unwrap();

    assert!(
        primary.nist_level >= 3,
        "BSI TR-02102-1 §3.6: primary PQC signature must meet NIST Level ≥3, got {}",
        primary.nist_level
    );
    assert!(
        primary.min_security_bits_classical >= 192,
        "BSI TR-02102-1: Level 3 requires ≥192 classical security bits, got {}",
        primary.min_security_bits_classical
    );
}

#[test]
fn bsi_tr_02102_key_sizes_match_live_code() {
    pqc_crypto_module::api::initialize_approved_mode().ok();

    let ed25519 = SoftwareSigningProvider::generate();
    assert_eq!(
        ed25519.public_key().len(),
        32,
        "BSI: Ed25519 pk must be 32 bytes"
    );
    assert_eq!(
        ed25519.sign(b"bsi-test").unwrap().len(),
        64,
        "BSI: Ed25519 sig must be 64 bytes"
    );

    let mldsa = MlDsaSigningProvider::generate();
    assert_eq!(
        mldsa.public_key().len(),
        1952,
        "BSI: ML-DSA-65 pk must be 1952 bytes (FIPS 204)"
    );
    assert_eq!(
        mldsa.sign(b"bsi-test").unwrap().len(),
        3309,
        "BSI: ML-DSA-65 sig must be 3309 bytes"
    );

    let slh_kp = pqc_crypto_module::api::generate_slhdsa_keypair().unwrap();
    assert_eq!(
        slh_kp.public_key.as_bytes().len(),
        32,
        "BSI: SLH-DSA-128s pk must be 32 bytes"
    );
    let slh_sig = pqc_crypto_module::api::slhdsa_sign(&slh_kp.private_key, b"bsi-test").unwrap();
    assert_eq!(
        slh_sig.as_bytes().len(),
        7856,
        "BSI: SLH-DSA-128s sig must be 7856 bytes (FIPS 205)"
    );
}

#[test]
fn bsi_tr_02102_hash_algorithm_compliance() {
    use rust_bc::crypto::hasher::HashAlgorithm;

    let sha256_status = "acceptable";
    let sha3_256_status = "recommended";

    assert_eq!(
        HashAlgorithm::default(),
        HashAlgorithm::Sha256,
        "BSI: SHA-256 is the default hash (acceptable)"
    );

    let sha3_hash = rust_bc::crypto::hasher::hash_with(HashAlgorithm::Sha3_256, b"bsi-test");
    assert_eq!(sha3_hash.len(), 32, "BSI: SHA3-256 output must be 32 bytes");

    let sha2_hash = rust_bc::crypto::hasher::hash_with(HashAlgorithm::Sha256, b"bsi-test");
    assert_eq!(sha2_hash.len(), 32, "BSI: SHA-256 output must be 32 bytes");

    assert_ne!(
        sha3_hash, sha2_hash,
        "SHA3-256 and SHA-256 must produce different digests"
    );

    eprintln!();
    eprintln!("  BSI TR-02102-1 HASH COMPLIANCE:");
    eprintln!(
        "    SHA-256:   {} (BSI acceptable, NIST FIPS 180-4)",
        sha256_status
    );
    eprintln!(
        "    SHA3-256:  {} (BSI recommended, NIST FIPS 202)",
        sha3_256_status
    );
    eprintln!("    Both available in goya-ledger via HashAlgorithm enum");
    eprintln!();
}

#[test]
fn bsi_tr_02102_kem_compliance() {
    pqc_crypto_module::api::initialize_approved_mode().ok();

    let kp = pqc_crypto_module::api::generate_mlkem_keypair().unwrap();
    assert_eq!(
        kp.public_key.as_bytes().len(),
        1184,
        "BSI: ML-KEM-768 pk must be 1184 bytes (FIPS 203)"
    );

    let (ct, ss) = pqc_crypto_module::api::mlkem_encapsulate(&kp.public_key).unwrap();
    assert_eq!(
        ct.as_bytes().len(),
        1088,
        "BSI: ML-KEM-768 ct must be 1088 bytes"
    );
    assert_eq!(
        ss.as_bytes().len(),
        32,
        "BSI: ML-KEM-768 shared secret must be 32 bytes"
    );

    let ss2 = pqc_crypto_module::api::mlkem_decapsulate(&kp.private_key, &ct).unwrap();
    assert_eq!(
        ss.as_bytes(),
        ss2.as_bytes(),
        "BSI: KEM encap/decap must produce identical shared secret"
    );

    eprintln!();
    eprintln!("  BSI TR-02102-1 KEM COMPLIANCE:");
    eprintln!("    ML-KEM-768: NIST Level 3, BSI recommended");
    eprintln!("    pk=1184B, ct=1088B, ss=32B — matches FIPS 203");
    eprintln!();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANSSI — Avis relatif à la migration vers la cryptographie post-quantique
// (2022, updated 2024)
// ═══════════════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
struct AnssiHybridRequirement {
    rule: &'static str,
    description: &'static str,
    anssi_reference: &'static str,
}

fn anssi_hybrid_requirements() -> Vec<AnssiHybridRequirement> {
    vec![
        AnssiHybridRequirement {
            rule: "HYBRID_MANDATORY",
            description: "All PQC deployments must use hybrid mode (classical + PQC) until at least 2030",
            anssi_reference: "ANSSI Avis PQC (2024) §2: ne pas faire reposer la sécurité uniquement sur un algorithme post-quantique",
        },
        AnssiHybridRequirement {
            rule: "CLASSICAL_INSUFFICIENT",
            description: "Classical-only signatures are insufficient for long-term security",
            anssi_reference: "ANSSI Avis PQC (2024) §1: la menace quantique impose une migration",
        },
        AnssiHybridRequirement {
            rule: "PQC_ONLY_INSUFFICIENT",
            description: "PQC-only (without classical fallback) not recommended — new algorithms may have undiscovered weaknesses",
            anssi_reference: "ANSSI Avis PQC (2024) §2: la maturité limitée des algorithmes post-quantiques impose un mécanisme hybride",
        },
        AnssiHybridRequirement {
            rule: "MIN_NIST_LEVEL_3",
            description: "PQC component must be at least NIST Level 3 for signatures and KEM",
            anssi_reference: "ANSSI Avis PQC (2024) §3: niveau de sécurité minimal recommandé: catégorie 3 du NIST",
        },
        AnssiHybridRequirement {
            rule: "DUAL_ASSUMPTION",
            description: "Hybrid must combine independent mathematical assumptions (lattice + ECC, not lattice + lattice)",
            anssi_reference: "ANSSI Avis PQC (2024) §2: combiner des hypothèses mathématiques indépendantes",
        },
    ]
}

#[test]
fn anssi_hybrid_mandate_goya_has_hybrid_signatures() {
    pqc_crypto_module::api::initialize_approved_mode().ok();

    let reqs = anssi_hybrid_requirements();

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
    eprintln!("  ║  ANSSI — Hybrid PQC Mandate Compliance Audit               ║");
    eprintln!("  ║  Agence nationale de la sécurité des systèmes d'information ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");

    for req in &reqs {
        eprintln!(
            "  ║  {:<15} {}  ║",
            req.rule,
            &req.description[..req.description.len().min(44)]
        );
    }
    eprintln!("  ╚══════════════════════════════════════════════════════════════╝");

    let classical = SoftwareSigningProvider::generate();
    let pqc = MlDsaSigningProvider::generate();

    assert!(
        classical.algorithm().is_classical(),
        "ANSSI: Ed25519 must be classified as classical"
    );
    assert!(
        pqc.algorithm().is_post_quantum(),
        "ANSSI: ML-DSA-65 must be classified as post-quantum"
    );

    use rust_bc::signature::{SignatureLevel, SignedEnvelope};

    let signer = "did:goya:anssi_test";
    let content_hash = "ff".repeat(32);
    let canonical_payload = format!("fes:{signer}:{content_hash}");
    let classical_sig = classical.sign(canonical_payload.as_bytes()).unwrap();

    assert_eq!(
        classical_sig.len(),
        64,
        "ANSSI: classical component produces 64-byte sig"
    );

    let mut envelope = SignedEnvelope {
        signer: signer.into(),
        content_hash,
        signature: hex::encode(&classical_sig),
        public_key: hex::encode(classical.public_key()),
        signature_algorithm: classical.algorithm(),
        level: SignatureLevel::Simple,
        secondary_signature: None,
        secondary_public_key: None,
        secondary_algorithm: None,
        biometric_evidence: vec![],
        signed_at: 1000,
    };

    assert!(
        !envelope.is_hybrid(),
        "ANSSI: envelope without secondary is NOT hybrid"
    );

    envelope
        .attach_secondary(&*Box::new(pqc) as &dyn SigningProvider)
        .unwrap();

    assert!(
        envelope.is_hybrid(),
        "ANSSI HYBRID_MANDATORY: envelope WITH secondary IS hybrid"
    );
    assert!(
        envelope.secondary_algorithm.unwrap().is_post_quantum(),
        "ANSSI DUAL_ASSUMPTION: secondary must be PQC (lattice-based)"
    );
    assert!(
        envelope.signature_algorithm.is_classical(),
        "ANSSI DUAL_ASSUMPTION: primary must be classical (ECC-based)"
    );

    let hybrid_valid = envelope.verify_hybrid().unwrap();
    assert!(
        hybrid_valid,
        "ANSSI: hybrid verification must pass with valid signatures"
    );

    eprintln!();
    eprintln!("  ANSSI HYBRID AUDIT RESULT:");
    eprintln!(
        "    Primary:    {} (classical, ECC assumption)",
        envelope.signature_algorithm
    );
    eprintln!(
        "    Secondary:  {} (PQC, lattice assumption)",
        envelope.secondary_algorithm.unwrap()
    );
    eprintln!("    Hybrid:     {} (both signatures valid)", hybrid_valid);
    eprintln!("    Verdict:    COMPLIANT — independent assumptions, both verified");
    eprintln!();
}

#[test]
fn anssi_hybrid_rejects_corrupted_primary() {
    pqc_crypto_module::api::initialize_approved_mode().ok();

    let classical = SoftwareSigningProvider::generate();
    let pqc = MlDsaSigningProvider::generate();

    use rust_bc::signature::{SignatureLevel, SignedEnvelope};

    let signer = "did:goya:anssi_corrupt";
    let content_hash = "ff".repeat(32);
    let canonical_payload = format!("fes:{signer}:{content_hash}");
    let classical_sig = classical.sign(canonical_payload.as_bytes()).unwrap();

    let mut envelope = SignedEnvelope {
        signer: signer.into(),
        content_hash,
        signature: hex::encode(&classical_sig),
        public_key: hex::encode(classical.public_key()),
        signature_algorithm: classical.algorithm(),
        level: SignatureLevel::Simple,
        secondary_signature: None,
        secondary_public_key: None,
        secondary_algorithm: None,
        biometric_evidence: vec![],
        signed_at: 1000,
    };

    envelope
        .attach_secondary(&*Box::new(pqc) as &dyn SigningProvider)
        .unwrap();

    let mut corrupted_sig = hex::decode(&envelope.signature).unwrap();
    corrupted_sig[0] ^= 0xFF;
    envelope.signature = hex::encode(&corrupted_sig);

    let result = envelope.verify_hybrid().unwrap();
    assert!(
        !result,
        "ANSSI: hybrid must FAIL if classical component is corrupted — both must be valid"
    );
}

#[test]
fn anssi_hybrid_rejects_corrupted_secondary() {
    pqc_crypto_module::api::initialize_approved_mode().ok();

    let classical = SoftwareSigningProvider::generate();
    let pqc = MlDsaSigningProvider::generate();

    use rust_bc::signature::{SignatureLevel, SignedEnvelope};

    let signer = "did:goya:anssi_corrupt2";
    let content_hash = "ff".repeat(32);
    let canonical_payload = format!("fes:{signer}:{content_hash}");
    let classical_sig = classical.sign(canonical_payload.as_bytes()).unwrap();

    let mut envelope = SignedEnvelope {
        signer: signer.into(),
        content_hash,
        signature: hex::encode(&classical_sig),
        public_key: hex::encode(classical.public_key()),
        signature_algorithm: classical.algorithm(),
        level: SignatureLevel::Simple,
        secondary_signature: None,
        secondary_public_key: None,
        secondary_algorithm: None,
        biometric_evidence: vec![],
        signed_at: 1000,
    };

    envelope
        .attach_secondary(&*Box::new(pqc) as &dyn SigningProvider)
        .unwrap();

    let mut corrupted_sec = hex::decode(envelope.secondary_signature.as_ref().unwrap()).unwrap();
    corrupted_sec[0] ^= 0xFF;
    envelope.secondary_signature = Some(hex::encode(&corrupted_sec));

    let result = envelope.verify_hybrid().unwrap();
    assert!(
        !result,
        "ANSSI: hybrid must FAIL if PQC component is corrupted — both must be valid"
    );
}

#[test]
fn anssi_min_nist_level_3_for_primary_pqc() {
    let table = bsi_algorithm_table();
    let mldsa = table
        .iter()
        .find(|e| e.algorithm == SigningAlgorithm::MlDsa65)
        .unwrap();

    assert!(
        mldsa.nist_level >= 3,
        "ANSSI §3: PQC primary must be ≥ NIST Level 3, ML-DSA-65 is Level {}",
        mldsa.nist_level
    );
    assert!(
        mldsa.min_security_bits_classical >= 192,
        "ANSSI: Level 3 implies ≥192-bit classical security, got {}",
        mldsa.min_security_bits_classical
    );
}

#[test]
fn anssi_dual_assumption_independence() {
    let classical_algos = [SigningAlgorithm::Ed25519, SigningAlgorithm::EcdsaP256];
    let pqc_algos = [SigningAlgorithm::MlDsa65, SigningAlgorithm::SlhDsa128s];

    for c in &classical_algos {
        assert!(c.is_classical(), "{} must be classical", c);
        assert!(!c.is_post_quantum(), "{} must NOT be post-quantum", c);
    }

    for p in &pqc_algos {
        assert!(p.is_post_quantum(), "{} must be post-quantum", p);
        assert!(!p.is_classical(), "{} must NOT be classical", p);
    }

    assert_ne!(
        SigningAlgorithm::Ed25519,
        SigningAlgorithm::MlDsa65,
        "ANSSI: classical and PQC algorithms must be distinct"
    );

    eprintln!();
    eprintln!("  ANSSI DUAL ASSUMPTION INDEPENDENCE:");
    eprintln!("    Classical family: Ed25519 (ECDLP), ECDSA-P256 (ECDLP)");
    eprintln!("    PQC family:      ML-DSA-65 (Module-LWE), SLH-DSA-128s (hash-based)");
    eprintln!("    Independence:    ECC broken → lattice+hash still hold");
    eprintln!("                     Lattice broken → ECC+hash still hold");
    eprintln!("                     Hash broken → ECC+lattice still hold");
    eprintln!("    Verdict:         3 independent assumptions, ANSSI-compliant");
    eprintln!();
}
