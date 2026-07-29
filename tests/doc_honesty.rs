//! Tests that public-facing documentation does not overstate performance.
//!
//! The 18,700 TX/s number is a micro-benchmark of the Solo ordering service
//! in isolation (no network, no consensus, no persistence, no signatures).
//! The measured E2E throughput is ~42 TPS (rate-limited) or ~71 TPS single
//! connection. Commercial docs must not present micro-benchmark numbers as
//! system throughput without qualification.

use std::path::Path;

fn read_doc(relative: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(relative))
        .unwrap_or_else(|e| panic!("cannot read {relative}: {e}"))
}

/// Every mention of "18,700" or "18700" in active commercial docs must appear
/// on a line that also contains a qualifier word making clear it is a
/// component-level measurement, not end-to-end system throughput.
#[test]
fn commercial_docs_qualify_microbenchmark_throughput() {
    let qualifiers = [
        "motor",
        "ordering",
        "micro",
        "componente",
        "aislado",
        "solo",
        "internal",
        "interno",
    ];

    let commercial_docs = [
        "docs/commercial/ONE-PAGER-PRODUCTO.md",
        "docs/commercial/ONE-PAGER-SERVICIOS-API.md",
        "docs/commercial/FAQ-ENTERPRISE.md",
        "docs/commercial/HORIZONTAL-CAPABILITIES-REPORT.md",
        "docs/commercial/PLATFORM-ARCHITECTURE.md",
        "docs/commercial/SERVICE-CATALOG.md",
        "docs/commercial/VALUE_PROPOSITION_SALES_PITCH.md",
    ];

    let mut violations = Vec::new();

    for doc_path in &commercial_docs {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(doc_path);
        if !path.exists() {
            continue;
        }
        let content = read_doc(doc_path);
        for (i, line) in content.lines().enumerate() {
            if line.contains("18,700") || line.contains("18700") {
                let lower = line.to_lowercase();
                let has_qualifier = qualifiers.iter().any(|q| lower.contains(q));
                if !has_qualifier {
                    violations.push(format!("{}:{}: {}", doc_path, i + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Commercial docs present 18,700 TX/s without qualifying it as a \
         micro-benchmark (add 'motor', 'ordering', 'interno', etc.):\n  {}",
        violations.join("\n  ")
    );
}

/// The benchmark results doc must contain a caveat that micro-benchmarks
/// do not represent end-to-end throughput.
#[test]
fn benchmark_results_has_caveat() {
    let content = read_doc("docs/architecture/benchmarks/BENCHMARKS-RESULTS.md");
    let lower = content.to_lowercase();
    assert!(
        lower.contains("end-to-end") || lower.contains("e2e"),
        "BENCHMARKS-RESULTS.md must mention that these are not end-to-end numbers"
    );
    assert!(
        lower.contains("componente") || lower.contains("aislado") || lower.contains("micro"),
        "BENCHMARKS-RESULTS.md must clarify these are component-level micro-benchmarks"
    );
}

/// Active commercial docs must mention measured E2E throughput (~42 TPS or
/// the actual number), not only the micro-benchmark figure.
#[test]
fn platform_architecture_shows_e2e_throughput() {
    let content = read_doc("docs/commercial/PLATFORM-ARCHITECTURE.md");
    assert!(
        content.contains("42 TPS") || content.contains("E2E") || content.contains("e2e"),
        "PLATFORM-ARCHITECTURE.md must show the real E2E throughput alongside any motor number"
    );
}

// ── Gap 3: compliance doc honesty ────────────────────────────────────────

/// The compliance doc must contain a disclaimer stating it is a
/// self-assessment, not a formal audit or certification.
#[test]
fn compliance_doc_has_self_assessment_disclaimer() {
    let content = read_doc("docs/compliance/ELECTRONIC-SIGNATURE-COMPLIANCE.md");
    let lower = content.to_lowercase();
    let has_disclaimer = lower.contains("self-assessment")
        || lower.contains("autoevaluación")
        || lower.contains("not a certification")
        || lower.contains("no constituye certificación");
    assert!(
        has_disclaimer,
        "ELECTRONIC-SIGNATURE-COMPLIANCE.md must contain a self-assessment disclaimer"
    );
}

/// The compliance doc must clarify that biometric evidence is unverified
/// client-asserted data — the system trusts whatever hash the client sends.
#[test]
fn compliance_doc_clarifies_biometric_is_unverified() {
    let content = read_doc("docs/compliance/ELECTRONIC-SIGNATURE-COMPLIANCE.md");
    let lower = content.to_lowercase();
    let has_clarification = lower.contains("client-asserted")
        || lower.contains("unverified")
        || lower.contains("no verifica")
        || lower.contains("sin verificación");
    assert!(
        has_clarification,
        "ELECTRONIC-SIGNATURE-COMPLIANCE.md must clarify biometric commitments are \
         unverified client-asserted data"
    );
}

/// The SP 800-63B AAL2 claim must be qualified — AAL2 requires identity
/// verification through a trusted provider, not self-asserted biometrics.
#[test]
fn compliance_doc_qualifies_aal2_claim() {
    let content = read_doc("docs/compliance/ELECTRONIC-SIGNATURE-COMPLIANCE.md");
    let lower = content.to_lowercase();
    // The line mentioning AAL2 must not be a flat claim — it needs a qualifier
    let has_aal2 = lower.contains("aal2");
    if has_aal2 {
        let has_qualifier = lower.contains("approximate")
            || lower.contains("aspirational")
            || lower.contains("analogía")
            || lower.contains("no equivale")
            || lower.contains("not equivalent")
            || lower.contains("structural analogy")
            || lower.contains("requires identity verification")
            || lower.contains("requiere verificación de identidad");
        assert!(
            has_qualifier,
            "SP 800-63B AAL2 claim must be qualified — AAL2 requires identity verification \
             through a trusted provider, not self-asserted biometric hashes"
        );
    }
}

// ── Gap 6: ML-KEM-768 honest scope ──────────────────────────────────────

/// Every mention of ML-KEM-768 in active commercial docs must appear on a
/// line that also qualifies it as TLS-layer or opt-in — not a core crypto
/// feature that is always active.
#[test]
fn commercial_docs_qualify_mlkem_as_tls_opt_in() {
    let qualifiers = [
        "tls",
        "opt-in",
        "opcional",
        "TLS_PQC_KEM",
        "híbrido",
        "hibrido",
    ];
    let commercial_docs = [
        "docs/commercial/PLATFORM-ARCHITECTURE.md",
        "docs/commercial/HORIZONTAL-CAPABILITIES-REPORT.md",
        "docs/commercial/FAQ-ENTERPRISE.md",
        "docs/commercial/ONE-PAGER-SERVICIOS-API.md",
        "docs/commercial/COMPLIANCE-LEY-21663-CIBERSEGURIDAD.md",
    ];

    let mut violations = Vec::new();
    for doc_path in &commercial_docs {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(doc_path);
        if !path.exists() {
            continue;
        }
        let content = read_doc(doc_path);
        for (i, line) in content.lines().enumerate() {
            let lower = line.to_lowercase();
            if lower.contains("ml-kem") || lower.contains("mlkem") {
                let has_qualifier = qualifiers.iter().any(|q| lower.contains(&q.to_lowercase()));
                if !has_qualifier {
                    violations.push(format!("{}:{}: {}", doc_path, i + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Commercial docs present ML-KEM-768 without qualifying it as TLS opt-in:\n  {}",
        violations.join("\n  ")
    );
}

/// The regulatory sandbox check that mentions ML-KEM must say it is
/// TLS-layer opt-in, not a core always-on feature.
#[test]
fn regulatory_sandbox_qualifies_mlkem() {
    let content = read_doc("src/regulatory/sandbox.rs");
    let mlkem_lines: Vec<&str> = content
        .lines()
        .filter(|l| l.to_lowercase().contains("ml-kem"))
        .collect();
    assert!(!mlkem_lines.is_empty(), "sandbox.rs should mention ML-KEM");
    let lower_all = mlkem_lines.join(" ").to_lowercase();
    assert!(
        lower_all.contains("tls") || lower_all.contains("opt-in"),
        "sandbox.rs mentions ML-KEM without TLS/opt-in qualifier: {:?}",
        mlkem_lines
    );
}

/// eIDAS Art. 26(b) "capable of identifying the signatory" must note
/// that DID-based self-identification differs from identity-verified
/// credentials from a trusted authority.
#[test]
fn compliance_doc_qualifies_art26b() {
    let content = read_doc("docs/compliance/ELECTRONIC-SIGNATURE-COMPLIANCE.md");
    // Find the Art. 26(b) section
    let has_art26 = content.contains("Art. 26") || content.contains("Art 26");
    assert!(has_art26, "Doc must cover eIDAS Art. 26");
    let lower = content.to_lowercase();
    let has_qualifier = lower.contains("self-issued")
        || lower.contains("self-asserted")
        || lower.contains("autoemitid")
        || lower.contains("identity provider")
        || lower.contains("without external identity verification")
        || lower.contains("sin verificación externa");
    assert!(
        has_qualifier,
        "eIDAS Art. 26(b) compliance claim must note that DID-based identification \
         is self-issued, not externally verified"
    );
}
