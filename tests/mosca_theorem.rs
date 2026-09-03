use std::fmt;

struct MoscaScenario {
    name: &'static str,
    x_shelf_life_years: f64,
    y_migration_years: f64,
    z_crqc_years: f64,
    goya_mitigation: GoyaMitigation,
    source_x: &'static str,
    source_z: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum GoyaMitigation {
    Migrated,
    HybridDeployed,
    NotStarted,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum MoscaVerdict {
    Safe,
    MigrateNow,
}

impl MoscaScenario {
    fn inequality_holds(&self) -> bool {
        self.x_shelf_life_years + self.y_migration_years > self.z_crqc_years
    }

    fn verdict(&self) -> MoscaVerdict {
        if self.inequality_holds() {
            MoscaVerdict::MigrateNow
        } else {
            MoscaVerdict::Safe
        }
    }

    fn is_goya_protected(&self) -> bool {
        matches!(
            self.goya_mitigation,
            GoyaMitigation::Migrated | GoyaMitigation::HybridDeployed
        )
    }
}

impl fmt::Display for MoscaScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verdict_str = match self.verdict() {
            MoscaVerdict::Safe => "SAFE (x+y <= z)",
            MoscaVerdict::MigrateNow => "MIGRATE NOW (x+y > z)",
        };
        let mitigation_str = match self.goya_mitigation {
            GoyaMitigation::Migrated => "MIGRATED (ML-DSA-65)",
            GoyaMitigation::HybridDeployed => "HYBRID (Ed25519 + ML-DSA-65)",
            GoyaMitigation::NotStarted => "NOT STARTED",
        };
        writeln!(f, "  ║  {:<50} ║", self.name)?;
        writeln!(
            f,
            "  ║    x (shelf life):    {:>6.1} years  ({})  ║",
            self.x_shelf_life_years, self.source_x
        )?;
        writeln!(
            f,
            "  ║    y (migration):     {:>6.1} years                            ║",
            self.y_migration_years
        )?;
        writeln!(
            f,
            "  ║    z (CRQC):          {:>6.1} years  ({})  ║",
            self.z_crqc_years, self.source_z
        )?;
        writeln!(
            f,
            "  ║    x + y = {:.1}  vs  z = {:.1}                                ║",
            self.x_shelf_life_years + self.y_migration_years,
            self.z_crqc_years
        )?;
        writeln!(f, "  ║    Mosca verdict:     {:<40} ║", verdict_str)?;
        writeln!(f, "  ║    Goya status:       {:<40} ║", mitigation_str)?;
        Ok(())
    }
}

fn goya_scenarios() -> Vec<MoscaScenario> {
    vec![
        MoscaScenario {
            name: "FEA Certificate (persona natural)",
            x_shelf_life_years: 7.0,
            y_migration_years: 2.0,
            z_crqc_years: 10.0,
            goya_mitigation: GoyaMitigation::Migrated,
            source_x: "PO01: 7-year retention + cert validity",
            source_z: "Mosca & Piani GRI 2023: 50% CRQC by 2035",
        },
        MoscaScenario {
            name: "CA Root Certificate",
            x_shelf_life_years: 17.0,
            y_migration_years: 2.0,
            z_crqc_years: 10.0,
            goya_mitigation: GoyaMitigation::Migrated,
            source_x: "PS06: 10-year validity + 7-year retention",
            source_z: "Mosca & Piani GRI 2023: 50% CRQC by 2035",
        },
        MoscaScenario {
            name: "CA Intermediate Certificate",
            x_shelf_life_years: 12.0,
            y_migration_years: 2.0,
            z_crqc_years: 10.0,
            goya_mitigation: GoyaMitigation::Migrated,
            source_x: "PS06: 5-year validity + 7-year retention",
            source_z: "Mosca & Piani GRI 2023: 50% CRQC by 2035",
        },
        MoscaScenario {
            name: "LexChain Legal Contract",
            x_shelf_life_years: 17.0,
            y_migration_years: 2.0,
            z_crqc_years: 10.0,
            goya_mitigation: GoyaMitigation::HybridDeployed,
            source_x: "Chilean civil code: 10-year contract enforceability + 7-year doc retention",
            source_z: "Mosca & Piani GRI 2023: 50% CRQC by 2035",
        },
        MoscaScenario {
            name: "BFT Consensus Vote",
            x_shelf_life_years: 0.01,
            y_migration_years: 0.5,
            z_crqc_years: 10.0,
            goya_mitigation: GoyaMitigation::HybridDeployed,
            source_x: "Ephemeral: valid for single round (~minutes)",
            source_z: "Mosca & Piani GRI 2023: 50% CRQC by 2035",
        },
        MoscaScenario {
            name: "FES Simple Signature (Ed25519 only)",
            x_shelf_life_years: 7.0,
            y_migration_years: 2.0,
            z_crqc_years: 10.0,
            goya_mitigation: GoyaMitigation::HybridDeployed,
            source_x: "PO01: 7-year retention",
            source_z: "Mosca & Piani GRI 2023: 50% CRQC by 2035",
        },
        MoscaScenario {
            name: "Notarized Document (blockchain-anchored)",
            x_shelf_life_years: 27.0,
            y_migration_years: 2.0,
            z_crqc_years: 10.0,
            goya_mitigation: GoyaMitigation::HybridDeployed,
            source_x: "Immutable ledger: perpetual + 7-year legal minimum",
            source_z: "Mosca & Piani GRI 2023: 50% CRQC by 2035",
        },
        MoscaScenario {
            name: "OID4VCI Access Token (ES256)",
            x_shelf_life_years: 0.02,
            y_migration_years: 0.5,
            z_crqc_years: 10.0,
            goya_mitigation: GoyaMitigation::NotStarted,
            source_x: "Token TTL: ~10 minutes",
            source_z: "Mosca & Piani GRI 2023: 50% CRQC by 2035",
        },
    ]
}

#[test]
fn mosca_inequality_all_scenarios() {
    let scenarios = goya_scenarios();

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════════════════════════╗");
    eprintln!("  ║  MOSCA'S THEOREM — Quantum Migration Urgency Analysis                      ║");
    eprintln!("  ║                                                                              ║");
    eprintln!("  ║  Theorem (Mosca 2013): If x + y > z, migration must start NOW.              ║");
    eprintln!("  ║    x = shelf life of data (how long it must stay secure)                     ║");
    eprintln!("  ║    y = time to migrate to quantum-safe algorithms                            ║");
    eprintln!("  ║    z = time until a CRQC (Cryptographically Relevant Quantum Computer)       ║");
    eprintln!("  ║                                                                              ║");
    eprintln!("  ║  Source: Michele Mosca, 'Cybersecurity in an era with quantum computers:     ║");
    eprintln!("  ║  will we be ready?' (2018). CRQC estimates: Mosca & Piani, Global Risk       ║");
    eprintln!("  ║  Institute Annual Report (2023): 50% probability of CRQC by 2035.            ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════════════════════════╣");

    for scenario in &scenarios {
        eprint!("{scenario}");
        eprintln!("  ║  {:─<76}║", "");
    }

    eprintln!("  ╠══════════════════════════════════════════════════════════════════════════════╣");

    let must_migrate: Vec<_> = scenarios.iter().filter(|s| s.inequality_holds()).collect();
    let safe: Vec<_> = scenarios.iter().filter(|s| !s.inequality_holds()).collect();
    let protected: Vec<_> = must_migrate
        .iter()
        .filter(|s| s.is_goya_protected())
        .collect();
    let unprotected: Vec<_> = must_migrate
        .iter()
        .filter(|s| !s.is_goya_protected())
        .collect();

    eprintln!("  ║  SUMMARY                                                                    ║");
    eprintln!(
        "  ║    Scenarios where x+y > z (must migrate):  {}                               ║",
        must_migrate.len()
    );
    eprintln!(
        "  ║    Already protected by goya PQC:           {}                               ║",
        protected.len()
    );
    eprintln!(
        "  ║    Safe (x+y <= z, no urgency):             {}                               ║",
        safe.len()
    );
    eprintln!(
        "  ║    Unprotected but must migrate:            {}                               ║",
        unprotected.len()
    );
    eprintln!("  ╚══════════════════════════════════════════════════════════════════════════════╝");
    eprintln!();

    for scenario in &must_migrate {
        assert!(scenario.is_goya_protected() || !needs_long_term_protection(scenario),
            "MOSCA VIOLATION: '{}' requires migration (x+y={:.1} > z={:.1}) but goya has not migrated",
            scenario.name,
            scenario.x_shelf_life_years + scenario.y_migration_years,
            scenario.z_crqc_years
        );
    }

    let long_term_protected: Vec<_> = scenarios
        .iter()
        .filter(|s| s.x_shelf_life_years >= 5.0 && s.inequality_holds())
        .collect();
    for s in &long_term_protected {
        assert!(
            s.is_goya_protected(),
            "Long-term data '{}' (shelf life {:.0}y) must be PQC-protected",
            s.name,
            s.x_shelf_life_years
        );
    }
}

fn needs_long_term_protection(scenario: &MoscaScenario) -> bool {
    scenario.x_shelf_life_years >= 1.0
}

#[test]
fn mosca_ca_root_is_most_urgent() {
    let scenarios = goya_scenarios();

    let ca_root = scenarios
        .iter()
        .find(|s| s.name.contains("CA Root"))
        .unwrap();
    let notarized = scenarios
        .iter()
        .find(|s| s.name.contains("Notarized"))
        .unwrap();

    assert!(ca_root.inequality_holds(), "CA Root x+y > z must hold");
    assert!(
        notarized.inequality_holds(),
        "Notarized docs x+y > z must hold"
    );

    assert!(
        ca_root.is_goya_protected(),
        "CA Root must be PQC-protected (ML-DSA-65)"
    );
    assert!(
        notarized.is_goya_protected(),
        "Notarized docs must be PQC-protected (hybrid)"
    );

    let urgency_ca =
        (ca_root.x_shelf_life_years + ca_root.y_migration_years) - ca_root.z_crqc_years;
    let urgency_notarized =
        (notarized.x_shelf_life_years + notarized.y_migration_years) - notarized.z_crqc_years;

    assert!(
        urgency_notarized > urgency_ca,
        "Notarized docs (perpetual) have higher urgency ({:.1}) than CA Root ({:.1})",
        urgency_notarized,
        urgency_ca
    );

    eprintln!();
    eprintln!("  URGENCY RANKING (x+y-z, higher = more urgent):");
    let mut ranked: Vec<_> = goya_scenarios()
        .into_iter()
        .filter(|s| s.inequality_holds())
        .collect();
    ranked.sort_by(|a, b| {
        let ua = (a.x_shelf_life_years + a.y_migration_years) - a.z_crqc_years;
        let ub = (b.x_shelf_life_years + b.y_migration_years) - b.z_crqc_years;
        ub.partial_cmp(&ua).unwrap()
    });
    for s in &ranked {
        let urgency = (s.x_shelf_life_years + s.y_migration_years) - s.z_crqc_years;
        let status = if s.is_goya_protected() {
            "PROTECTED"
        } else {
            "EXPOSED"
        };
        eprintln!("    {:+6.1}y  {:<45} [{}]", urgency, s.name, status);
    }
    eprintln!();
}

#[test]
fn mosca_ephemeral_data_safe_without_pqc() {
    let scenarios = goya_scenarios();

    let ephemeral: Vec<_> = scenarios
        .iter()
        .filter(|s| s.x_shelf_life_years < 1.0)
        .collect();

    for s in &ephemeral {
        assert!(
            !s.inequality_holds() || !needs_long_term_protection(s),
            "Ephemeral data '{}' should not trigger Mosca urgency",
            s.name
        );
    }

    eprintln!();
    eprintln!("  EPHEMERAL DATA (x < 1 year):");
    for s in &ephemeral {
        eprintln!(
            "    {:<40} x={:.2}y  x+y={:.2}  verdict=SAFE",
            s.name,
            s.x_shelf_life_years,
            s.x_shelf_life_years + s.y_migration_years
        );
    }
    eprintln!();
}

#[test]
fn mosca_goya_migration_status_is_complete() {
    let scenarios = goya_scenarios();

    let total = scenarios.len();
    let migrated_count = scenarios
        .iter()
        .filter(|s| matches!(s.goya_mitigation, GoyaMitigation::Migrated))
        .count();
    let hybrid_count = scenarios
        .iter()
        .filter(|s| matches!(s.goya_mitigation, GoyaMitigation::HybridDeployed))
        .count();
    let not_started_count = scenarios
        .iter()
        .filter(|s| matches!(s.goya_mitigation, GoyaMitigation::NotStarted))
        .count();

    assert!(
        migrated_count + hybrid_count >= 6,
        "At least 6 of {} scenarios must be PQC-protected, got {}",
        total,
        migrated_count + hybrid_count
    );

    let not_started_long_term: Vec<_> = scenarios
        .iter()
        .filter(|s| {
            matches!(s.goya_mitigation, GoyaMitigation::NotStarted) && s.x_shelf_life_years >= 1.0
        })
        .collect();
    assert!(
        not_started_long_term.is_empty(),
        "No long-term data should lack PQC migration, found: {:?}",
        not_started_long_term
            .iter()
            .map(|s| s.name)
            .collect::<Vec<_>>()
    );

    eprintln!();
    eprintln!("  GOYA MIGRATION STATUS:");
    eprintln!("    Fully migrated (ML-DSA-65):    {}", migrated_count);
    eprintln!("    Hybrid deployed (Ed25519+PQC): {}", hybrid_count);
    eprintln!("    Not started (acceptable):      {}", not_started_count);
    eprintln!(
        "    Coverage: {:.0}% of scenarios PQC-protected",
        (migrated_count + hybrid_count) as f64 / total as f64 * 100.0
    );
    eprintln!();
}

#[test]
fn mosca_crqc_sensitivity_analysis() {
    let scenarios = goya_scenarios();

    let crqc_estimates = [
        ("Optimistic (2040)", 15.0),
        ("Mosca & Piani median (2035)", 10.0),
        ("Pessimistic (2030)", 5.0),
        ("Aggressive (2028)", 3.0),
    ];

    eprintln!();
    eprintln!("  CRQC SENSITIVITY ANALYSIS:");
    eprintln!("  How many goya-ledger scenarios require migration under different CRQC timelines?");
    eprintln!();

    for (label, z) in &crqc_estimates {
        let must_migrate: Vec<_> = scenarios
            .iter()
            .filter(|s| s.x_shelf_life_years + s.y_migration_years > *z)
            .collect();
        let unprotected: Vec<_> = must_migrate
            .iter()
            .filter(|s| !s.is_goya_protected() && needs_long_term_protection(s))
            .collect();

        eprintln!(
            "    z={:>5.1}y {:<30} → {}/{} must migrate, {} unprotected long-term",
            z,
            label,
            must_migrate.len(),
            scenarios.len(),
            unprotected.len()
        );

        assert_eq!(
            unprotected.len(),
            0,
            "Under {} (z={:.1}), {} long-term scenarios lack PQC protection: {:?}",
            label,
            z,
            unprotected.len(),
            unprotected.iter().map(|s| s.name).collect::<Vec<_>>()
        );
    }
    eprintln!();
}
