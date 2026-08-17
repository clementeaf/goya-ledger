//! EUDI attestation type hierarchy and issuer authorization.
//!
//! Models the ARF v3.0 attestation tiers (PID, EAA, QEAA, PuB-EAA) and
//! enforces issuer role requirements at issuance time.
//!
//! Separation of concerns:
//! - **Technical capability**: Goya validates that an issuer's registered role
//!   matches the attestation type and that required prerequisites (e.g. PID)
//!   are satisfied.
//! - **Legal status**: Goya does NOT self-declare that an issuer is a QTSP or
//!   public authority. That determination comes from an external trust source
//!   (Trusted List / LoTE) registered in the `AttestationTypeRegistry`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// ── Attestation types ────────────────────────────────────────────────────

/// EUDI attestation tier per ARF v3.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttestationType {
    /// Person Identification Data — issued only by Member State PID Providers.
    Pid,
    /// Electronic Attestation of Attributes — any Trust Service Provider.
    Eaa,
    /// Qualified EAA — Qualified Trust Service Provider only.
    Qeaa,
    /// Public-body EAA — public authority or authentic source delegate.
    PubEaa,
}

impl std::fmt::Display for AttestationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pid => write!(f, "PID"),
            Self::Eaa => write!(f, "EAA"),
            Self::Qeaa => write!(f, "QEAA"),
            Self::PubEaa => write!(f, "PuB-EAA"),
        }
    }
}

// ── Issuer roles ─────────────────────────────────────────────────────────

/// Role of an issuer in the EUDI ecosystem.
/// Registered via external trust source, not self-declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IssuerRole {
    /// Member State PID Provider (can issue PID).
    PidProvider,
    /// Trust Service Provider (can issue EAA).
    Tsp,
    /// Qualified Trust Service Provider (can issue EAA + QEAA).
    Qtsp,
    /// Public authority / authentic source (can issue EAA + PuB-EAA).
    PublicBody,
}

impl IssuerRole {
    /// Which attestation types this role authorizes.
    fn authorized_types(&self) -> &[AttestationType] {
        match self {
            Self::PidProvider => &[AttestationType::Pid],
            Self::Tsp => &[AttestationType::Eaa],
            Self::Qtsp => &[AttestationType::Eaa, AttestationType::Qeaa],
            Self::PublicBody => &[AttestationType::Eaa, AttestationType::PubEaa],
        }
    }

    pub fn can_issue(&self, att_type: AttestationType) -> bool {
        self.authorized_types().contains(&att_type)
    }
}

impl std::fmt::Display for IssuerRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PidProvider => write!(f, "PID Provider"),
            Self::Tsp => write!(f, "TSP"),
            Self::Qtsp => write!(f, "QTSP"),
            Self::PublicBody => write!(f, "Public Body"),
        }
    }
}

// ── Attestation rulebook ─────────────────────────────────────────────────

/// Minimal rulebook: required claims + schema for a credential type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationRulebook {
    pub attestation_type: AttestationType,
    pub vct: String,
    pub required_claims: Vec<String>,
    pub requires_pid: bool,
}

impl AttestationRulebook {
    pub fn validate_claims(&self, claims: &serde_json::Value) -> Result<(), String> {
        let map = claims.as_object().ok_or("claims must be a JSON object")?;
        for field in &self.required_claims {
            if !map.contains_key(field) {
                return Err(format!(
                    "{} rulebook: missing required claim '{field}'",
                    self.vct
                ));
            }
        }
        Ok(())
    }
}

// ── Issuer registration ──────────────────────────────────────────────────

/// Registered issuer entry. The `trust_source` field documents WHERE the
/// role assignment came from — Goya does not self-assign roles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredIssuer {
    pub did: String,
    pub role: IssuerRole,
    /// URI or identifier of the external trust source that authorized this
    /// issuer (e.g. a Trusted List URI, LoTE entry, or regulatory reference).
    pub trust_source: String,
    /// Optional: specific attestation types this issuer is authorized for
    /// within their role. Empty = all types the role permits.
    pub authorized_vcts: Vec<String>,
    pub registered_at: u64,
}

// ── Registry ─────────────────────────────────────────────────────────────

/// Central registry of issuer authorizations and attestation rulebooks.
/// Thread-safe for use in AppState.
pub struct AttestationTypeRegistry {
    issuers: RwLock<HashMap<String, RegisteredIssuer>>,
    rulebooks: RwLock<HashMap<String, AttestationRulebook>>,
}

impl AttestationTypeRegistry {
    pub fn new() -> Self {
        let mut rulebooks = HashMap::new();
        // Built-in PID rulebook per CIR 2024/2977
        rulebooks.insert(
            "eu.europa.ec.eudi.pid.1".to_string(),
            AttestationRulebook {
                attestation_type: AttestationType::Pid,
                vct: "eu.europa.ec.eudi.pid.1".to_string(),
                required_claims: vec![
                    "family_name".into(),
                    "given_name".into(),
                    "birth_date".into(),
                ],
                requires_pid: false, // PID is the root — no prerequisite
            },
        );
        Self {
            issuers: RwLock::new(HashMap::new()),
            rulebooks: RwLock::new(rulebooks),
        }
    }

    // ── Issuer management ────────────────────────────────────────────

    /// Register an issuer with a role from an external trust source.
    pub fn register_issuer(&self, issuer: RegisteredIssuer) {
        self.issuers
            .write()
            .unwrap()
            .insert(issuer.did.clone(), issuer);
    }

    pub fn get_issuer(&self, did: &str) -> Option<RegisteredIssuer> {
        self.issuers.read().unwrap().get(did).cloned()
    }

    pub fn remove_issuer(&self, did: &str) -> bool {
        self.issuers.write().unwrap().remove(did).is_some()
    }

    // ── Rulebook management ──────────────────────────────────────────

    pub fn register_rulebook(&self, rulebook: AttestationRulebook) {
        self.rulebooks
            .write()
            .unwrap()
            .insert(rulebook.vct.clone(), rulebook);
    }

    pub fn get_rulebook(&self, vct: &str) -> Option<AttestationRulebook> {
        self.rulebooks.read().unwrap().get(vct).cloned()
    }

    // ── Authorization check ──────────────────────────────────────────

    /// Validate that an issuer is authorized to issue a specific attestation.
    ///
    /// Checks (fail-closed — all must pass):
    /// 1. Issuer is registered
    /// 2. Rulebook exists for the vct
    /// 3. Issuer's role permits the attestation type
    /// 4. If issuer has restricted vcts, the vct is in the list
    /// 5. Required claims are present
    /// 6. PID prerequisite satisfied (if required)
    pub fn authorize_issuance(
        &self,
        issuer_did: &str,
        vct: &str,
        claims: &serde_json::Value,
        holder_has_pid: bool,
    ) -> Result<IssuanceAuthorization, String> {
        // 1. Issuer registered?
        let issuer = self
            .get_issuer(issuer_did)
            .ok_or_else(|| format!("issuer '{issuer_did}' not registered"))?;

        // 2. Rulebook exists?
        let rulebook = self
            .get_rulebook(vct)
            .ok_or_else(|| format!("no rulebook for vct '{vct}'"))?;

        // 3. Role permits attestation type?
        if !issuer.role.can_issue(rulebook.attestation_type) {
            return Err(format!(
                "issuer role {} cannot issue {} (type {})",
                issuer.role, vct, rulebook.attestation_type
            ));
        }

        // 4. Restricted vcts?
        if !issuer.authorized_vcts.is_empty() && !issuer.authorized_vcts.contains(&vct.to_string())
        {
            return Err(format!(
                "issuer '{issuer_did}' not authorized for vct '{vct}'"
            ));
        }

        // 5. Required claims?
        rulebook.validate_claims(claims)?;

        // 6. PID prerequisite?
        if rulebook.requires_pid && !holder_has_pid {
            return Err(format!("vct '{vct}' requires holder to have a valid PID"));
        }

        Ok(IssuanceAuthorization {
            attestation_type: rulebook.attestation_type,
            issuer_role: issuer.role,
            trust_source: issuer.trust_source.clone(),
            vct: vct.to_string(),
        })
    }
}

impl Default for AttestationTypeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Successful authorization result — metadata for the issued credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceAuthorization {
    pub attestation_type: AttestationType,
    pub issuer_role: IssuerRole,
    pub trust_source: String,
    pub vct: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn registry_with_issuers() -> AttestationTypeRegistry {
        let reg = AttestationTypeRegistry::new();

        // PID Provider — authorized by member state TSL
        reg.register_issuer(RegisteredIssuer {
            did: "did:goya:pid-provider".into(),
            role: IssuerRole::PidProvider,
            trust_source: "https://tsl.example.eu/pid-providers".into(),
            authorized_vcts: vec![],
            registered_at: now(),
        });

        // QTSP — authorized by EU Trusted List
        reg.register_issuer(RegisteredIssuer {
            did: "did:goya:qtsp-acme".into(),
            role: IssuerRole::Qtsp,
            trust_source: "https://tsl.example.eu/qtsp-list".into(),
            authorized_vcts: vec![],
            registered_at: now(),
        });

        // TSP — authorized by national registry
        reg.register_issuer(RegisteredIssuer {
            did: "did:goya:tsp-corp".into(),
            role: IssuerRole::Tsp,
            trust_source: "https://tsl.example.eu/tsp-list".into(),
            authorized_vcts: vec![],
            registered_at: now(),
        });

        // Public Body — authorized by public authority registry
        reg.register_issuer(RegisteredIssuer {
            did: "did:goya:gov-agency".into(),
            role: IssuerRole::PublicBody,
            trust_source: "https://lote.example.eu/public-bodies".into(),
            authorized_vcts: vec![],
            registered_at: now(),
        });

        // EAA rulebook for diplomas
        reg.register_rulebook(AttestationRulebook {
            attestation_type: AttestationType::Eaa,
            vct: "eu.europa.ec.eudi.diploma.1".into(),
            required_claims: vec!["degree".into(), "institution".into(), "date_awarded".into()],
            requires_pid: true,
        });

        // QEAA rulebook for professional licenses
        reg.register_rulebook(AttestationRulebook {
            attestation_type: AttestationType::Qeaa,
            vct: "eu.europa.ec.eudi.professional_license.1".into(),
            required_claims: vec!["license_type".into(), "issuing_authority".into()],
            requires_pid: true,
        });

        // PuB-EAA rulebook for residence certificates
        reg.register_rulebook(AttestationRulebook {
            attestation_type: AttestationType::PubEaa,
            vct: "eu.europa.ec.eudi.residence.1".into(),
            required_claims: vec!["address".into(), "municipality".into()],
            requires_pid: true,
        });

        reg
    }

    // ── PID issuance ─────────────────────────────────────────────────

    #[test]
    fn pid_provider_can_issue_pid() {
        let reg = registry_with_issuers();
        let claims = serde_json::json!({
            "family_name": "García",
            "given_name": "María",
            "birth_date": "1985-03-15",
        });
        let auth = reg
            .authorize_issuance(
                "did:goya:pid-provider",
                "eu.europa.ec.eudi.pid.1",
                &claims,
                false,
            )
            .unwrap();
        assert_eq!(auth.attestation_type, AttestationType::Pid);
        assert_eq!(auth.issuer_role, IssuerRole::PidProvider);
    }

    #[test]
    fn pid_rejects_missing_required_claims() {
        let reg = registry_with_issuers();
        let claims = serde_json::json!({
            "family_name": "García",
            // missing given_name and birth_date
        });
        let err = reg
            .authorize_issuance(
                "did:goya:pid-provider",
                "eu.europa.ec.eudi.pid.1",
                &claims,
                false,
            )
            .unwrap_err();
        assert!(err.contains("given_name"), "got: {err}");
    }

    #[test]
    fn non_pid_provider_cannot_issue_pid() {
        let reg = registry_with_issuers();
        let claims = serde_json::json!({
            "family_name": "Test",
            "given_name": "Test",
            "birth_date": "2000-01-01",
        });
        let err = reg
            .authorize_issuance(
                "did:goya:qtsp-acme",
                "eu.europa.ec.eudi.pid.1",
                &claims,
                false,
            )
            .unwrap_err();
        assert!(err.contains("cannot issue"), "got: {err}");
    }

    // ── EAA issuance ─────────────────────────────────────────────────

    #[test]
    fn qtsp_can_issue_eaa() {
        let reg = registry_with_issuers();
        let claims = serde_json::json!({
            "degree": "Computer Science",
            "institution": "Universidad de Chile",
            "date_awarded": "2020-06-15",
        });
        let auth = reg
            .authorize_issuance(
                "did:goya:qtsp-acme",
                "eu.europa.ec.eudi.diploma.1",
                &claims,
                true,
            )
            .unwrap();
        assert_eq!(auth.attestation_type, AttestationType::Eaa);
    }

    #[test]
    fn eaa_requires_pid() {
        let reg = registry_with_issuers();
        let claims = serde_json::json!({
            "degree": "Computer Science",
            "institution": "Universidad de Chile",
            "date_awarded": "2020-06-15",
        });
        let err = reg
            .authorize_issuance(
                "did:goya:qtsp-acme",
                "eu.europa.ec.eudi.diploma.1",
                &claims,
                false, // no PID
            )
            .unwrap_err();
        assert!(
            err.contains("requires holder to have a valid PID"),
            "got: {err}"
        );
    }

    // ── QEAA issuance ────────────────────────────────────────────────

    #[test]
    fn qtsp_can_issue_qeaa() {
        let reg = registry_with_issuers();
        let claims = serde_json::json!({
            "license_type": "Medical Doctor",
            "issuing_authority": "Colegio Médico",
        });
        let auth = reg
            .authorize_issuance(
                "did:goya:qtsp-acme",
                "eu.europa.ec.eudi.professional_license.1",
                &claims,
                true,
            )
            .unwrap();
        assert_eq!(auth.attestation_type, AttestationType::Qeaa);
        assert_eq!(auth.issuer_role, IssuerRole::Qtsp);
    }

    #[test]
    fn tsp_cannot_issue_qeaa() {
        let reg = registry_with_issuers();
        let claims = serde_json::json!({
            "license_type": "Medical Doctor",
            "issuing_authority": "Colegio Médico",
        });
        let err = reg
            .authorize_issuance(
                "did:goya:tsp-corp",
                "eu.europa.ec.eudi.professional_license.1",
                &claims,
                true,
            )
            .unwrap_err();
        assert!(err.contains("TSP cannot issue"), "got: {err}");
    }

    // ── PuB-EAA issuance ─────────────────────────────────────────────

    #[test]
    fn public_body_can_issue_pub_eaa() {
        let reg = registry_with_issuers();
        let claims = serde_json::json!({
            "address": "Av. Libertador 1234",
            "municipality": "Santiago",
        });
        let auth = reg
            .authorize_issuance(
                "did:goya:gov-agency",
                "eu.europa.ec.eudi.residence.1",
                &claims,
                true,
            )
            .unwrap();
        assert_eq!(auth.attestation_type, AttestationType::PubEaa);
        assert_eq!(auth.issuer_role, IssuerRole::PublicBody);
    }

    #[test]
    fn qtsp_cannot_issue_pub_eaa() {
        let reg = registry_with_issuers();
        let claims = serde_json::json!({
            "address": "Test",
            "municipality": "Test",
        });
        let err = reg
            .authorize_issuance(
                "did:goya:qtsp-acme",
                "eu.europa.ec.eudi.residence.1",
                &claims,
                true,
            )
            .unwrap_err();
        assert!(err.contains("cannot issue"), "got: {err}");
    }

    // ── Unregistered issuer ──────────────────────────────────────────

    #[test]
    fn unregistered_issuer_rejected() {
        let reg = registry_with_issuers();
        let claims =
            serde_json::json!({"family_name": "X", "given_name": "Y", "birth_date": "2000-01-01"});
        let err = reg
            .authorize_issuance(
                "did:goya:unknown",
                "eu.europa.ec.eudi.pid.1",
                &claims,
                false,
            )
            .unwrap_err();
        assert!(err.contains("not registered"), "got: {err}");
    }

    // ── Unknown vct ──────────────────────────────────────────────────

    #[test]
    fn unknown_vct_rejected() {
        let reg = registry_with_issuers();
        let claims = serde_json::json!({"foo": "bar"});
        let err = reg
            .authorize_issuance("did:goya:pid-provider", "unknown.type.1", &claims, false)
            .unwrap_err();
        assert!(err.contains("no rulebook"), "got: {err}");
    }

    // ── Restricted vcts ──────────────────────────────────────────────

    #[test]
    fn restricted_vct_enforcement() {
        let reg = AttestationTypeRegistry::new();
        reg.register_issuer(RegisteredIssuer {
            did: "did:goya:restricted".into(),
            role: IssuerRole::Tsp,
            trust_source: "https://tsl.example.eu/tsp".into(),
            authorized_vcts: vec!["eu.europa.ec.eudi.diploma.1".into()],
            registered_at: now(),
        });
        reg.register_rulebook(AttestationRulebook {
            attestation_type: AttestationType::Eaa,
            vct: "eu.europa.ec.eudi.diploma.1".into(),
            required_claims: vec!["degree".into()],
            requires_pid: false,
        });
        reg.register_rulebook(AttestationRulebook {
            attestation_type: AttestationType::Eaa,
            vct: "eu.europa.ec.eudi.health.1".into(),
            required_claims: vec!["diagnosis".into()],
            requires_pid: false,
        });

        // Allowed vct
        let claims = serde_json::json!({"degree": "CS"});
        assert!(reg
            .authorize_issuance(
                "did:goya:restricted",
                "eu.europa.ec.eudi.diploma.1",
                &claims,
                true
            )
            .is_ok());

        // Disallowed vct
        let claims = serde_json::json!({"diagnosis": "healthy"});
        let err = reg
            .authorize_issuance(
                "did:goya:restricted",
                "eu.europa.ec.eudi.health.1",
                &claims,
                true,
            )
            .unwrap_err();
        assert!(err.contains("not authorized for vct"), "got: {err}");
    }

    // ── Role authorization matrix ────────────────────────────────────

    #[test]
    fn role_authorization_matrix() {
        assert!(IssuerRole::PidProvider.can_issue(AttestationType::Pid));
        assert!(!IssuerRole::PidProvider.can_issue(AttestationType::Eaa));
        assert!(!IssuerRole::PidProvider.can_issue(AttestationType::Qeaa));
        assert!(!IssuerRole::PidProvider.can_issue(AttestationType::PubEaa));

        assert!(!IssuerRole::Tsp.can_issue(AttestationType::Pid));
        assert!(IssuerRole::Tsp.can_issue(AttestationType::Eaa));
        assert!(!IssuerRole::Tsp.can_issue(AttestationType::Qeaa));
        assert!(!IssuerRole::Tsp.can_issue(AttestationType::PubEaa));

        assert!(!IssuerRole::Qtsp.can_issue(AttestationType::Pid));
        assert!(IssuerRole::Qtsp.can_issue(AttestationType::Eaa));
        assert!(IssuerRole::Qtsp.can_issue(AttestationType::Qeaa));
        assert!(!IssuerRole::Qtsp.can_issue(AttestationType::PubEaa));

        assert!(!IssuerRole::PublicBody.can_issue(AttestationType::Pid));
        assert!(IssuerRole::PublicBody.can_issue(AttestationType::Eaa));
        assert!(!IssuerRole::PublicBody.can_issue(AttestationType::Qeaa));
        assert!(IssuerRole::PublicBody.can_issue(AttestationType::PubEaa));
    }

    // ── Trust source preserved ───────────────────────────────────────

    #[test]
    fn authorization_carries_trust_source() {
        let reg = registry_with_issuers();
        let claims = serde_json::json!({
            "family_name": "Test",
            "given_name": "Test",
            "birth_date": "2000-01-01",
        });
        let auth = reg
            .authorize_issuance(
                "did:goya:pid-provider",
                "eu.europa.ec.eudi.pid.1",
                &claims,
                false,
            )
            .unwrap();
        assert_eq!(auth.trust_source, "https://tsl.example.eu/pid-providers");
    }

    // ── Issuer removal ───────────────────────────────────────────────

    #[test]
    fn removed_issuer_cannot_issue() {
        let reg = registry_with_issuers();
        let claims = serde_json::json!({
            "family_name": "Test",
            "given_name": "Test",
            "birth_date": "2000-01-01",
        });
        assert!(reg
            .authorize_issuance(
                "did:goya:pid-provider",
                "eu.europa.ec.eudi.pid.1",
                &claims,
                false
            )
            .is_ok());
        reg.remove_issuer("did:goya:pid-provider");
        assert!(reg
            .authorize_issuance(
                "did:goya:pid-provider",
                "eu.europa.ec.eudi.pid.1",
                &claims,
                false
            )
            .is_err());
    }

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn display_types_and_roles() {
        assert_eq!(format!("{}", AttestationType::Pid), "PID");
        assert_eq!(format!("{}", AttestationType::Qeaa), "QEAA");
        assert_eq!(format!("{}", AttestationType::PubEaa), "PuB-EAA");
        assert_eq!(format!("{}", IssuerRole::Qtsp), "QTSP");
        assert_eq!(format!("{}", IssuerRole::PublicBody), "Public Body");
    }
}
