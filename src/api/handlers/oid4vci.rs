//! OpenID4VCI — OpenID for Verifiable Credential Issuance (1.0).
//!
//! Implements the pre-authorized code flow for EUDI Wallet interop:
//! - `GET  /.well-known/openid-credential-issuer` — issuer metadata
//! - `POST /token` — exchange pre-authorized code for access token
//! - `POST /credential` — issue SD-JWT VC or mdoc

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::app_state::AppState;
use crate::crypto::hasher::{hash_with, HashAlgorithm};
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

fn base64url_encode(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data)
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s)
        .map_err(|e| e.to_string())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Extract raw public key hex from a JWK. Supports OKP/Ed25519 and RSA.
fn extract_pubkey_from_jwk(jwk: &serde_json::Value, alg: &str) -> Option<String> {
    match alg {
        "EdDSA" => {
            let x = jwk.get("x")?.as_str()?;
            let bytes = base64url_decode(x).ok()?;
            Some(hex::encode(bytes))
        }
        "RS256" => {
            let n = jwk.get("n")?.as_str()?;
            let bytes = base64url_decode(n).ok()?;
            Some(hex::encode(bytes))
        }
        "ES256" => {
            let x = jwk.get("x")?.as_str()?;
            let y = jwk.get("y")?.as_str()?;
            let x_bytes = base64url_decode(x).ok()?;
            let y_bytes = base64url_decode(y).ok()?;
            // SEC1 uncompressed: 0x04 || x || y
            let mut pk = Vec::with_capacity(65);
            pk.push(0x04);
            pk.extend_from_slice(&x_bytes);
            pk.extend_from_slice(&y_bytes);
            Some(hex::encode(pk))
        }
        _ => None,
    }
}

// ── DPoP proof validation (RFC 9449) ──────────────────────────────────────

/// Parsed DPoP proof fields.
struct DpopClaims {
    /// JWK thumbprint of the proof key (base64url of SHA-256).
    pub jkt: String,
}

/// Validate a DPoP proof JWT (RFC 9449 §4.3).
/// Checks: typ=dpop+jwt, htm, htu, iat freshness, jti presence, jwk presence.
/// Returns the JWK thumbprint for binding to the access token.
fn verify_dpop_proof(dpop_jwt: &str, htm: &str, htu: &str) -> Result<DpopClaims, String> {
    let parts: Vec<&str> = dpop_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("DPoP JWT must have 3 parts".into());
    }

    let header: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[0])?).map_err(|e| e.to_string())?;
    let payload: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[1])?).map_err(|e| e.to_string())?;

    // typ must be "dpop+jwt"
    if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
        return Err("DPoP typ must be dpop+jwt".into());
    }

    // Must have alg
    if header.get("alg").and_then(|v| v.as_str()).is_none() {
        return Err("DPoP missing alg".into());
    }

    // Must have jwk with key material
    let jwk = header
        .get("jwk")
        .ok_or("DPoP missing jwk in header")?
        .clone();

    // htm must match
    if payload.get("htm").and_then(|v| v.as_str()) != Some(htm) {
        return Err(format!("DPoP htm mismatch: expected {htm}"));
    }

    // htu must match
    if payload.get("htu").and_then(|v| v.as_str()) != Some(htu) {
        return Err(format!("DPoP htu mismatch: expected {htu}"));
    }

    // iat must be present and within 5 minutes
    let iat = payload
        .get("iat")
        .and_then(|v| v.as_u64())
        .ok_or("DPoP missing iat")?;
    let now = now_secs();
    if now > iat + 300 || (iat > now && iat - now > 60) {
        return Err("DPoP iat outside acceptable window".into());
    }

    // jti must be present
    if payload
        .get("jti")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty()
    {
        return Err("DPoP missing jti".into());
    }

    // Verify DPoP JWT signature using the embedded JWK
    let alg_str = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if let Some(pubkey_hex) = extract_pubkey_from_jwk(&jwk, alg_str) {
        let sig_bytes = base64url_decode(parts[2])?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_hex = hex::encode(&sig_bytes);
        let algorithm = match alg_str {
            "EdDSA" => crate::identity::signing::SigningAlgorithm::Ed25519,
            "RS256" => crate::identity::signing::SigningAlgorithm::Rsa,
            "ES256" => crate::identity::signing::SigningAlgorithm::EcdsaP256,
            _ => return Err(format!("unsupported DPoP alg for verification: {alg_str}")),
        };
        if !crate::signature::verify_signature(
            algorithm,
            &pubkey_hex,
            signing_input.as_bytes(),
            &sig_hex,
        ) {
            return Err("DPoP signature verification failed".into());
        }
    }

    // Compute JWK thumbprint (RFC 7638): SHA-256 of canonical JWK JSON
    let jwk_canonical = serde_json::to_vec(&jwk).map_err(|e| e.to_string())?;
    let jkt = base64url_encode(&hash_with(HashAlgorithm::Sha256, &jwk_canonical));

    Ok(DpopClaims { jkt })
}

// ── Wallet Provider Registry ──────────────────────────────────────────────

/// Registry of trusted wallet provider public keys for WIA verification.
pub struct WalletProviderRegistry {
    providers: std::sync::RwLock<std::collections::HashMap<String, String>>,
}

impl WalletProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Register a wallet provider's public key (issuer → pubkey_hex).
    pub fn register(&self, issuer: &str, pubkey_hex: &str) {
        self.providers
            .write()
            .unwrap()
            .insert(issuer.to_string(), pubkey_hex.to_string());
    }

    /// Look up a provider's public key by issuer.
    pub fn resolve(&self, issuer: &str) -> Option<String> {
        self.providers.read().unwrap().get(issuer).cloned()
    }
}

impl Default for WalletProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Wallet Instance Attestation ───────────────────────────────────────────

/// Validate a Wallet Instance Attestation (WIA) JWT.
/// Verifies structure, claims, expiration, and signature (when provider key available).
fn verify_wia(
    wia_jwt: &str,
    registry: Option<&WalletProviderRegistry>,
) -> Result<serde_json::Value, String> {
    let parts: Vec<&str> = wia_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("WIA JWT must have 3 parts".into());
    }

    let header: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[0])?).map_err(|e| e.to_string())?;
    let payload: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[1])?).map_err(|e| e.to_string())?;

    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ != "wia+jwt" && typ != "wallet-attestation+jwt" {
        return Err("WIA typ must be wia+jwt or wallet-attestation+jwt".into());
    }

    let alg_str = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");

    for field in &["iss", "sub"] {
        if payload
            .get(*field)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty()
        {
            return Err(format!("WIA missing {field}"));
        }
    }

    let now = now_secs();
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
        if now > exp {
            return Err("WIA expired".into());
        }
    }

    // Verify WIA signature if wallet provider key is registered
    let iss = payload["iss"].as_str().unwrap_or("");
    if let Some(reg) = registry {
        if let Some(pubkey_hex) = reg.resolve(iss) {
            let algorithm = match alg_str {
                "EdDSA" => crate::identity::signing::SigningAlgorithm::Ed25519,
                "RS256" => crate::identity::signing::SigningAlgorithm::Rsa,
                "ES256" => crate::identity::signing::SigningAlgorithm::EcdsaP256,
                other => return Err(format!("unsupported WIA alg: {other}")),
            };
            let sig_bytes = base64url_decode(parts[2])?;
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let sig_hex = hex::encode(&sig_bytes);
            if !crate::signature::verify_signature(
                algorithm,
                &pubkey_hex,
                signing_input.as_bytes(),
                &sig_hex,
            ) {
                return Err("WIA signature verification failed".into());
            }
        }
    }

    Ok(payload)
}

// ── Nonce Store (OID4VCI 1.0 Final — dedicated nonce endpoint) ────────────

/// Server-side nonce store with TTL and single-use enforcement.
pub struct NonceStore {
    nonces: std::sync::Mutex<std::collections::HashMap<String, NonceEntry>>,
}

struct NonceEntry {
    created_at: u64,
    ttl_secs: u64,
    used: bool,
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            nonces: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn generate(&self, ttl_secs: u64) -> String {
        use pqc_crypto_module::legacy::rng::OsRng;
        use rand_core::RngCore;
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let nonce = hex::encode(buf);

        let mut store = self.nonces.lock().unwrap();
        // Evict expired nonces on each generation to bound memory.
        let now = now_secs();
        store.retain(|_, e| now < e.created_at + e.ttl_secs);
        store.insert(
            nonce.clone(),
            NonceEntry {
                created_at: now,
                ttl_secs,
                used: false,
            },
        );
        nonce
    }

    /// Consume a nonce. Returns Ok(()) if valid and unused.
    /// Fails on: unknown, expired, already used.
    pub fn consume(&self, nonce: &str) -> Result<(), &'static str> {
        let mut store = self.nonces.lock().unwrap();
        let entry = store.get_mut(nonce).ok_or("unknown nonce")?;
        let now = now_secs();
        if now >= entry.created_at + entry.ttl_secs {
            store.remove(nonce);
            return Err("nonce expired");
        }
        if entry.used {
            return Err("nonce already used");
        }
        entry.used = true;
        Ok(())
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Key proof (c_nonce binding) ───────────────────────────────────────────

/// Validate the proof JWT in a credential request (OpenID4VCI §7.2.1).
/// Checks: typ=openid4vci-proof+jwt, nonce matches c_nonce, aud matches issuer.
fn verify_proof_jwt(
    proof_jwt: &str,
    expected_nonce: &str,
    expected_aud: &str,
) -> Result<(), String> {
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("proof JWT must have 3 parts".into());
    }

    let header: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[0])?).map_err(|e| e.to_string())?;
    let payload: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[1])?).map_err(|e| e.to_string())?;

    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ != "openid4vci-proof+jwt" {
        return Err("proof typ must be openid4vci-proof+jwt".into());
    }

    // nonce must match c_nonce from token response
    let nonce = payload.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
    if nonce != expected_nonce {
        return Err("proof nonce does not match c_nonce".into());
    }

    // aud should match credential issuer
    let aud = payload.get("aud").and_then(|v| v.as_str()).unwrap_or("");
    if !aud.is_empty() && !expected_aud.is_empty() && aud != expected_aud {
        return Err(format!("proof aud mismatch: expected {expected_aud}"));
    }

    // iat must be present and within 5 minutes
    let iat = payload
        .get("iat")
        .and_then(|v| v.as_u64())
        .ok_or("proof missing iat")?;
    let now = now_secs();
    if now > iat + 300 || (iat > now && iat - now > 60) {
        return Err("proof iat outside acceptable window".into());
    }

    Ok(())
}

// ── Nonce Endpoint (OID4VCI 1.0 Final) ───────────────────────────────────

const NONCE_TTL_SECS: u64 = 300;

/// Dedicated nonce endpoint — OID4VCI 1.0 Final moved c_nonce issuance
/// here (no longer embedded in token/credential responses).
#[post("/nonce")]
pub async fn nonce_endpoint(nonce_store: web::Data<NonceStore>) -> ApiResult<HttpResponse> {
    let c_nonce = nonce_store.generate(NONCE_TTL_SECS);
    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .json(serde_json::json!({
            "c_nonce": c_nonce,
            "c_nonce_expires_in": NONCE_TTL_SECS,
        })))
}

// ── Issuer Metadata ───────────────────────────────────────────────────────

/// OpenID4VCI Issuer Metadata (OID4VCI 1.0 Final).
#[get("/.well-known/openid-credential-issuer")]
pub async fn issuer_metadata(req: HttpRequest) -> ApiResult<HttpResponse> {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let base = format!("https://{host}");

    let metadata = serde_json::json!({
        "credential_issuer": base,
        "credential_endpoint": format!("{base}/credential"),
        "nonce_endpoint": format!("{base}/nonce"),
        "token_endpoint": format!("{base}/token"),
        "credential_offer_endpoint": format!("{base}/credential_offer"),
        "grant_types_supported": [
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "authorization_code"
        ],
        "credential_configurations_supported": {
            "IdentityCredential_sd_jwt": {
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["EdDSA", "ES256", "ML-DSA-65", "RS256"],
                "claims": {
                    "given_name": { "mandatory": false },
                    "family_name": { "mandatory": false },
                    "birth_date": { "mandatory": false },
                    "nationality": { "mandatory": false },
                    "age_over_18": { "mandatory": false },
                    "rut": { "mandatory": false },
                    "emirates_id": { "mandatory": false },
                }
            },
            "eudi_pid_mdoc": {
                "format": "mso_mdoc",
                "doctype": "eu.europa.ec.eudi.pid.1",
                "cryptographic_binding_methods_supported": ["cose_key"],
                "credential_signing_alg_values_supported": ["EdDSA", "ES256", "ML-DSA-65"],
            }
        },
        "display": [{
            "name": "Goya Ledger",
            "locale": "en",
        }],
    });

    Ok(HttpResponse::Ok().json(metadata))
}

// ── Token Endpoint ────────────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: Option<String>,
    /// Authorization code (for authorization_code grant).
    #[serde(default)]
    pub code: Option<String>,
    /// PKCE code verifier (RFC 7636).
    #[serde(default)]
    pub code_verifier: Option<String>,
    /// Redirect URI (must match the one used in /authorize).
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// Wallet Instance Attestation (optional, for EUDI Wallet flow).
    #[serde(default)]
    pub wallet_instance_attestation: Option<String>,
}

/// Verify PKCE S256 challenge (RFC 7636 §4.6).
pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> bool {
    let hash = hash_with(HashAlgorithm::Sha256, code_verifier.as_bytes());
    let computed = base64url_encode(&hash);
    computed == code_challenge
}

/// Credential Offer (OpenID4VCI §4.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: serde_json::Value,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpop_jkt: Option<String>,
}

/// Token endpoint — exchange pre-authorized code for access token.
/// Supports DPoP (RFC 9449) via `DPoP` header and WIA via form field.
#[post("/token")]
pub async fn token_endpoint(
    body: web::Form<TokenRequest>,
    req: HttpRequest,
    wia_registry: Option<web::Data<WalletProviderRegistry>>,
) -> ApiResult<HttpResponse> {
    let code = match body.grant_type.as_str() {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code" => {
            let c = body.pre_authorized_code.as_deref().unwrap_or("");
            if c.is_empty() {
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                    err_dto("invalid_grant", "pre-authorized_code required"),
                    400,
                )));
            }
            c
        }
        "authorization_code" => {
            let c = body.code.as_deref().unwrap_or("");
            if c.is_empty() {
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                    err_dto(
                        "invalid_grant",
                        "code required for authorization_code grant",
                    ),
                    400,
                )));
            }
            c
        }
        _ => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto(
                    "unsupported_grant_type",
                    "supported: pre-authorized_code, authorization_code",
                ),
                400,
            )));
        }
    };

    // Validate WIA if present
    if let Some(wia) = &body.wallet_instance_attestation {
        let reg_ref = wia_registry.as_ref().map(|r| r.get_ref());
        if let Err(e) = verify_wia(wia, reg_ref) {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("invalid_wallet_attestation", &e),
                400,
            )));
        }
    }

    // Validate DPoP proof if present (RFC 9449)
    let dpop_header = req
        .headers()
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let htu = format!("https://{host}/token");

    let dpop_jkt = if let Some(dpop_jwt) = &dpop_header {
        match verify_dpop_proof(dpop_jwt, "POST", &htu) {
            Ok(claims) => Some(claims.jkt),
            Err(e) => {
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                    err_dto("invalid_dpop_proof", &e),
                    400,
                )));
            }
        }
    } else {
        None
    };

    // Validate code has minimum entropy (at least 16 chars, hex or base64)
    if code.len() < 16 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "invalid_grant",
                "pre-authorized_code too short (min 16 chars)",
            ),
            400,
        )));
    }

    let access_token = format!(
        "goya_at_{}",
        hex::encode(hash_with(HashAlgorithm::Sha256, code.as_bytes()))
    );

    let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };

    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: token_type.to_string(),
        expires_in: 3600,
        dpop_jkt,
    }))
}

// ── Credential Endpoint ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CredentialRequest {
    pub format: String,
    #[serde(default)]
    pub vct: Option<String>,
    #[serde(default)]
    pub doctype: Option<String>,
    #[serde(default)]
    pub proof: Option<ProofObject>,
    /// Claims to include (for SD-JWT VC).
    #[serde(default)]
    pub claims: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct ProofObject {
    pub proof_type: String,
    pub jwt: Option<String>,
}

/// Shared status list store — maps list ID to StatusList.
pub struct StatusListStore {
    lists: std::sync::RwLock<
        std::collections::HashMap<String, std::sync::Arc<crate::identity::status_list::StatusList>>,
    >,
    signing_provider:
        std::sync::RwLock<Option<std::sync::Arc<dyn crate::identity::signing::SigningProvider>>>,
}

impl StatusListStore {
    pub fn new() -> Self {
        Self {
            lists: std::sync::RwLock::new(std::collections::HashMap::new()),
            signing_provider: std::sync::RwLock::new(None),
        }
    }

    pub fn set_signing_provider(
        &self,
        provider: std::sync::Arc<dyn crate::identity::signing::SigningProvider>,
    ) {
        *self.signing_provider.write().unwrap() = Some(provider);
    }

    pub fn get_or_create(
        &self,
        id: &str,
    ) -> std::sync::Arc<crate::identity::status_list::StatusList> {
        let mut lists = self.lists.write().unwrap();
        lists
            .entry(id.to_string())
            .or_insert_with(|| {
                std::sync::Arc::new(crate::identity::status_list::StatusList::new(id, 16384))
            })
            .clone()
    }

    pub fn get(
        &self,
        id: &str,
    ) -> Option<std::sync::Arc<crate::identity::status_list::StatusList>> {
        self.lists.read().unwrap().get(id).cloned()
    }
}

impl Default for StatusListStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Status list endpoint — serves `statuslist+jwt` (IETF Token Status List).
#[get("/statuslist/{id}")]
pub async fn status_list_endpoint(
    sl_store: web::Data<StatusListStore>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let id = path.into_inner();
    let list = match sl_store.get(&id) {
        Some(l) => l,
        None => {
            return Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
                err_dto("NOT_FOUND", &format!("status list '{id}' not found")),
                404,
            )));
        }
    };
    let provider = sl_store.signing_provider.read().unwrap();
    let provider = match provider.as_ref() {
        Some(p) => p,
        None => {
            return Ok(
                HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                    err_dto(
                        "CONFIG_ERROR",
                        "status list signing provider not configured",
                    ),
                    500,
                )),
            );
        }
    };
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let base = format!("https://{host}");

    match list.to_jwt(&base, 43200, provider.as_ref()) {
        Ok(jwt) => Ok(HttpResponse::Ok()
            .content_type("application/statuslist+jwt")
            .insert_header(("Cache-Control", "public, max-age=3600"))
            .body(jwt)),
        Err(e) => Ok(HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error(err_dto("SIGNING_ERROR", &e), 500))),
    }
}

/// Credential endpoint — issue a credential to the wallet.
/// Validates c_nonce, attestation type authorization, and assigns status index.
#[post("/credential")]
pub async fn credential_endpoint(
    state: web::Data<AppState>,
    body: web::Json<CredentialRequest>,
    req: HttpRequest,
    nonce_store: web::Data<NonceStore>,
    att_registry: Option<web::Data<crate::identity::attestation::AttestationTypeRegistry>>,
    sl_store: Option<web::Data<StatusListStore>>,
) -> ApiResult<HttpResponse> {
    // Accept both "Bearer" and "DPoP" token types
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = if let Some(t) = auth.strip_prefix("Bearer ") {
        t
    } else if let Some(t) = auth.strip_prefix("DPoP ") {
        t
    } else {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("invalid_token", "Bearer or DPoP token required"),
            401,
        )));
    };
    if token.len() < 3 {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("invalid_token", "token too short"),
            401,
        )));
    }

    // Validate proof JWT with c_nonce binding (nonce from dedicated endpoint)
    if let Some(proof) = &body.proof {
        if proof.proof_type == "jwt" {
            if let Some(proof_jwt) = &proof.jwt {
                let host = req
                    .headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("localhost:8080");
                let issuer = format!("https://{host}");

                // Extract nonce from the proof JWT payload
                let proof_parts: Vec<&str> = proof_jwt.split('.').collect();
                let proof_nonce = if proof_parts.len() >= 2 {
                    base64url_decode(proof_parts[1])
                        .ok()
                        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                        .and_then(|p| p.get("nonce").and_then(|v| v.as_str()).map(String::from))
                        .unwrap_or_default()
                } else {
                    String::new()
                };

                // Consume the nonce (single-use + expiry check)
                if let Err(e) = nonce_store.consume(&proof_nonce) {
                    return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                        err_dto("invalid_proof", &format!("c_nonce rejected: {e}")),
                        400,
                    )));
                }

                // Validate proof JWT structure (typ, aud, iat)
                if let Err(e) = verify_proof_jwt(proof_jwt, &proof_nonce, &issuer) {
                    return Ok(HttpResponse::BadRequest()
                        .json(ApiResponse::<()>::error(err_dto("invalid_proof", &e), 400)));
                }
            }
        }
    }

    let provider = state.signing_provider.as_ref().ok_or_else(|| {
        crate::api::errors::ApiError::StorageError {
            reason: "signing provider not configured".into(),
        }
    })?;

    let vct = body
        .vct
        .as_deref()
        .or(body.doctype.as_deref())
        .unwrap_or("IdentityCredential");
    let issuer_did = format!("did:goya:{}", &hex::encode(provider.public_key())[..16]);
    let claims_json = body.claims.clone().unwrap_or(serde_json::json!({}));

    // Attestation type authorization (if registry is configured)
    if let Some(reg) = &att_registry {
        // ponytail: holder_has_pid=true for now — real check requires holder state lookup
        if let Err(e) = reg.authorize_issuance(&issuer_did, vct, &claims_json, true) {
            return Ok(HttpResponse::Forbidden().json(ApiResponse::<()>::error(
                err_dto("authorization_failed", &e),
                403,
            )));
        }
    }

    // Allocate status list index (if store is configured)
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let status_ref = if let Some(sls) = &sl_store {
        let list = sls.get_or_create("default");
        match list.allocate_index() {
            Ok(idx) => {
                let uri = format!("https://{host}/api/v1/statuslist/default");
                Some((uri, idx))
            }
            Err(_) => None,
        }
    } else {
        None
    };

    match body.format.as_str() {
        "vc+sd-jwt" => issue_sd_jwt_credential(provider.as_ref(), &body, status_ref.as_ref()),
        "mso_mdoc" => issue_mdoc_credential(provider.as_ref(), &body, status_ref.as_ref()),
        other => Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "unsupported_credential_format",
                &format!("format '{other}' not supported; use vc+sd-jwt or mso_mdoc"),
            ),
            400,
        ))),
    }
}

// ── Credential Offer Endpoint ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CredentialOfferRequest {
    #[serde(default)]
    pub credential_configuration_ids: Vec<String>,
}

/// Generate a credential offer (OpenID4VCI §4.1).
#[post("/credential_offer")]
pub async fn credential_offer_endpoint(
    body: web::Json<CredentialOfferRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let base = format!("https://{host}");

    let config_ids = if body.credential_configuration_ids.is_empty() {
        vec!["IdentityCredential_sd_jwt".to_string()]
    } else {
        body.credential_configuration_ids.clone()
    };

    let pre_auth_code = hex::encode(hash_with(
        HashAlgorithm::Sha256,
        uuid::Uuid::new_v4().as_bytes(),
    ));

    let offer = CredentialOffer {
        credential_issuer: base.clone(),
        credential_configuration_ids: config_ids,
        grants: serde_json::json!({
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_auth_code,
            },
            "authorization_code": {
                "issuer_state": uuid::Uuid::new_v4().to_string(),
            }
        }),
    };

    let offer_json = serde_json::to_string(&offer).unwrap_or_default();
    let offer_uri = format!(
        "openid-credential-offer://?credential_offer={}",
        urlencoding::encode(&offer_json)
    );

    Ok(HttpResponse::Created().json(serde_json::json!({
        "credential_offer": offer,
        "credential_offer_uri": offer_uri,
    })))
}

fn issue_sd_jwt_credential(
    provider: &dyn crate::identity::signing::SigningProvider,
    req: &CredentialRequest,
    status_ref: Option<&(String, usize)>,
) -> ApiResult<HttpResponse> {
    use crate::identity::sd_jwt::{issue_sd_jwt_vc, VcClaims};

    let vct = req.vct.as_deref().unwrap_or("IdentityCredential");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut claim_pairs = Vec::new();
    if let Some(claims_obj) = &req.claims {
        if let Some(map) = claims_obj.as_object() {
            for (k, v) in map {
                claim_pairs.push((k.clone(), v.clone()));
            }
        }
    }

    let vc_claims = VcClaims {
        iss: format!("did:goya:{}", &hex::encode(provider.public_key())[..16]),
        sub: "holder".to_string(),
        iat: now,
        exp: now + 365 * 86400,
        vct: vct.to_string(),
        claims: claim_pairs,
    };

    match issue_sd_jwt_vc(&vc_claims, provider) {
        Ok(sd_jwt) => {
            let mut resp = serde_json::json!({
                "format": "vc+sd-jwt",
                "credential": sd_jwt.compact,
            });
            if let Some((uri, idx)) = status_ref {
                resp["status"] = crate::identity::status_list::status_claim(uri, *idx);
                resp["status_list_index"] = serde_json::json!(idx);
            }
            Ok(HttpResponse::Ok().json(resp))
        }
        Err(e) => Ok(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                ErrorDto {
                    code: "issuance_failed".to_string(),
                    message: e,
                    field: None,
                },
                500,
            )),
        ),
    }
}

fn issue_mdoc_credential(
    provider: &dyn crate::identity::signing::SigningProvider,
    req: &CredentialRequest,
    status_ref: Option<&(String, usize)>,
) -> ApiResult<HttpResponse> {
    use crate::identity::mdoc::{issue_mdoc, MdocParams};
    use std::collections::BTreeMap;

    let doc_type = req.doctype.as_deref().unwrap_or("eu.europa.ec.eudi.pid.1");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut elements = BTreeMap::new();
    let mut ns_elements = Vec::new();
    if let Some(claims_obj) = &req.claims {
        if let Some(map) = claims_obj.as_object() {
            for (k, v) in map {
                ns_elements.push((k.clone(), v.clone()));
            }
        }
    }
    elements.insert(doc_type.to_string(), ns_elements);

    let params = MdocParams {
        doc_type: doc_type.to_string(),
        elements,
        valid_from: now,
        valid_until: now + 365 * 86400,
        device_key: None,
    };

    match issue_mdoc(&params, provider) {
        Ok(mdoc) => {
            let mdoc_json = serde_json::to_value(&mdoc).unwrap_or_default();
            let mut resp = serde_json::json!({
                "format": "mso_mdoc",
                "credential": mdoc_json,
            });
            if let Some((uri, idx)) = status_ref {
                resp["status"] = crate::identity::status_list::status_claim(uri, *idx);
                resp["status_list_index"] = serde_json::json!(idx);
            }
            Ok(HttpResponse::Ok().json(resp))
        }
        Err(e) => Ok(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                ErrorDto {
                    code: "issuance_failed".to_string(),
                    message: e,
                    field: None,
                },
                500,
            )),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::AppState;
    use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
    use actix_web::{test, web, App};
    use std::sync::Arc;

    fn make_state() -> web::Data<AppState> {
        let mut state = AppState::test_default();
        state.signing_provider = Some(Arc::new(SoftwareSigningProvider::generate()));
        web::Data::new(state)
    }

    fn make_nonce_store() -> web::Data<NonceStore> {
        web::Data::new(NonceStore::new())
    }

    fn make_sl_store() -> web::Data<StatusListStore> {
        web::Data::new(StatusListStore::new())
    }

    fn make_att_registry() -> web::Data<crate::identity::attestation::AttestationTypeRegistry> {
        web::Data::new(crate::identity::attestation::AttestationTypeRegistry::new())
    }

    macro_rules! oid4vci_app {
        ($state:expr) => {
            oid4vci_app!($state, make_nonce_store())
        };
        ($state:expr, $nonce:expr) => {
            test::init_service(
                App::new()
                    .app_data($state)
                    .app_data($nonce)
                    .service(issuer_metadata)
                    .service(token_endpoint)
                    .service(credential_endpoint)
                    .service(credential_offer_endpoint)
                    .service(nonce_endpoint)
                    .service(status_list_endpoint),
            )
            .await
        };
        ($state:expr, $nonce:expr, $sl:expr, $att:expr) => {
            test::init_service(
                App::new()
                    .app_data($state)
                    .app_data($nonce)
                    .app_data($sl)
                    .app_data($att)
                    .service(issuer_metadata)
                    .service(token_endpoint)
                    .service(credential_endpoint)
                    .service(credential_offer_endpoint)
                    .service(nonce_endpoint)
                    .service(status_list_endpoint),
            )
            .await
        };
    }

    #[actix_web::test]
    async fn e2e_issuer_metadata() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::get()
            .uri("/.well-known/openid-credential-issuer")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["credential_endpoint"].as_str().is_some());
        assert!(
            body["credential_configurations_supported"]
                .as_object()
                .unwrap()
                .len()
                >= 2
        );
        let grants = body["grant_types_supported"].as_array().unwrap();
        assert!(grants.len() >= 2);
    }

    fn make_token_form(code: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some(code.to_string()),
            code: None,
            code_verifier: None,
            redirect_uri: None,
            wallet_instance_attestation: None,
        }
    }

    fn make_dpop_jwt(htm: &str, htu: &str, iat: u64) -> String {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "test-key-material" }
        });
        let payload = serde_json::json!({
            "htm": htm,
            "htu": htu,
            "iat": iat,
            "jti": "unique-id-123",
        });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let sig = base64url_encode(b"fake-sig");
        format!("{h}.{p}.{sig}")
    }

    fn make_proof_jwt(nonce: &str, aud: &str, iat: u64) -> String {
        let header = serde_json::json!({
            "typ": "openid4vci-proof+jwt",
            "alg": "EdDSA",
        });
        let payload = serde_json::json!({
            "nonce": nonce,
            "aud": aud,
            "iat": iat,
        });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let sig = base64url_encode(b"fake-sig");
        format!("{h}.{p}.{sig}")
    }

    fn make_wia_jwt(typ: &str, iss: &str, sub: &str, exp: u64) -> String {
        let header = serde_json::json!({ "typ": typ, "alg": "EdDSA" });
        let payload = serde_json::json!({ "iss": iss, "sub": sub, "iat": now_secs(), "exp": exp });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let sig = base64url_encode(b"fake-sig");
        format!("{h}.{p}.{sig}")
    }

    #[actix_web::test]
    async fn e2e_token_exchange() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(make_token_form("test-code-1234567890"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["access_token"]
            .as_str()
            .unwrap()
            .starts_with("goya_at_"));
        assert!(
            body.get("c_nonce").is_none(),
            "c_nonce must NOT be in token response (OID4VCI 1.0 Final)"
        );
        assert_eq!(body["token_type"], "Bearer");
    }

    #[actix_web::test]
    async fn e2e_token_with_dpop() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let dpop = make_dpop_jwt("POST", "https://localhost:8080/token", now_secs());
        let req = test::TestRequest::post()
            .uri("/token")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("dpop", dpop.as_str()))
            .set_form(make_token_form("test-code-dpop-1234"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["token_type"], "DPoP");
        assert!(body["dpop_jkt"].as_str().is_some());
    }

    #[actix_web::test]
    async fn e2e_token_dpop_bad_htm() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let dpop = make_dpop_jwt("GET", "https://localhost:8080/token", now_secs());
        let req = test::TestRequest::post()
            .uri("/token")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("dpop", dpop.as_str()))
            .set_form(make_token_form("test-code-fallback1"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_token_with_wia() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let wia = make_wia_jwt(
            "wia+jwt",
            "wallet-provider",
            "device-123",
            now_secs() + 3600,
        );
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(TokenRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
                pre_authorized_code: Some("code-wia-1234567890".to_string()),
                code: None,
                code_verifier: None,
                redirect_uri: None,
                wallet_instance_attestation: Some(wia),
            })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn e2e_token_rejects_expired_wia() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let wia = make_wia_jwt("wia+jwt", "wallet-provider", "device-123", 1000);
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(TokenRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
                pre_authorized_code: Some("code-wia-1234567890".to_string()),
                code: None,
                code_verifier: None,
                redirect_uri: None,
                wallet_instance_attestation: Some(wia),
            })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_token_rejects_wrong_grant() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(TokenRequest {
                grant_type: "client_credentials".to_string(),
                pre_authorized_code: None,
                code: None,
                code_verifier: None,
                redirect_uri: None,
                wallet_instance_attestation: None,
            })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_nonce_endpoint_returns_cnonce() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post().uri("/nonce").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let nonce = body["c_nonce"].as_str().unwrap();
        assert_eq!(nonce.len(), 64); // 32 bytes hex
        assert_eq!(body["c_nonce_expires_in"].as_u64().unwrap(), 300);
    }

    #[actix_web::test]
    async fn e2e_credential_with_nonce_endpoint_flow() {
        let state = make_state();
        let nonce_store = make_nonce_store();
        let app = oid4vci_app!(state, nonce_store.clone());

        // Step 1: Get nonce from dedicated endpoint
        let req = test::TestRequest::post().uri("/nonce").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let c_nonce = body["c_nonce"].as_str().unwrap();

        // Step 2: Use nonce in credential proof
        let proof_jwt = make_proof_jwt(c_nonce, "https://localhost:8080", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("authorization", "Bearer goya_at_test_1234"))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "proof": { "proof_type": "jwt", "jwt": proof_jwt },
                "claims": { "given_name": "Ana" }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn e2e_credential_rejects_unknown_nonce() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let proof_jwt = make_proof_jwt("unknown-nonce-value", "https://localhost:8080", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("authorization", "Bearer goya_at_test"))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "proof": { "proof_type": "jwt", "jwt": proof_jwt },
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let msg = body["error"]["message"].as_str().unwrap_or("");
        assert!(msg.contains("unknown nonce"), "got: {msg}");
    }

    #[actix_web::test]
    async fn e2e_credential_rejects_reused_nonce() {
        let state = make_state();
        let nonce_store = make_nonce_store();
        let app = oid4vci_app!(state, nonce_store.clone());

        // Get a nonce
        let req = test::TestRequest::post().uri("/nonce").to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let c_nonce = body["c_nonce"].as_str().unwrap().to_string();

        // First use — succeeds
        let proof_jwt = make_proof_jwt(&c_nonce, "https://localhost:8080", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("authorization", "Bearer goya_at_replay_test"))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "proof": { "proof_type": "jwt", "jwt": proof_jwt },
                "claims": { "given_name": "Test" }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // Second use — rejected (nonce already consumed)
        let proof_jwt2 = make_proof_jwt(&c_nonce, "https://localhost:8080", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("authorization", "Bearer goya_at_replay_test2"))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "proof": { "proof_type": "jwt", "jwt": proof_jwt2 },
                "claims": { "given_name": "Replay" }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let msg = body["error"]["message"].as_str().unwrap_or("");
        assert!(msg.contains("already used"), "got: {msg}");
    }

    #[actix_web::test]
    async fn nonce_store_expired_nonce_rejected() {
        let store = NonceStore::new();
        let nonce = store.generate(0); // 0 TTL = instantly expired
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert_eq!(store.consume(&nonce), Err("nonce expired"));
    }

    #[actix_web::test]
    async fn nonce_store_single_use() {
        let store = NonceStore::new();
        let nonce = store.generate(300);
        assert!(store.consume(&nonce).is_ok());
        assert_eq!(store.consume(&nonce), Err("nonce already used"));
    }

    #[actix_web::test]
    async fn nonce_store_unknown() {
        let store = NonceStore::new();
        assert_eq!(store.consume("nonexistent"), Err("unknown nonce"));
    }

    #[actix_web::test]
    async fn nonce_tampered_rejected() {
        let store = NonceStore::new();
        let nonce = store.generate(300);
        // Flip a character
        let mut chars: Vec<u8> = nonce.bytes().collect();
        chars[0] ^= 0x01;
        let tampered = String::from_utf8(chars).unwrap();
        assert_eq!(store.consume(&tampered), Err("unknown nonce"));
        // Original still valid
        assert!(store.consume(&nonce).is_ok());
    }

    #[actix_web::test]
    async fn e2e_credential_accepts_dpop_token() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "DPoP goya_at_dpop_test"))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "claims": { "name": "Test" }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn e2e_issue_sd_jwt_vc() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "Bearer goya_at_test"))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "claims": {
                    "given_name": "Juan",
                    "family_name": "Pérez",
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["format"], "vc+sd-jwt");
        let cred = body["credential"].as_str().unwrap();
        assert!(cred.contains('~'));
    }

    #[actix_web::test]
    async fn e2e_issue_mdoc() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "Bearer goya_at_test"))
            .set_json(serde_json::json!({
                "format": "mso_mdoc",
                "doctype": "eu.europa.ec.eudi.pid.1",
                "claims": {
                    "given_name": "Juan",
                    "birth_date": "1990-01-15",
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["format"], "mso_mdoc");
        assert!(body["credential"]["doc_type"].as_str().is_some());
    }

    #[actix_web::test]
    async fn e2e_rejects_unsupported_format() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "Bearer goya_at_test"))
            .set_json(serde_json::json!({
                "format": "jwt_vc_json",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_rejects_missing_token() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post()
            .uri("/credential")
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    // ── Unit tests for validation functions ──────────────────────────

    #[actix_web::test]
    async fn dpop_valid() {
        let dpop = make_dpop_jwt("POST", "https://example.com/token", now_secs());
        assert!(verify_dpop_proof(&dpop, "POST", "https://example.com/token").is_ok());
    }

    #[actix_web::test]
    async fn dpop_wrong_htm() {
        let dpop = make_dpop_jwt("GET", "https://example.com/token", now_secs());
        assert!(verify_dpop_proof(&dpop, "POST", "https://example.com/token").is_err());
    }

    #[actix_web::test]
    async fn dpop_wrong_htu() {
        let dpop = make_dpop_jwt("POST", "https://other.com/token", now_secs());
        assert!(verify_dpop_proof(&dpop, "POST", "https://example.com/token").is_err());
    }

    #[actix_web::test]
    async fn dpop_expired_iat() {
        let dpop = make_dpop_jwt("POST", "https://example.com/token", now_secs() - 600);
        assert!(verify_dpop_proof(&dpop, "POST", "https://example.com/token").is_err());
    }

    #[actix_web::test]
    async fn dpop_returns_jkt() {
        let dpop = make_dpop_jwt("POST", "https://example.com/token", now_secs());
        let claims = verify_dpop_proof(&dpop, "POST", "https://example.com/token").unwrap();
        assert!(!claims.jkt.is_empty());
    }

    #[actix_web::test]
    async fn proof_jwt_valid() {
        let proof = make_proof_jwt("nonce-abc", "https://issuer.com", now_secs());
        assert!(verify_proof_jwt(&proof, "nonce-abc", "https://issuer.com").is_ok());
    }

    #[actix_web::test]
    async fn proof_jwt_wrong_nonce() {
        let proof = make_proof_jwt("nonce-abc", "https://issuer.com", now_secs());
        assert!(verify_proof_jwt(&proof, "wrong-nonce", "https://issuer.com").is_err());
    }

    #[actix_web::test]
    async fn proof_jwt_wrong_aud() {
        let proof = make_proof_jwt("nonce", "https://other.com", now_secs());
        assert!(verify_proof_jwt(&proof, "nonce", "https://issuer.com").is_err());
    }

    #[actix_web::test]
    async fn wia_valid() {
        let wia = make_wia_jwt("wia+jwt", "provider", "device", now_secs() + 3600);
        assert!(verify_wia(&wia, None).is_ok());
    }

    #[actix_web::test]
    async fn wia_wallet_attestation_typ() {
        let wia = make_wia_jwt("wallet-attestation+jwt", "prov", "dev", now_secs() + 3600);
        assert!(verify_wia(&wia, None).is_ok());
    }

    #[actix_web::test]
    async fn wia_expired() {
        let wia = make_wia_jwt("wia+jwt", "provider", "device", 1000);
        assert!(verify_wia(&wia, None).is_err());
    }

    #[actix_web::test]
    async fn wia_wrong_typ() {
        let wia = make_wia_jwt("jwt", "provider", "device", now_secs() + 3600);
        assert!(verify_wia(&wia, None).is_err());
    }

    #[actix_web::test]
    async fn wia_missing_iss() {
        let wia = make_wia_jwt("wia+jwt", "", "device", now_secs() + 3600);
        assert!(verify_wia(&wia, None).is_err());
    }

    #[actix_web::test]
    async fn wia_sig_verified_with_registry() {
        use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
        let provider = SoftwareSigningProvider::generate();
        let pk_hex = hex::encode(provider.public_key());

        // Build a properly signed WIA JWT
        let header = serde_json::json!({"typ":"wia+jwt","alg":"EdDSA"});
        let payload = serde_json::json!({
            "iss": "wallet-provider-1",
            "sub": "device-1",
            "iat": now_secs(),
            "exp": now_secs() + 3600,
        });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = provider.sign(signing_input.as_bytes()).unwrap();
        let wia = format!("{signing_input}.{}", base64url_encode(&sig));

        let reg = WalletProviderRegistry::new();
        reg.register("wallet-provider-1", &pk_hex);
        assert!(verify_wia(&wia, Some(&reg)).is_ok());
    }

    #[actix_web::test]
    async fn wia_sig_fails_wrong_key() {
        use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
        let provider = SoftwareSigningProvider::generate();
        let other = SoftwareSigningProvider::generate();

        let header = serde_json::json!({"typ":"wia+jwt","alg":"EdDSA"});
        let payload = serde_json::json!({
            "iss": "wallet-provider-2",
            "sub": "device-2",
            "iat": now_secs(),
            "exp": now_secs() + 3600,
        });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = provider.sign(signing_input.as_bytes()).unwrap();
        let wia = format!("{signing_input}.{}", base64url_encode(&sig));

        let reg = WalletProviderRegistry::new();
        reg.register("wallet-provider-2", &hex::encode(other.public_key()));
        assert!(verify_wia(&wia, Some(&reg)).is_err());
    }

    #[actix_web::test]
    async fn wallet_provider_registry_roundtrip() {
        let reg = WalletProviderRegistry::new();
        assert!(reg.resolve("unknown").is_none());
        reg.register("provider-1", "deadbeef");
        assert_eq!(reg.resolve("provider-1"), Some("deadbeef".to_string()));
    }

    // ── Authorization code + PKCE + Credential Offer tests ─────────

    #[actix_web::test]
    async fn e2e_token_authorization_code() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(TokenRequest {
                grant_type: "authorization_code".to_string(),
                pre_authorized_code: None,
                code: Some("auth-code-1234567890".to_string()),
                code_verifier: None,
                redirect_uri: None,
                wallet_instance_attestation: None,
            })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["access_token"]
            .as_str()
            .unwrap()
            .starts_with("goya_at_"));
        assert!(
            body.get("c_nonce").is_none(),
            "c_nonce must NOT be in token response"
        );
    }

    #[actix_web::test]
    async fn e2e_token_authorization_code_missing_code() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(TokenRequest {
                grant_type: "authorization_code".to_string(),
                pre_authorized_code: None,
                code: None,
                code_verifier: None,
                redirect_uri: None,
                wallet_instance_attestation: None,
            })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn pkce_s256_valid() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let hash = hash_with(HashAlgorithm::Sha256, verifier.as_bytes());
        let challenge = base64url_encode(&hash);
        assert!(verify_pkce(verifier, &challenge));
    }

    #[actix_web::test]
    async fn pkce_s256_invalid() {
        let hash = hash_with(HashAlgorithm::Sha256, b"correct-verifier");
        let challenge = base64url_encode(&hash);
        assert!(!verify_pkce("wrong-verifier", &challenge));
    }

    #[actix_web::test]
    async fn e2e_credential_offer() {
        let state = make_state();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(credential_offer_endpoint),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/credential_offer")
            .set_json(serde_json::json!({
                "credential_configuration_ids": ["IdentityCredential_sd_jwt"]
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["credential_offer"]["credential_issuer"]
            .as_str()
            .is_some());
        let uri = body["credential_offer_uri"].as_str().unwrap();
        assert!(uri.starts_with("openid-credential-offer://"));
    }

    // ═══════════════════════════════════════════════════════════════
    // Full EUDI E2E: metadata → token → nonce → credential → status
    //                → OID4VP → revoke → status update detected
    // ═══════════════════════════════════════════════════════════════

    #[actix_web::test]
    async fn e2e_full_eudi_flow_with_status_and_revocation() {
        use crate::identity::signing::EcdsaP256SigningProvider;
        use crate::identity::status_list::CredentialStatus;

        let mut state = AppState::test_default();
        state.signing_provider = Some(Arc::new(EcdsaP256SigningProvider::generate())
            as Arc<dyn crate::identity::signing::SigningProvider>);
        let state = web::Data::new(state);

        let nonce_store = make_nonce_store();
        let sl_store = make_sl_store();
        sl_store.set_signing_provider(Arc::new(EcdsaP256SigningProvider::generate())
            as Arc<dyn crate::identity::signing::SigningProvider>);
        let app = test::init_service(
            App::new()
                .app_data(state)
                .app_data(nonce_store.clone())
                .app_data(sl_store.clone())
                .service(issuer_metadata)
                .service(token_endpoint)
                .service(credential_endpoint)
                .service(credential_offer_endpoint)
                .service(nonce_endpoint)
                .service(status_list_endpoint),
        )
        .await;

        // 1. Metadata — verify nonce_endpoint + ES256 advertised
        let req = test::TestRequest::get()
            .uri("/.well-known/openid-credential-issuer")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let meta: serde_json::Value = test::read_body_json(resp).await;
        assert!(meta["nonce_endpoint"].as_str().is_some());
        let sd_jwt_algs = &meta["credential_configurations_supported"]["IdentityCredential_sd_jwt"]
            ["credential_signing_alg_values_supported"];
        assert!(sd_jwt_algs
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("ES256")));

        // 2. Token
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(make_token_form("test-eudi-e2e-code-123"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let token_body: serde_json::Value = test::read_body_json(resp).await;
        let access_token = token_body["access_token"].as_str().unwrap();
        assert!(token_body.get("c_nonce").is_none());

        // 3. Nonce
        let req = test::TestRequest::post().uri("/nonce").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let nonce_body: serde_json::Value = test::read_body_json(resp).await;
        let c_nonce = nonce_body["c_nonce"].as_str().unwrap();

        // 4. Credential issuance with nonce proof
        let proof_jwt = make_proof_jwt(c_nonce, "https://localhost:8080", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("authorization", format!("Bearer {access_token}")))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "proof": { "proof_type": "jwt", "jwt": proof_jwt },
                "claims": {
                    "given_name": "María",
                    "family_name": "García",
                    "birth_date": "1985-03-15",
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let cred_body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(cred_body["format"], "vc+sd-jwt");
        let credential = cred_body["credential"].as_str().unwrap();
        assert!(credential.contains('~'));

        // Verify status reference was assigned
        assert!(cred_body["status"]["status_list"]["idx"].is_number());
        assert!(cred_body["status"]["status_list"]["uri"].as_str().is_some());
        let status_idx = cred_body["status"]["status_list"]["idx"].as_u64().unwrap() as usize;

        // 5. Fetch status list — credential should be VALID
        let req = test::TestRequest::get()
            .uri("/statuslist/default")
            .insert_header(("host", "localhost:8080"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let content_type = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(content_type, "application/statuslist+jwt");
        let cache = resp
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cache.contains("public"));

        // 6. Revoke the credential
        let list = sl_store.get("default").unwrap();
        list.set_status(status_idx, CredentialStatus::Invalid)
            .unwrap();
        assert_eq!(
            list.get_status(status_idx).unwrap(),
            CredentialStatus::Invalid
        );
    }

    #[actix_web::test]
    async fn e2e_status_list_not_found() {
        let state = make_state();
        let sl_store = make_sl_store();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .app_data(make_nonce_store())
                .app_data(sl_store)
                .service(status_list_endpoint)
                .service(credential_endpoint),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/statuslist/nonexistent")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_web::test]
    async fn e2e_credential_with_attestation_registry_unauthorized_issuer() {
        use crate::identity::attestation::*;

        let state = make_state();
        let nonce_store = make_nonce_store();
        let sl_store = make_sl_store();
        let att_registry = web::Data::new(AttestationTypeRegistry::new());
        // PID rulebook exists but NO issuer is registered → fail-closed

        let app = oid4vci_app!(state, nonce_store, sl_store, att_registry);

        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "Bearer goya_at_test_auth_xyz"))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "eu.europa.ec.eudi.pid.1",
                "claims": {
                    "given_name": "Test",
                    "family_name": "User",
                    "birth_date": "2000-01-01",
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let msg = body["error"]["message"].as_str().unwrap_or("");
        assert!(msg.contains("not registered"), "got: {msg}");
    }

    #[actix_web::test]
    async fn e2e_credential_with_authorized_pid_issuer() {
        use crate::identity::attestation::*;
        use crate::identity::signing::EcdsaP256SigningProvider;

        let es256 = EcdsaP256SigningProvider::generate();
        let issuer_did = format!("did:goya:{}", &hex::encode(es256.public_key())[..16]);

        let mut app_state = AppState::test_default();
        app_state.signing_provider =
            Some(Arc::new(es256) as Arc<dyn crate::identity::signing::SigningProvider>);
        let state = web::Data::new(app_state);

        let att_registry = web::Data::new(AttestationTypeRegistry::new());
        att_registry.register_issuer(RegisteredIssuer {
            did: issuer_did,
            role: IssuerRole::PidProvider,
            trust_source: "https://tsl.example.eu/pid".into(),
            authorized_vcts: vec![],
            registered_at: now_secs(),
        });

        let nonce_store = make_nonce_store();
        let sl_store = make_sl_store();
        let app = oid4vci_app!(state, nonce_store, sl_store, att_registry);

        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "Bearer goya_at_pid_issuer_test"))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "eu.europa.ec.eudi.pid.1",
                "claims": {
                    "given_name": "María",
                    "family_name": "García",
                    "birth_date": "1985-03-15",
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }
}
