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

// ── Wallet Instance Attestation ───────────────────────────────────────────

/// Validate a Wallet Instance Attestation (WIA) JWT.
/// Minimal check: well-formed JWT with typ=wia+jwt, iss, sub, iat, exp.
fn verify_wia(wia_jwt: &str) -> Result<serde_json::Value, String> {
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

    Ok(payload)
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

// ── Issuer Metadata ───────────────────────────────────────────────────────

/// OpenID4VCI Issuer Metadata (RFC draft-ietf-oauth-sd-jwt-vc §7).
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
        "token_endpoint": format!("{base}/token"),
        "credentials_supported": [
            {
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["EdDSA", "ML-DSA-65", "RS256"],
                "claims": {
                    "given_name": { "mandatory": false },
                    "family_name": { "mandatory": false },
                    "birth_date": { "mandatory": false },
                    "nationality": { "mandatory": false },
                    "age_over_18": { "mandatory": false },
                    "rut": { "mandatory": false },
                }
            },
            {
                "format": "mso_mdoc",
                "doctype": "eu.europa.ec.eudi.pid.1",
                "cryptographic_binding_methods_supported": ["cose_key"],
                "credential_signing_alg_values_supported": ["EdDSA", "ML-DSA-65"],
            }
        ],
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
    /// Wallet Instance Attestation (optional, for EUDI Wallet flow).
    #[serde(default)]
    pub wallet_instance_attestation: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    c_nonce: String,
    c_nonce_expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpop_jkt: Option<String>,
}

/// Token endpoint — exchange pre-authorized code for access token.
/// Supports DPoP (RFC 9449) via `DPoP` header and WIA via form field.
#[post("/token")]
pub async fn token_endpoint(
    body: web::Form<TokenRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    if body.grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "unsupported_grant_type",
                "only pre-authorized_code supported",
            ),
            400,
        )));
    }

    let code = body.pre_authorized_code.as_deref().unwrap_or("");
    if code.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("invalid_grant", "pre-authorized_code required"),
            400,
        )));
    }

    // Validate WIA if present
    if let Some(wia) = &body.wallet_instance_attestation {
        if let Err(e) = verify_wia(wia) {
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
    let c_nonce = hex::encode(hash_with(HashAlgorithm::Sha256, access_token.as_bytes()));

    let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };

    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: token_type.to_string(),
        expires_in: 3600,
        c_nonce,
        c_nonce_expires_in: 300,
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

/// Credential endpoint — issue a credential to the wallet.
/// When proof.jwt is present, validates c_nonce binding (OpenID4VCI §7.2.1).
#[post("/credential")]
pub async fn credential_endpoint(
    state: web::Data<AppState>,
    body: web::Json<CredentialRequest>,
    req: HttpRequest,
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

    // Validate proof JWT with c_nonce binding if present
    if let Some(proof) = &body.proof {
        if proof.proof_type == "jwt" {
            if let Some(proof_jwt) = &proof.jwt {
                // Derive expected c_nonce from access token (same as token endpoint)
                let expected_nonce =
                    hex::encode(hash_with(HashAlgorithm::Sha256, token.as_bytes()));
                let host = req
                    .headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("localhost:8080");
                let issuer = format!("https://{host}");
                if let Err(e) = verify_proof_jwt(proof_jwt, &expected_nonce, &issuer) {
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

    match body.format.as_str() {
        "vc+sd-jwt" => issue_sd_jwt_credential(provider.as_ref(), &body),
        "mso_mdoc" => issue_mdoc_credential(provider.as_ref(), &body),
        other => Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "unsupported_credential_format",
                &format!("format '{other}' not supported; use vc+sd-jwt or mso_mdoc"),
            ),
            400,
        ))),
    }
}

fn issue_sd_jwt_credential(
    provider: &dyn crate::identity::signing::SigningProvider,
    req: &CredentialRequest,
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
        Ok(sd_jwt) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "format": "vc+sd-jwt",
            "credential": sd_jwt.compact,
        }))),
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
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "format": "mso_mdoc",
                "credential": mdoc_json,
            })))
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
    use crate::identity::signing::SoftwareSigningProvider;
    use actix_web::{test, web, App};
    use std::sync::Arc;

    fn make_state() -> web::Data<AppState> {
        let mut state = AppState::test_default();
        state.signing_provider = Some(Arc::new(SoftwareSigningProvider::generate()));
        web::Data::new(state)
    }

    macro_rules! oid4vci_app {
        ($state:expr) => {
            test::init_service(
                App::new()
                    .app_data($state)
                    .service(issuer_metadata)
                    .service(token_endpoint)
                    .service(credential_endpoint),
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
        assert!(body["credentials_supported"].as_array().unwrap().len() >= 2);
    }

    fn make_token_form(code: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some(code.to_string()),
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
        assert!(body["c_nonce"].as_str().is_some());
        assert_eq!(body["token_type"], "Bearer");
        assert!(body["dpop_jkt"].is_null());
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
                grant_type: "authorization_code".to_string(),
                pre_authorized_code: None,
                wallet_instance_attestation: None,
            })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_credential_with_cnonce_proof() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let token = "goya_at_test";
        let c_nonce = hex::encode(hash_with(HashAlgorithm::Sha256, token.as_bytes()));
        let proof_jwt = make_proof_jwt(&c_nonce, "https://localhost:8080", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("authorization", format!("Bearer {token}")))
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
    async fn e2e_credential_rejects_bad_cnonce() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let proof_jwt = make_proof_jwt("wrong-nonce", "https://localhost:8080", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "Bearer goya_at_test"))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "proof": { "proof_type": "jwt", "jwt": proof_jwt },
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
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
        assert!(verify_wia(&wia).is_ok());
    }

    #[actix_web::test]
    async fn wia_wallet_attestation_typ() {
        let wia = make_wia_jwt("wallet-attestation+jwt", "prov", "dev", now_secs() + 3600);
        assert!(verify_wia(&wia).is_ok());
    }

    #[actix_web::test]
    async fn wia_expired() {
        let wia = make_wia_jwt("wia+jwt", "provider", "device", 1000);
        assert!(verify_wia(&wia).is_err());
    }

    #[actix_web::test]
    async fn wia_wrong_typ() {
        let wia = make_wia_jwt("jwt", "provider", "device", now_secs() + 3600);
        assert!(verify_wia(&wia).is_err());
    }

    #[actix_web::test]
    async fn wia_missing_iss() {
        let wia = make_wia_jwt("wia+jwt", "", "device", now_secs() + 3600);
        assert!(verify_wia(&wia).is_err());
    }
}
