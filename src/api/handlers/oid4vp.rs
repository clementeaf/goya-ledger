//! OpenID4VP — OpenID for Verifiable Presentations (1.0).
//!
//! Verifier-side endpoints for requesting and receiving credential presentations:
//! - `POST /api/v1/oid4vp/request` — create presentation request
//! - `GET  /api/v1/oid4vp/request/{id}` — fetch request by reference
//! - `POST /api/v1/oid4vp/response` — submit vp_token

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use actix_web::{get, post, web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s)
        .map_err(|e| e.to_string())
}

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

// ── Types ─────────────────────────────────────────────────────────────────

// ── DCQL — Digital Credentials Query Language (OpenID4VP 1.0 Final) ──────

/// DCQL query — the sole query mechanism in OpenID4VP 1.0 Final.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlQuery {
    pub credentials: Vec<CredentialQuery>,
}

/// A single credential requirement in DCQL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialQuery {
    pub id: String,
    pub format: String,
    #[serde(default)]
    pub claims: Vec<ClaimQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

/// A claim requirement within a DCQL credential query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimQuery {
    pub path: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<serde_json::Value>>,
}

/// Match disclosed claims against a DCQL query.
fn match_dcql_query(
    query: &DcqlQuery,
    format: &str,
    disclosed_claims: &serde_json::Value,
) -> Result<(), String> {
    for cq in &query.credentials {
        if cq.format != format {
            return Err(format!(
                "DCQL format mismatch for '{}': expected {}, got {format}",
                cq.id, cq.format
            ));
        }
        for claim in &cq.claims {
            let found = claim.path.iter().any(|p| {
                let key = p.strip_prefix("$.").unwrap_or(p);
                claim_exists(disclosed_claims, key)
            });
            if !found {
                return Err(format!(
                    "DCQL required claim not disclosed: {:?}",
                    claim.path
                ));
            }
        }
    }
    Ok(())
}

fn default_response_mode() -> String {
    "direct_post".into()
}

/// Authorization request (stored for cross-device retrieval).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub request_id: String,
    pub client_id: String,
    pub response_uri: String,
    pub dcql_query: DcqlQuery,
    #[serde(default = "default_response_mode")]
    pub response_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id_scheme: Option<String>,
    pub nonce: String,
    pub state: String,
    pub created_at: u64,
}

/// VP response from the wallet (OID4VP 1.0 Final — DCQL-only).
#[derive(Debug, Clone, Deserialize)]
pub struct VpResponse {
    pub vp_token: String,
    pub state: String,
}

/// Result of verifying a VP response.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub format: String,
    pub claims: serde_json::Value,
    pub nonce_verified: bool,
}

/// In-memory request store for cross-device flow + issuer key registry.
pub struct VpRequestStore {
    requests: RwLock<HashMap<String, AuthorizationRequest>>,
    /// Issuer DID → hex-encoded public key. Used for VP signature verification.
    issuer_keys: RwLock<HashMap<String, String>>,
}

impl VpRequestStore {
    pub fn new() -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
            issuer_keys: RwLock::new(HashMap::new()),
        }
    }

    pub fn store(&self, req: AuthorizationRequest) {
        self.requests
            .write()
            .unwrap()
            .insert(req.request_id.clone(), req);
    }

    pub fn get(&self, id: &str) -> Option<AuthorizationRequest> {
        self.requests.read().unwrap().get(id).cloned()
    }

    /// Register an issuer's public key for VP verification.
    pub fn register_issuer_key(&self, did: &str, pubkey_hex: &str) {
        self.issuer_keys
            .write()
            .unwrap()
            .insert(did.to_string(), pubkey_hex.to_string());
    }

    /// Look up an issuer's public key by DID.
    pub fn resolve_issuer_key(&self, did: &str) -> Option<String> {
        self.issuer_keys.read().unwrap().get(did).cloned()
    }
}

impl Default for VpRequestStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a claim key exists in a JSON value (flat or nested by namespace).
fn claim_exists(claims: &serde_json::Value, key: &str) -> bool {
    if let Some(obj) = claims.as_object() {
        if obj.contains_key(key) {
            return true;
        }
        // Check nested namespaces (mdoc style)
        for v in obj.values() {
            if let Some(inner) = v.as_object() {
                if inner.contains_key(key) {
                    return true;
                }
            }
        }
    }
    false
}

// ── Endpoints ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateRequestBody {
    pub client_id: String,
    pub response_uri: String,
    pub dcql_query: Option<DcqlQuery>,
    /// Legacy field — rejected with an explicit error per OID4VP 1.0 Final.
    #[serde(default)]
    pub presentation_definition: Option<serde_json::Value>,
    #[serde(default)]
    pub response_mode: Option<String>,
    #[serde(default)]
    pub client_id_scheme: Option<String>,
}

/// Create a presentation request (OID4VP 1.0 Final — DCQL only).
#[post("/oid4vp/request")]
pub async fn create_request(
    store: web::Data<VpRequestStore>,
    body: web::Json<CreateRequestBody>,
) -> ApiResult<HttpResponse> {
    // Reject legacy PresentationDefinition explicitly
    if body.presentation_definition.is_some() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "INVALID_REQUEST",
                "presentation_definition is not supported in OpenID4VP 1.0 Final; use dcql_query",
            ),
            400,
        )));
    }

    let dcql_query = match &body.dcql_query {
        Some(q) => q.clone(),
        None => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("INVALID_REQUEST", "dcql_query is required"),
                400,
            )));
        }
    };

    let trace = uuid::Uuid::new_v4().to_string();
    let nonce = hex::encode(crate::crypto::hasher::hash_with(
        crate::crypto::hasher::HashAlgorithm::Sha256,
        trace.as_bytes(),
    ));
    let state = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let request = AuthorizationRequest {
        request_id: trace.clone(),
        client_id: body.client_id.clone(),
        response_uri: body.response_uri.clone(),
        dcql_query,
        response_mode: body
            .response_mode
            .clone()
            .unwrap_or_else(default_response_mode),
        client_id_scheme: body.client_id_scheme.clone(),
        nonce: nonce.clone(),
        state: state.clone(),
        created_at: now,
    };

    store.store(request);

    Ok(HttpResponse::Created().json(ApiResponse::success(
        serde_json::json!({
            "request_id": trace,
            "request_uri": format!("/api/v1/oid4vp/request/{trace}"),
            "nonce": nonce,
            "state": state,
        }),
        trace,
    )))
}

/// Fetch a presentation request by ID (cross-device QR code flow).
#[get("/oid4vp/request/{id}")]
pub async fn get_request(
    store: web::Data<VpRequestStore>,
    path: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let id = path.into_inner();
    let trace = uuid::Uuid::new_v4().to_string();
    match store.get(&id) {
        Some(req) => Ok(HttpResponse::Ok().json(ApiResponse::success(req, trace))),
        None => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("NOT_FOUND", "request not found"),
            404,
        ))),
    }
}

/// Receive a VP response from the wallet.
#[post("/oid4vp/response")]
pub async fn submit_response(
    store: web::Data<VpRequestStore>,
    body: web::Json<VpResponse>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();

    // Find the original request by state
    let request = {
        let requests = store.requests.read().unwrap();
        requests.values().find(|r| r.state == body.state).cloned()
    };
    let request = match request {
        Some(r) => r,
        None => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("INVALID_STATE", "no matching request for state"),
                400,
            )));
        }
    };

    // Detect format from the vp_token
    let result = if body.vp_token.contains('~') {
        verify_sd_jwt_presentation(&body.vp_token, &request.nonce, &store)
    } else {
        verify_mdoc_presentation(&body.vp_token)
    };

    let vr = match result {
        Ok(vr) => vr,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("VERIFICATION_FAILED", &e),
                400,
            )));
        }
    };

    // Match against DCQL query
    let format = &vr.format;
    let match_result = match_dcql_query(&request.dcql_query, format, &vr.claims);
    if let Err(e) = match_result {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("DEFINITION_MISMATCH", &e),
            400,
        )));
    }

    Ok(HttpResponse::Ok().json(ApiResponse::success(vr, trace)))
}

fn verify_sd_jwt_presentation(
    vp_token: &str,
    nonce: &str,
    store: &VpRequestStore,
) -> Result<VerificationResult, String> {
    let parts: Vec<&str> = vp_token.split('~').collect();
    if parts.is_empty() {
        return Err("empty vp_token".into());
    }
    let jwt = parts[0];
    let jwt_parts: Vec<&str> = jwt.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err("invalid JWT structure".into());
    }

    let payload_bytes = base64url_decode(jwt_parts[1])?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| e.to_string())?;

    let iss = payload["iss"].as_str().unwrap_or("");

    // Attempt issuer pubkey lookup for signature verification
    let sig_verified = if let Some(pubkey_hex) = store.resolve_issuer_key(iss) {
        crate::identity::sd_jwt::verify_sd_jwt_vc(vp_token, &pubkey_hex).is_ok()
    } else {
        false
    };

    // Parse disclosed claims from disclosures
    let mut disclosed = serde_json::Map::new();
    for disclosure_b64 in parts[1..].iter().filter(|p| !p.is_empty()) {
        if let Ok(bytes) = base64url_decode(disclosure_b64) {
            if let Ok(arr) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(arr) = arr.as_array() {
                    if arr.len() >= 3 {
                        if let Some(name) = arr[1].as_str() {
                            disclosed.insert(name.to_string(), arr[2].clone());
                        }
                    }
                }
            }
        }
    }

    // Include JWT-level claims too
    disclosed.insert("iss".to_string(), payload["iss"].clone());
    disclosed.insert("sub".to_string(), payload["sub"].clone());
    disclosed.insert("vct".to_string(), payload["vct"].clone());

    // Verify nonce: check if the JWT payload contains a matching nonce,
    // or if a KB-JWT with the nonce is appended.
    let nonce_verified = if !nonce.is_empty() {
        let jwt_nonce = payload.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
        if jwt_nonce == nonce {
            true
        } else {
            // Check KB-JWT nonce (last ~-separated segment with dots)
            let tail: Vec<&str> = parts[1..]
                .iter()
                .copied()
                .filter(|p| !p.is_empty())
                .collect();
            tail.last()
                .filter(|s| s.split('.').count() == 3)
                .and_then(|kb| {
                    let kb_parts: Vec<&str> = kb.split('.').collect();
                    let payload_bytes = base64url_decode(kb_parts[1]).ok()?;
                    let kb_payload: serde_json::Value =
                        serde_json::from_slice(&payload_bytes).ok()?;
                    let kb_nonce = kb_payload.get("nonce")?.as_str()?;
                    Some(kb_nonce == nonce)
                })
                .unwrap_or(false)
        }
    } else {
        true
    };

    Ok(VerificationResult {
        valid: sig_verified,
        format: "vc+sd-jwt".to_string(),
        claims: serde_json::Value::Object(disclosed),
        nonce_verified,
    })
}

fn verify_mdoc_presentation(vp_token: &str) -> Result<VerificationResult, String> {
    let mdoc: crate::identity::mdoc::Mdoc =
        serde_json::from_str(vp_token).map_err(|e| format!("invalid mdoc JSON: {e}"))?;
    let verified = crate::identity::mdoc::verify_mdoc(&mdoc)?;

    let mut claims = serde_json::Map::new();
    for (ns, elements) in &verified.disclosed_elements {
        let mut ns_claims = serde_json::Map::new();
        for (k, v) in elements {
            ns_claims.insert(k.clone(), v.clone());
        }
        claims.insert(ns.clone(), serde_json::Value::Object(ns_claims));
    }

    Ok(VerificationResult {
        valid: true,
        format: "mso_mdoc".to_string(),
        claims: serde_json::Value::Object(claims),
        nonce_verified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::SigningProvider;
    use actix_web::{test, web, App};

    fn make_store() -> web::Data<VpRequestStore> {
        web::Data::new(VpRequestStore::new())
    }

    fn test_dcql() -> DcqlQuery {
        DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "pid".into(),
                format: "vc+sd-jwt".into(),
                claims: vec![ClaimQuery {
                    path: vec!["$.given_name".into()],
                    values: None,
                }],
                meta: None,
            }],
        }
    }

    macro_rules! vp_app {
        ($store:expr) => {
            test::init_service(
                App::new().app_data($store).service(
                    web::scope("/api/v1")
                        .service(create_request)
                        .service(get_request)
                        .service(submit_response),
                ),
            )
            .await
        };
    }

    // ── DCQL request creation + fetch ────────────────────────────

    #[actix_web::test]
    async fn e2e_create_and_fetch_dcql_request() {
        let store = make_store();
        let app = vp_app!(store);

        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/request")
            .set_json(serde_json::json!({
                "client_id": "verifier.example.com",
                "response_uri": "https://verifier.example.com/callback",
                "dcql_query": test_dcql(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let request_id = body["data"]["request_id"].as_str().unwrap();
        assert!(!request_id.is_empty());

        // Fetch by reference (cross-device QR flow)
        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/oid4vp/request/{request_id}"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["client_id"], "verifier.example.com");
    }

    #[actix_web::test]
    async fn e2e_request_not_found() {
        let store = make_store();
        let app = vp_app!(store);
        let req = test::TestRequest::get()
            .uri("/api/v1/oid4vp/request/nonexistent")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ── Legacy PresentationDefinition explicitly rejected ─────────

    #[actix_web::test]
    async fn e2e_rejects_presentation_definition() {
        let store = make_store();
        let app = vp_app!(store);
        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/request")
            .set_json(serde_json::json!({
                "client_id": "v.example.com",
                "response_uri": "https://v.example.com/cb",
                "presentation_definition": {"id": "x", "input_descriptors": []}
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let msg = body["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("presentation_definition is not supported"),
            "got: {msg}"
        );
    }

    #[actix_web::test]
    async fn e2e_rejects_missing_dcql() {
        let store = make_store();
        let app = vp_app!(store);
        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/request")
            .set_json(serde_json::json!({
                "client_id": "v.example.com",
                "response_uri": "https://v.example.com/cb"
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    // ── SD-JWT VP via DCQL ────────────────────────────────────────

    #[actix_web::test]
    async fn e2e_submit_sd_jwt_via_dcql() {
        use crate::identity::sd_jwt::{issue_sd_jwt_vc, VcClaims};
        use crate::identity::signing::SoftwareSigningProvider;

        let provider = SoftwareSigningProvider::generate();
        let iss_did = format!("did:goya:{}", &hex::encode(provider.public_key())[..16]);

        let store = make_store();
        store.register_issuer_key(&iss_did, &hex::encode(provider.public_key()));
        let app = vp_app!(store.clone());

        // Create DCQL request
        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/request")
            .set_json(serde_json::json!({
                "client_id": "v.example.com",
                "response_uri": "https://v.example.com/cb",
                "dcql_query": test_dcql(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let state = body["data"]["state"].as_str().unwrap().to_string();

        let sd_jwt = issue_sd_jwt_vc(
            &VcClaims {
                iss: iss_did,
                sub: "did:goya:holder".into(),
                iat: 1_700_000_000,
                exp: 2_000_000_000,
                vct: "IdentityCredential".into(),
                claims: vec![("given_name".into(), serde_json::json!("Juan"))],
            },
            &provider,
        )
        .unwrap();

        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/response")
            .set_json(serde_json::json!({
                "vp_token": sd_jwt.compact,
                "state": state,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["valid"], true);
        assert_eq!(body["data"]["format"], "vc+sd-jwt");
        assert_eq!(body["data"]["claims"]["given_name"], "Juan");
    }

    // ── mdoc VP via DCQL ─────────────────────────────────────────

    #[actix_web::test]
    async fn e2e_submit_mdoc_via_dcql() {
        let store = make_store();
        let app = vp_app!(store.clone());

        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/request")
            .set_json(serde_json::json!({
                "client_id": "v.example.com",
                "response_uri": "https://v.example.com/cb",
                "dcql_query": {
                    "credentials": [{
                        "id": "pid",
                        "format": "mso_mdoc",
                        "claims": [{"path": ["$.given_name"]}]
                    }]
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let state = body["data"]["state"].as_str().unwrap().to_string();

        use crate::identity::mdoc::{issue_mdoc, MdocParams};
        use crate::identity::signing::SoftwareSigningProvider;
        use std::collections::BTreeMap;
        let provider = SoftwareSigningProvider::generate();
        let mut elements = BTreeMap::new();
        elements.insert(
            "eu.europa.ec.eudi.pid.1".to_string(),
            vec![("given_name".to_string(), serde_json::json!("Juan"))],
        );
        let mdoc = issue_mdoc(
            &MdocParams {
                doc_type: "eu.europa.ec.eudi.pid.1".into(),
                elements,
                valid_from: 1_700_000_000,
                valid_until: 2_000_000_000,
                device_key: None,
            },
            &provider,
        )
        .unwrap();

        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/response")
            .set_json(serde_json::json!({
                "vp_token": serde_json::to_string(&mdoc).unwrap(),
                "state": state,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["valid"], true);
        assert_eq!(body["data"]["format"], "mso_mdoc");
    }

    // ── DCQL matching ────────────────────────────────────────────

    #[actix_web::test]
    async fn e2e_dcql_missing_claim_rejects() {
        use crate::identity::sd_jwt::{issue_sd_jwt_vc, VcClaims};
        use crate::identity::signing::SoftwareSigningProvider;

        let provider = SoftwareSigningProvider::generate();
        let store = make_store();
        let app = vp_app!(store.clone());

        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/request")
            .set_json(serde_json::json!({
                "client_id": "v.example.com",
                "response_uri": "https://v.example.com/cb",
                "dcql_query": test_dcql(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let state = body["data"]["state"].as_str().unwrap().to_string();

        // SD-JWT WITHOUT given_name (required by DCQL)
        let sd_jwt = issue_sd_jwt_vc(
            &VcClaims {
                iss: "did:goya:issuer".into(),
                sub: "did:goya:holder".into(),
                iat: 1_700_000_000,
                exp: 2_000_000_000,
                vct: "IdentityCredential".into(),
                claims: vec![("age_over_18".into(), serde_json::json!(true))],
            },
            &provider,
        )
        .unwrap();

        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/response")
            .set_json(serde_json::json!({
                "vp_token": sd_jwt.compact,
                "state": state,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_submit_invalid_state() {
        let store = make_store();
        let app = vp_app!(store);
        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/response")
            .set_json(serde_json::json!({
                "vp_token": "fake~token~",
                "state": "nonexistent-state",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    // ── DCQL multi-credential query ──────────────────────────────

    #[actix_web::test]
    async fn dcql_multi_credential_query() {
        let query = DcqlQuery {
            credentials: vec![
                CredentialQuery {
                    id: "pid".into(),
                    format: "vc+sd-jwt".into(),
                    claims: vec![ClaimQuery {
                        path: vec!["$.given_name".into()],
                        values: None,
                    }],
                    meta: None,
                },
                CredentialQuery {
                    id: "diploma".into(),
                    format: "vc+sd-jwt".into(),
                    claims: vec![ClaimQuery {
                        path: vec!["$.degree".into()],
                        values: None,
                    }],
                    meta: None,
                },
            ],
        };
        let claims = serde_json::json!({"given_name": "Juan", "degree": "CS"});
        assert!(match_dcql_query(&query, "vc+sd-jwt", &claims).is_ok());
    }

    #[actix_web::test]
    async fn dcql_multi_credential_partial_fails() {
        let query = DcqlQuery {
            credentials: vec![
                CredentialQuery {
                    id: "pid".into(),
                    format: "vc+sd-jwt".into(),
                    claims: vec![ClaimQuery {
                        path: vec!["$.given_name".into()],
                        values: None,
                    }],
                    meta: None,
                },
                CredentialQuery {
                    id: "diploma".into(),
                    format: "vc+sd-jwt".into(),
                    claims: vec![ClaimQuery {
                        path: vec!["$.degree".into()],
                        values: None,
                    }],
                    meta: None,
                },
            ],
        };
        let claims = serde_json::json!({"given_name": "Juan"}); // missing degree
        assert!(match_dcql_query(&query, "vc+sd-jwt", &claims).is_err());
    }

    // ── DCQL unit tests ──────────────────────────────────────────

    #[actix_web::test]
    async fn dcql_query_match_valid() {
        let claims = serde_json::json!({"given_name": "Juan", "iss": "x"});
        assert!(match_dcql_query(&test_dcql(), "vc+sd-jwt", &claims).is_ok());
    }

    #[actix_web::test]
    async fn dcql_query_match_missing_claim() {
        let claims = serde_json::json!({"iss": "x"});
        assert!(match_dcql_query(&test_dcql(), "vc+sd-jwt", &claims).is_err());
    }

    #[actix_web::test]
    async fn dcql_query_format_mismatch() {
        let query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "pid".into(),
                format: "mso_mdoc".into(),
                claims: vec![],
                meta: None,
            }],
        };
        let claims = serde_json::json!({});
        assert!(match_dcql_query(&query, "vc+sd-jwt", &claims).is_err());
    }

    // ── Other ────────────────────────────────────────────────────

    #[actix_web::test]
    async fn issuer_key_registry_roundtrip() {
        let store = VpRequestStore::new();
        assert!(store.resolve_issuer_key("did:goya:abc").is_none());
        store.register_issuer_key("did:goya:abc", "deadbeef");
        assert_eq!(
            store.resolve_issuer_key("did:goya:abc"),
            Some("deadbeef".to_string())
        );
    }

    #[actix_web::test]
    async fn e2e_create_request_with_response_mode() {
        let store = make_store();
        let app = vp_app!(store);
        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/request")
            .set_json(serde_json::json!({
                "client_id": "v.example.com",
                "response_uri": "https://v.example.com/cb",
                "dcql_query": test_dcql(),
                "response_mode": "direct_post.jwt",
                "client_id_scheme": "x509_san_dns"
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
    }
}
