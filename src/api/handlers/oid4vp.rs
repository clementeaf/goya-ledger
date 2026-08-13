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

/// Presentation definition — what credentials the verifier needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationDefinition {
    pub id: String,
    pub input_descriptors: Vec<InputDescriptor>,
}

/// Describes one credential requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDescriptor {
    pub id: String,
    /// Credential format(s) accepted.
    pub format: DescriptorFormat,
    /// Constraints on claims.
    #[serde(default)]
    pub constraints: Option<Constraints>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorFormat {
    #[serde(rename = "vc+sd-jwt", default)]
    pub sd_jwt: Option<FormatAlgs>,
    #[serde(default)]
    pub mso_mdoc: Option<FormatAlgs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatAlgs {
    #[serde(default)]
    pub alg: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    pub fields: Vec<FieldConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConstraint {
    pub path: Vec<String>,
    #[serde(default)]
    pub optional: bool,
}

/// Authorization request (stored for cross-device retrieval).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub request_id: String,
    pub client_id: String,
    pub response_uri: String,
    pub presentation_definition: PresentationDefinition,
    pub nonce: String,
    pub state: String,
    pub created_at: u64,
}

/// VP response from the wallet.
#[derive(Debug, Clone, Deserialize)]
pub struct VpResponse {
    pub vp_token: String,
    pub presentation_submission: PresentationSubmission,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<DescriptorMapEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorMapEntry {
    pub id: String,
    pub format: String,
    pub path: String,
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

// ── Presentation Definition Matching ─────────────────────────────────────

/// Match a vp_token against a presentation_definition's input_descriptors.
/// Checks: format compatibility, required field constraints satisfied.
fn match_presentation_definition(
    definition: &PresentationDefinition,
    submission: &PresentationSubmission,
    disclosed_claims: &serde_json::Value,
    format: &str,
) -> Result<(), String> {
    if submission.definition_id != definition.id {
        return Err(format!(
            "definition_id mismatch: expected {}, got {}",
            definition.id, submission.definition_id
        ));
    }

    for descriptor in &definition.input_descriptors {
        // Find matching entry in descriptor_map
        let map_entry = submission
            .descriptor_map
            .iter()
            .find(|e| e.id == descriptor.id);
        let map_entry = match map_entry {
            Some(e) => e,
            None => {
                return Err(format!(
                    "missing descriptor_map entry for '{}'",
                    descriptor.id
                ));
            }
        };

        // Check format compatibility
        let format_ok = match format {
            "vc+sd-jwt" => map_entry.format == "vc+sd-jwt" && descriptor.format.sd_jwt.is_some(),
            "mso_mdoc" => map_entry.format == "mso_mdoc" && descriptor.format.mso_mdoc.is_some(),
            _ => false,
        };
        if !format_ok {
            return Err(format!(
                "format mismatch for '{}': submitted {}, accepted {:?}",
                descriptor.id, map_entry.format, format
            ));
        }

        // Check field constraints
        if let Some(constraints) = &descriptor.constraints {
            for field in &constraints.fields {
                if field.optional {
                    continue;
                }
                // Check if any path matches a key in disclosed claims
                let found = field.path.iter().any(|p| {
                    // Simplified JSONPath: $.claim_name → check "claim_name" in claims
                    let key = p.strip_prefix("$.").unwrap_or(p);
                    claim_exists(disclosed_claims, key)
                });
                if !found {
                    return Err(format!("required field not disclosed: {:?}", field.path));
                }
            }
        }
    }

    Ok(())
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
    pub presentation_definition: PresentationDefinition,
}

/// Create a presentation request.
#[post("/oid4vp/request")]
pub async fn create_request(
    store: web::Data<VpRequestStore>,
    body: web::Json<CreateRequestBody>,
) -> ApiResult<HttpResponse> {
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
        presentation_definition: body.presentation_definition.clone(),
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

    // Match against presentation_definition
    let format = &vr.format;
    if let Err(e) = match_presentation_definition(
        &request.presentation_definition,
        &body.presentation_submission,
        &vr.claims,
        format,
    ) {
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

    fn test_definition() -> PresentationDefinition {
        PresentationDefinition {
            id: "pid-request".to_string(),
            input_descriptors: vec![InputDescriptor {
                id: "identity".to_string(),
                format: DescriptorFormat {
                    sd_jwt: Some(FormatAlgs {
                        alg: vec!["EdDSA".to_string()],
                    }),
                    mso_mdoc: Some(FormatAlgs {
                        alg: vec!["EdDSA".to_string()],
                    }),
                },
                constraints: Some(Constraints {
                    fields: vec![
                        FieldConstraint {
                            path: vec!["$.given_name".to_string()],
                            optional: false,
                        },
                        FieldConstraint {
                            path: vec!["$.birth_date".to_string()],
                            optional: true,
                        },
                    ],
                }),
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

    #[actix_web::test]
    async fn e2e_create_and_fetch_request() {
        let store = make_store();
        let app = vp_app!(store);

        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/request")
            .set_json(serde_json::json!({
                "client_id": "verifier.example.com",
                "response_uri": "https://verifier.example.com/callback",
                "presentation_definition": test_definition(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let request_id = body["data"]["request_id"].as_str().unwrap();
        assert!(!request_id.is_empty());
        assert!(body["data"]["nonce"].as_str().is_some());

        // Fetch by reference
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

    #[actix_web::test]
    async fn e2e_submit_sd_jwt_response() {
        use crate::identity::sd_jwt::{issue_sd_jwt_vc, VcClaims};
        use crate::identity::signing::SoftwareSigningProvider;

        let provider = SoftwareSigningProvider::generate();
        let iss_did = format!("did:goya:{}", &hex::encode(provider.public_key())[..16]);

        let store = make_store();
        // Register issuer key for signature verification
        store.register_issuer_key(&iss_did, &hex::encode(provider.public_key()));
        let app = vp_app!(store.clone());

        // Create request
        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/request")
            .set_json(serde_json::json!({
                "client_id": "v.example.com",
                "response_uri": "https://v.example.com/cb",
                "presentation_definition": test_definition(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let state = body["data"]["state"].as_str().unwrap().to_string();

        // Issue SD-JWT with matching issuer DID
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
                "presentation_submission": {
                    "id": "sub1",
                    "definition_id": "pid-request",
                    "descriptor_map": [{
                        "id": "identity",
                        "format": "vc+sd-jwt",
                        "path": "$",
                    }]
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["valid"], true);
        assert_eq!(body["data"]["format"], "vc+sd-jwt");
        assert_eq!(body["data"]["claims"]["given_name"], "Juan");
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
                "presentation_submission": {
                    "id": "s1",
                    "definition_id": "d1",
                    "descriptor_map": []
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_sd_jwt_without_issuer_key_returns_valid_false() {
        use crate::identity::sd_jwt::{issue_sd_jwt_vc, VcClaims};
        use crate::identity::signing::SoftwareSigningProvider;

        let provider = SoftwareSigningProvider::generate();
        let store = make_store();
        // No issuer key registered
        let app = vp_app!(store.clone());

        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/request")
            .set_json(serde_json::json!({
                "client_id": "v.example.com",
                "response_uri": "https://v.example.com/cb",
                "presentation_definition": test_definition(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let state = body["data"]["state"].as_str().unwrap().to_string();

        let sd_jwt = issue_sd_jwt_vc(
            &VcClaims {
                iss: "did:goya:unknown".into(),
                sub: "did:goya:holder".into(),
                iat: 1_700_000_000,
                exp: 2_000_000_000,
                vct: "IdentityCredential".into(),
                claims: vec![("given_name".into(), serde_json::json!("Ana"))],
            },
            &provider,
        )
        .unwrap();

        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/response")
            .set_json(serde_json::json!({
                "vp_token": sd_jwt.compact,
                "state": state,
                "presentation_submission": {
                    "id": "s1",
                    "definition_id": "pid-request",
                    "descriptor_map": [{"id":"identity","format":"vc+sd-jwt","path":"$"}]
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["valid"], false); // no issuer key → unverified
        assert_eq!(body["data"]["format"], "vc+sd-jwt");
    }

    #[actix_web::test]
    async fn e2e_definition_mismatch_rejects() {
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
                "presentation_definition": test_definition(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let state = body["data"]["state"].as_str().unwrap().to_string();

        // SD-JWT WITHOUT given_name (required by definition)
        let sd_jwt = issue_sd_jwt_vc(
            &VcClaims {
                iss: "did:goya:issuer2".into(),
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
                "presentation_submission": {
                    "id": "s1",
                    "definition_id": "pid-request",
                    "descriptor_map": [{"id":"identity","format":"vc+sd-jwt","path":"$"}]
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400); // missing required given_name
    }

    #[actix_web::test]
    async fn match_definition_unit_valid() {
        let def = test_definition();
        let sub = PresentationSubmission {
            id: "s1".into(),
            definition_id: "pid-request".into(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "identity".into(),
                format: "vc+sd-jwt".into(),
                path: "$".into(),
            }],
        };
        let claims = serde_json::json!({"given_name": "Juan", "iss": "x", "sub": "y", "vct": "z"});
        assert!(match_presentation_definition(&def, &sub, &claims, "vc+sd-jwt").is_ok());
    }

    #[actix_web::test]
    async fn match_definition_unit_missing_field() {
        let def = test_definition();
        let sub = PresentationSubmission {
            id: "s1".into(),
            definition_id: "pid-request".into(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "identity".into(),
                format: "vc+sd-jwt".into(),
                path: "$".into(),
            }],
        };
        let claims = serde_json::json!({"iss": "x", "sub": "y"}); // no given_name
        assert!(match_presentation_definition(&def, &sub, &claims, "vc+sd-jwt").is_err());
    }

    #[actix_web::test]
    async fn match_definition_unit_wrong_format() {
        let mut def = test_definition();
        def.input_descriptors[0].format.mso_mdoc = None;
        let sub = PresentationSubmission {
            id: "s1".into(),
            definition_id: "pid-request".into(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "identity".into(),
                format: "mso_mdoc".into(),
                path: "$".into(),
            }],
        };
        let claims = serde_json::json!({"given_name": "Juan"});
        assert!(match_presentation_definition(&def, &sub, &claims, "mso_mdoc").is_err());
    }

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
    async fn e2e_submit_mdoc_response() {
        let store = make_store();
        let app = vp_app!(store.clone());

        // Create request
        let req = test::TestRequest::post()
            .uri("/api/v1/oid4vp/request")
            .set_json(serde_json::json!({
                "client_id": "v.example.com",
                "response_uri": "https://v.example.com/cb",
                "presentation_definition": test_definition(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let state = body["data"]["state"].as_str().unwrap().to_string();

        // Issue a real mdoc
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
                "presentation_submission": {
                    "id": "s1",
                    "definition_id": "pid-request",
                    "descriptor_map": [{
                        "id": "identity",
                        "format": "mso_mdoc",
                        "path": "$",
                    }]
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["valid"], true);
        assert_eq!(body["data"]["format"], "mso_mdoc");
    }
}
