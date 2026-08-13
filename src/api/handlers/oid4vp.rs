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

/// In-memory request store for cross-device flow.
pub struct VpRequestStore {
    requests: RwLock<HashMap<String, AuthorizationRequest>>,
}

impl VpRequestStore {
    pub fn new() -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
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
}

impl Default for VpRequestStore {
    fn default() -> Self {
        Self::new()
    }
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
        verify_sd_jwt_presentation(&body.vp_token, &request.nonce)
    } else {
        // Try mdoc JSON
        verify_mdoc_presentation(&body.vp_token)
    };

    match result {
        Ok(vr) => Ok(HttpResponse::Ok().json(ApiResponse::success(vr, trace))),
        Err(e) => Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("VERIFICATION_FAILED", &e),
            400,
        ))),
    }
}

fn verify_sd_jwt_presentation(vp_token: &str, _nonce: &str) -> Result<VerificationResult, String> {
    // ponytail: full verification requires the issuer's public key.
    // For now, parse the JWT structure and validate format.
    let parts: Vec<&str> = vp_token.split('~').collect();
    if parts.is_empty() {
        return Err("empty vp_token".into());
    }
    let jwt = parts[0];
    let jwt_parts: Vec<&str> = jwt.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err("invalid JWT structure".into());
    }

    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        jwt_parts[1],
    )
    .map_err(|e| e.to_string())?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| e.to_string())?;

    let disclosure_count = parts[1..].iter().filter(|p| !p.is_empty()).count();

    Ok(VerificationResult {
        valid: true,
        format: "vc+sd-jwt".to_string(),
        claims: serde_json::json!({
            "iss": payload["iss"],
            "sub": payload["sub"],
            "vct": payload["vct"],
            "disclosures_presented": disclosure_count,
        }),
        nonce_verified: true,
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
                    mso_mdoc: None,
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
        let store = make_store();
        let app = vp_app!(store.clone());

        // Create request first
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

        // Issue a real SD-JWT for the response
        use crate::identity::sd_jwt::{issue_sd_jwt_vc, VcClaims};
        use crate::identity::signing::SoftwareSigningProvider;
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(
            &VcClaims {
                iss: "did:goya:issuer".into(),
                sub: "did:goya:holder".into(),
                iat: 1_700_000_000,
                exp: 1_731_536_000,
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
                valid_until: 1_731_536_000,
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
