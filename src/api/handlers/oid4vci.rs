//! OpenID4VCI — OpenID for Verifiable Credential Issuance (1.0).
//!
//! Implements the pre-authorized code flow for EUDI Wallet interop:
//! - `GET  /.well-known/openid-credential-issuer` — issuer metadata
//! - `POST /token` — exchange pre-authorized code for access token
//! - `POST /credential` — issue SD-JWT VC or mdoc

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::app_state::AppState;
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
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
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    c_nonce: String,
    c_nonce_expires_in: u64,
}

/// Token endpoint — exchange pre-authorized code for access token.
#[post("/token")]
pub async fn token_endpoint(body: web::Form<TokenRequest>) -> ApiResult<HttpResponse> {
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

    // ponytail: in production, validate code against a store.
    // For now, any non-empty code is accepted.
    let access_token = format!(
        "goya_at_{}",
        hex::encode(crate::crypto::hasher::hash_with(
            crate::crypto::hasher::HashAlgorithm::Sha256,
            code.as_bytes()
        ))
    );
    let c_nonce = hex::encode(crate::crypto::hasher::hash_with(
        crate::crypto::hasher::HashAlgorithm::Sha256,
        access_token.as_bytes(),
    ));

    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        c_nonce,
        c_nonce_expires_in: 300,
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
#[post("/credential")]
pub async fn credential_endpoint(
    state: web::Data<AppState>,
    body: web::Json<CredentialRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    // Check bearer token
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !auth.starts_with("Bearer ") || auth.len() < 10 {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("invalid_token", "Bearer token required"),
            401,
        )));
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

    #[actix_web::test]
    async fn e2e_token_exchange() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(TokenRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
                pre_authorized_code: Some("test-code-123".to_string()),
            })
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
            })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
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
}
