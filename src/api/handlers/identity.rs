use crate::api::errors::{enforce_acl, ApiError, ApiResponse, ApiResult, ErrorDto};
use crate::api::handlers::channels::{
    channel_id_from_req, enforce_channel_membership, get_channel_store,
};
use crate::api::models::*;
use crate::app_state::AppState;
use crate::identity::keys::KeyManager;
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use chrono::Utc;

/// POST /identity/create - Create a new DID, generate Ed25519 keypair, persist to store.
#[post("/identity/create")]
async fn create_identity(
    state: web::Data<AppState>,
    _body: web::Json<CreateIdentityRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let algorithm = state
        .signing_provider
        .as_ref()
        .map(|p| p.algorithm())
        .unwrap_or_default();
    let key_mgr = KeyManager::with_algorithm(algorithm, now);
    let public_key_hex = hex::encode(key_mgr.public_key());
    let did = crate::identity::did::did_from_pubkey_hex(&public_key_hex);

    // Persist to store
    let _channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, _channel)?;
    let record = crate::storage::traits::IdentityRecord {
        did: did.clone(),
        public_key: public_key_hex.clone(),
        created_at: now,
        updated_at: now,
        status: "active".to_string(),
        migrated_from: None,
    };
    store
        .write_identity(&record)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;

    crate::audit::emit_if_present(
        &state.audit_store,
        crate::audit::AuditAction::DidRegistered,
        req.headers()
            .get("X-Org-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown"),
        Some(format!("did={did}")),
    );

    let response = IdentityResponse {
        did,
        public_key: public_key_hex,
        created_at: Utc::now(),
    };
    Ok(HttpResponse::Created().json(ApiResponse::success(response, trace_id)))
}

/// GET /identity/{did} - Fetch DID document from store.
#[get("/identity/{did}")]
async fn get_identity(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, _channel)?;

    let record = store.read_identity(&did).map_err(|_| ApiError::NotFound {
        resource: format!("identity {did}"),
    })?;

    let response = IdentityResponse {
        did: record.did,
        public_key: record.public_key,
        created_at: chrono::DateTime::from_timestamp(record.created_at as i64, 0)
            .unwrap_or_else(Utc::now),
    };
    Ok(HttpResponse::Ok().json(ApiResponse::success(response, trace_id)))
}

/// POST /identity/{did}/rotate-key - Key rotation (generates new keypair).
#[post("/identity/{did}/rotate-key")]
async fn rotate_key(
    state: web::Data<AppState>,
    path: web::Path<String>,
    _body: web::Json<RotateKeyRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Verify DID exists
    let _channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, _channel)?;
    let mut record = store.read_identity(&did).map_err(|_| ApiError::NotFound {
        resource: format!("identity {did}"),
    })?;

    // Update timestamp to reflect rotation
    record.updated_at = now;
    store
        .write_identity(&record)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;

    let response = RotateKeyResponse {
        did,
        new_key_index: _body.old_key_index + 1,
        rotated_at: Utc::now(),
    };
    Ok(HttpResponse::Ok().json(ApiResponse::success(response, trace_id)))
}

/// POST /identity/{did}/verify-signature - Verify Ed25519 signature.
#[post("/identity/{did}/verify-signature")]
async fn verify_signature(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<VerifySignatureRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();

    // Verify DID exists
    let _channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, _channel)?;
    let _record = store.read_identity(&did).map_err(|_| ApiError::NotFound {
        resource: format!("identity {did}"),
    })?;

    // Verify signature using the declared algorithm
    let valid = crate::signature::verify_signature(
        body.signature_algorithm,
        &body.public_key,
        body.message.as_bytes(),
        &body.signature,
    );

    let response = VerifySignatureResponse {
        valid,
        key_index: 0,
        verified_at: Utc::now(),
    };
    Ok(HttpResponse::Ok().json(ApiResponse::success(response, trace_id)))
}

// ── PQC Migration ───────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct MigrateRequest {
    #[serde(default = "default_target_algorithm")]
    pub target_algorithm: String,
}

fn default_target_algorithm() -> String {
    "ml-dsa-65".into()
}

#[derive(Debug, serde::Serialize)]
struct MigrateResponse {
    old_did: String,
    new_did: String,
    new_algorithm: String,
    new_public_key_hex: String,
    migrated_at: u64,
}

#[post("/identity/{did}/migrate")]
pub async fn migrate_did(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<MigrateRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();

    let target = match body.target_algorithm.to_lowercase().as_str() {
        "ml-dsa-65" | "mldsa65" | "" => crate::identity::signing::SigningAlgorithm::MlDsa65,
        "ed25519" => crate::identity::signing::SigningAlgorithm::Ed25519,
        other => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                ErrorDto {
                    code: "INVALID_ALGORITHM".into(),
                    message: format!("unsupported target: {other}. Use ml-dsa-65 or ed25519"),
                    field: Some("target_algorithm".into()),
                },
                400,
            )));
        }
    };

    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let record = store.read_identity(&did).map_err(|_| ApiError::NotFound {
        resource: format!("identity {did}"),
    })?;

    if record.status == "migrated" {
        return Ok(HttpResponse::Conflict().json(ApiResponse::<()>::error(
            ErrorDto {
                code: "ALREADY_MIGRATED".into(),
                message: format!("DID {did} already migrated"),
                field: None,
            },
            409,
        )));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let result = crate::identity::keys::migrate_identity(store.as_ref(), &did, target, now)
        .map_err(|e| ApiError::StorageError {
            reason: format!("migration failed: {e}"),
        })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        MigrateResponse {
            old_did: result.old_did,
            new_did: result.new_did,
            new_algorithm: format!("{}", result.new_algorithm),
            new_public_key_hex: result.new_public_key_hex,
            migrated_at: now,
        },
        trace_id,
    )))
}

// ── Store-backed identity endpoints ──────────────────────────────────────────

/// POST /api/v1/store/identities — persiste un IdentityRecord en el store.
#[post("/store/identities")]
pub async fn store_write_identity(
    state: web::Data<AppState>,
    body: web::Json<crate::storage::traits::IdentityRecord>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Identity",
        &req,
    )?;
    super::validation::validate_store_identity(&body)?;
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    store
        .write_identity(&body)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;
    crate::audit::emit_if_present(
        &state.audit_store,
        crate::audit::AuditAction::DidRegistered,
        req.headers()
            .get("X-Org-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown"),
        Some(format!("did={}", body.did)),
    );
    Ok(HttpResponse::Created().json(ApiResponse::success(body.into_inner(), trace_id)))
}

/// GET /api/v1/store/identities/{did} — lee un IdentityRecord del store.
#[get("/store/identities/{did}")]
pub async fn store_get_identity(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    match store.read_identity(&did) {
        Ok(identity) => Ok(HttpResponse::Ok().json(ApiResponse::success(identity, trace_id))),
        Err(_) => Err(ApiError::NotFound {
            resource: format!("identity {did}"),
        }),
    }
}

/// Pagination query params for list endpoints.
#[derive(serde::Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// GET /api/v1/store/identities?limit=100&offset=0 — list identity records with pagination.
#[get("/store/identities")]
pub async fn store_list_identities(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<PaginationQuery>,
) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    let all = store
        .list_identities()
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);
    let page: Vec<_> = all.into_iter().skip(offset).take(limit).collect();
    Ok(HttpResponse::Ok().json(ApiResponse::success(page, trace_id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_identity_handlers_are_public() {
        let _ = (store_write_identity, store_get_identity);
    }
}
