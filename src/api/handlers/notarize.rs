//! Notarization endpoints — Proof of Existence service.
//!
//! Supports two signature levels:
//! - **Simple (FES)**: Ed25519 signature, DID-based identity
//! - **Advanced (FEA)**: ML-DSA-65 (PQC) signature + biometric evidence
//!
//! Legal alignment: Chile Ley 19.799, EU eIDAS 910/2014, US ESIGN Act.
//!
//! Endpoints:
//! - POST   /api/v1/notarize              — register a document hash
//! - GET    /api/v1/notarize/verify/{hash} — verify a document hash
//! - GET    /api/v1/notarize/{id}         — get notarization by ID
//! - GET    /api/v1/notarize              — list notarizations
//! - POST   /api/v1/notarize/{hash}/transfer — transfer ownership
//! - GET    /api/v1/notarize/{hash}/owner — current owner
//! - GET    /api/v1/notarize/{hash}/provenance — full chain

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::api::handlers::channels::{channel_id_from_req, get_channel_store};
use crate::app_state::AppState;
use crate::identity::signing::{SigningAlgorithm, SigningProvider as _};
use crate::signature::{
    compute_biometrics_hash, verify_signature, BiometricEvidence, SignatureLevel,
};
use crate::storage::traits::{NotarizationEntry, OwnershipTransfer};
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Request types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct NotarizeRequest {
    /// SHA-256 hash of the document (64 hex chars = 32 bytes).
    pub content_hash: String,
    /// DID or address of the signer.
    pub signer: String,
    /// Public key (hex). Size depends on algorithm:
    /// - Ed25519: 64 hex chars (32 bytes)
    /// - ML-DSA-65: 3904 hex chars (1952 bytes)
    pub public_key: String,
    /// Signature over the signing payload, hex-encoded.
    pub signature: String,
    /// Optional metadata (document name, description, etc.).
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    /// Signature level: "simple" (default) or "advanced".
    #[serde(default)]
    pub signature_level: SignatureLevel,
    /// Signing algorithm: "Ed25519" (default) or "MlDsa65".
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    /// Biometric evidence (required for Advanced).
    #[serde(default)]
    pub biometric_evidence: Vec<BiometricEvidence>,
}

#[derive(Deserialize)]
pub struct NotarizeListQuery {
    /// Filter by signer DID/address.
    pub signer: Option<String>,
}

// ── Signing payload construction ─────────────────────────────────────────────

/// Build the signing payload based on signature level.
///
/// - Simple:   `"notarize:{signer}:{content_hash}"`
/// - Advanced: `"notarize_fea:{signer}:{content_hash}:{biometrics_hash}"`
fn build_notarize_payload(
    level: SignatureLevel,
    signer: &str,
    content_hash: &str,
    biometric_evidence: &[BiometricEvidence],
) -> String {
    match level {
        SignatureLevel::Simple => format!("notarize:{signer}:{content_hash}"),
        SignatureLevel::Advanced | SignatureLevel::Qualified => {
            let bio_hash = compute_biometrics_hash(biometric_evidence);
            format!("notarize_fea:{signer}:{content_hash}:{bio_hash}")
        }
    }
}

/// Build the transfer signing payload based on signature level.
fn build_transfer_payload(
    level: SignatureLevel,
    content_hash: &str,
    from_did: &str,
    to_did: &str,
    biometric_evidence: &[BiometricEvidence],
) -> String {
    match level {
        SignatureLevel::Simple => format!("transfer_doc:{content_hash}:{from_did}:{to_did}"),
        SignatureLevel::Advanced | SignatureLevel::Qualified => {
            let bio_hash = compute_biometrics_hash(biometric_evidence);
            format!("transfer_fea:{content_hash}:{from_did}:{to_did}:{bio_hash}")
        }
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// Register a document hash for on-chain timestamping.
///
/// Supports Simple (FES) and Advanced (FEA) electronic signatures.
/// Advanced requires ML-DSA-65 algorithm and at least one biometric evidence.
#[post("/notarize")]
pub async fn submit_notarization(
    state: web::Data<AppState>,
    body: web::Json<NotarizeRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    // Validate content_hash: must be 64 hex chars (SHA-256)
    if body.content_hash.len() != 64 || hex::decode(&body.content_hash).is_err() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "INVALID_HASH",
                "content_hash must be 64 hex characters (SHA-256)",
            ),
            400,
        )));
    }

    // Validate FES/FEA constraints
    if let Err(e) = crate::signature::validate_fes_fea(
        body.signature_level,
        body.signature_algorithm,
        &body.biometric_evidence,
        &body.public_key,
    ) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("VALIDATION", &e.to_string()),
            400,
        )));
    }

    // Verify signer DID matches public key — prevents impersonation.
    // FEA uses the node's ML-DSA-65 key (not the user's Ed25519), so the
    // DID (derived from the user's Ed25519 pubkey) will never match.
    if body.signature_level == SignatureLevel::Simple
        && !crate::identity::did::did_matches_pubkey(&body.signer, &body.public_key)
    {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto(
                "SIGNER_MISMATCH",
                "signer DID does not match the provided public key",
            ),
            401,
        )));
    }

    // Build and verify signature over the level-appropriate payload
    let sign_msg = build_notarize_payload(
        body.signature_level,
        &body.signer,
        &body.content_hash,
        &body.biometric_evidence,
    );
    if !verify_signature(
        body.signature_algorithm,
        &body.public_key,
        sign_msg.as_bytes(),
        &body.signature,
    ) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto(
                "INVALID_SIGNATURE",
                &format!("{} signature verification failed", body.signature_algorithm),
            ),
            401,
        )));
    }

    // Check for duplicate: same content_hash already notarized
    if store.read_notarization_by_hash(&body.content_hash).is_ok() {
        return Ok(HttpResponse::Conflict().json(ApiResponse::<()>::error(
            err_dto("ALREADY_NOTARIZED", "document already notarized"),
            409,
        )));
    }

    // Get current block height for anchoring
    let block_height = store.get_latest_height().unwrap_or(0);

    let entry = NotarizationEntry {
        id: uuid::Uuid::new_v4().to_string(),
        content_hash: body.content_hash.clone(),
        signer: body.signer.clone(),
        metadata: body.metadata.clone(),
        notarized_at: now_secs(),
        block_height,
        signature: body.signature.clone(),
        signature_algorithm: body.signature_algorithm,
        signature_level: body.signature_level,
        biometric_evidence: body.biometric_evidence.clone(),
    };

    store
        .write_notarization(&entry)
        .map_err(|e| crate::api::errors::ApiError::StorageError {
            reason: e.to_string(),
        })?;

    Ok(HttpResponse::Created().json(ApiResponse::success(
        serde_json::json!({
            "id": entry.id,
            "content_hash": entry.content_hash,
            "signer": entry.signer,
            "notarized_at": entry.notarized_at,
            "block_height": entry.block_height,
            "signature_level": entry.signature_level,
            "signature_algorithm": entry.signature_algorithm,
        }),
        trace,
    )))
}

/// Verify a document hash — returns the notarization record if it exists.
#[get("/notarize/verify/{hash}")]
pub async fn verify_notarization(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let content_hash = path.into_inner();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    if content_hash.len() != 64 || hex::decode(&content_hash).is_err() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_HASH", "hash must be 64 hex characters (SHA-256)"),
            400,
        )));
    }

    match store.read_notarization_by_hash(&content_hash) {
        Ok(entry) => Ok(HttpResponse::Ok().json(ApiResponse::success(
            serde_json::json!({
                "verified": true,
                "id": entry.id,
                "content_hash": entry.content_hash,
                "signer": entry.signer,
                "notarized_at": entry.notarized_at,
                "block_height": entry.block_height,
                "metadata": entry.metadata,
                "signature": entry.signature,
                "signature_algorithm": entry.signature_algorithm,
                "signature_level": entry.signature_level,
                "biometric_evidence": entry.biometric_evidence,
            }),
            trace,
        ))),
        Err(_) => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("NOT_FOUND", "no notarization found for this document hash"),
            404,
        ))),
    }
}

/// Get a notarization by ID.
#[get("/notarize/{id}")]
pub async fn get_notarization(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let id = path.into_inner();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    match store.read_notarization(&id) {
        Ok(entry) => Ok(HttpResponse::Ok().json(ApiResponse::success(
            serde_json::json!({
                "id": entry.id,
                "content_hash": entry.content_hash,
                "signer": entry.signer,
                "notarized_at": entry.notarized_at,
                "block_height": entry.block_height,
                "metadata": entry.metadata,
                "signature": entry.signature,
                "signature_algorithm": entry.signature_algorithm,
                "signature_level": entry.signature_level,
                "biometric_evidence": entry.biometric_evidence,
            }),
            trace,
        ))),
        Err(_) => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("NOT_FOUND", "notarization not found"),
            404,
        ))),
    }
}

/// List notarizations, optionally filtered by signer.
#[get("/notarize")]
pub async fn list_notarizations(
    state: web::Data<AppState>,
    query: web::Query<NotarizeListQuery>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let entries = store
        .list_notarizations(query.signer.as_deref())
        .map_err(|e| crate::api::errors::ApiError::StorageError {
            reason: e.to_string(),
        })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "count": entries.len(),
            "notarizations": entries,
        }),
        trace,
    )))
}

// ── Ownership Transfer ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TransferDocumentRequest {
    /// DID of the current owner (sender).
    pub from_did: String,
    /// DID of the new owner (recipient).
    pub to_did: String,
    /// Public key of the sender (hex).
    pub public_key: String,
    /// Signature over the transfer payload, hex-encoded.
    pub signature: String,
    /// Signature level: "simple" (default) or "advanced".
    #[serde(default)]
    pub signature_level: SignatureLevel,
    /// Signing algorithm: "Ed25519" (default) or "MlDsa65".
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    /// Biometric evidence (required for Advanced).
    #[serde(default)]
    pub biometric_evidence: Vec<BiometricEvidence>,
}

/// POST /api/v1/notarize/{hash}/transfer — transfer document ownership.
#[post("/notarize/{hash}/transfer")]
pub async fn transfer_document(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<TransferDocumentRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let content_hash = path.into_inner();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    // Validate content_hash format
    if content_hash.len() != 64 || hex::decode(&content_hash).is_err() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_HASH", "hash must be 64 hex characters"),
            400,
        )));
    }

    // Verify document exists
    store
        .read_notarization_by_hash(&content_hash)
        .map_err(|_| crate::api::errors::ApiError::NotFound {
            resource: format!("notarization {content_hash}"),
        })?;

    // Validate FES/FEA constraints
    if let Err(e) = crate::signature::validate_fes_fea(
        body.signature_level,
        body.signature_algorithm,
        &body.biometric_evidence,
        &body.public_key,
    ) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("VALIDATION", &e.to_string()),
            400,
        )));
    }

    // Verify from_did matches public_key
    if !crate::identity::did::did_matches_pubkey(&body.from_did, &body.public_key) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("SIGNER_MISMATCH", "from_did does not match public key"),
            401,
        )));
    }

    // Verify signature
    let sign_msg = build_transfer_payload(
        body.signature_level,
        &content_hash,
        &body.from_did,
        &body.to_did,
        &body.biometric_evidence,
    );
    if !verify_signature(
        body.signature_algorithm,
        &body.public_key,
        sign_msg.as_bytes(),
        &body.signature,
    ) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("INVALID_SIGNATURE", "signature verification failed"),
            401,
        )));
    }

    // Resolve current owner: last transfer recipient, or original signer
    let transfers = store
        .read_ownership_transfers(&content_hash)
        .unwrap_or_default();
    let notarization = store.read_notarization_by_hash(&content_hash).unwrap();
    let current_owner = transfers
        .last()
        .map(|t| t.to_did.as_str())
        .unwrap_or(&notarization.signer);

    // Only current owner can transfer
    if body.from_did != current_owner {
        return Ok(HttpResponse::Forbidden().json(ApiResponse::<()>::error(
            err_dto(
                "NOT_OWNER",
                &format!("only the current owner ({current_owner}) can transfer"),
            ),
            403,
        )));
    }

    let transfer = OwnershipTransfer {
        content_hash: content_hash.clone(),
        from_did: body.from_did.clone(),
        to_did: body.to_did.clone(),
        signature: body.signature.clone(),
        public_key: body.public_key.clone(),
        transferred_at: now_secs(),
        signature_algorithm: body.signature_algorithm,
        signature_level: body.signature_level,
        biometric_evidence: body.biometric_evidence.clone(),
    };

    store.write_ownership_transfer(&transfer).map_err(|e| {
        crate::api::errors::ApiError::StorageError {
            reason: e.to_string(),
        }
    })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "content_hash": content_hash,
            "from": body.from_did,
            "to": body.to_did,
            "transferred_at": transfer.transferred_at,
            "signature_level": transfer.signature_level,
            "signature_algorithm": transfer.signature_algorithm,
        }),
        trace,
    )))
}

/// GET /api/v1/notarize/{hash}/owner — current document owner.
#[get("/notarize/{hash}/owner")]
pub async fn get_document_owner(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let content_hash = path.into_inner();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let notarization = store
        .read_notarization_by_hash(&content_hash)
        .map_err(|_| crate::api::errors::ApiError::NotFound {
            resource: format!("notarization {content_hash}"),
        })?;

    let transfers = store
        .read_ownership_transfers(&content_hash)
        .unwrap_or_default();
    let current_owner = transfers
        .last()
        .map(|t| t.to_did.clone())
        .unwrap_or_else(|| notarization.signer.clone());

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "content_hash": content_hash,
            "owner": current_owner,
            "original_signer": notarization.signer,
            "transfer_count": transfers.len(),
        }),
        trace,
    )))
}

/// GET /api/v1/notarize/{hash}/provenance — full transfer chain.
#[get("/notarize/{hash}/provenance")]
pub async fn get_document_provenance(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let content_hash = path.into_inner();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let notarization = store
        .read_notarization_by_hash(&content_hash)
        .map_err(|_| crate::api::errors::ApiError::NotFound {
            resource: format!("notarization {content_hash}"),
        })?;

    let transfers = store
        .read_ownership_transfers(&content_hash)
        .unwrap_or_default();

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "content_hash": content_hash,
            "original_signer": notarization.signer,
            "notarized_at": notarization.notarized_at,
            "signature_level": notarization.signature_level,
            "transfers": transfers,
        }),
        trace,
    )))
}

// ── Server-side FEA signing ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SignFeaRequest {
    /// SHA-256 hash of the document (64 hex chars).
    pub content_hash: String,
    /// DID of the signer.
    pub signer: String,
    /// Biometric evidence (required, at least one).
    pub biometric_evidence: Vec<BiometricEvidence>,
}

/// POST /api/v1/sign/fea — server-side ML-DSA-65 signature.
///
/// The browser cannot run ML-DSA-65 (no WebCrypto/WASM support).
/// This endpoint signs on behalf of the user using the node's ML-DSA-65
/// signing provider and returns the signature + public key so the
/// frontend can call POST /notarize with a real FEA envelope.
#[post("/sign/fea")]
pub async fn sign_fea(
    _state: web::Data<AppState>,
    body: web::Json<SignFeaRequest>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();

    // Validate content_hash
    if body.content_hash.len() != 64 || hex::decode(&body.content_hash).is_err() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_HASH", "content_hash must be 64 hex characters"),
            400,
        )));
    }

    // Require biometric evidence
    if body.biometric_evidence.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "BIOMETRIC_REQUIRED",
                "FEA requires at least one biometric evidence",
            ),
            400,
        )));
    }
    for evidence in &body.biometric_evidence {
        if let Err(e) = evidence.validate() {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("INVALID_BIOMETRIC", &e.to_string()),
                400,
            )));
        }
    }

    // Build FEA signing payload
    let bio_hash = compute_biometrics_hash(&body.biometric_evidence);
    let payload = format!(
        "notarize_fea:{}:{}:{}",
        body.signer, body.content_hash, bio_hash
    );

    // FEA always requires ML-DSA-65 regardless of the node's global signing config.
    let fea_provider = crate::identity::signing::MlDsaSigningProvider::generate();
    let signature = fea_provider.sign(payload.as_bytes()).map_err(|e| {
        crate::api::errors::ApiError::StorageError {
            reason: format!("signing failed: {e}"),
        }
    })?;
    let public_key = fea_provider.public_key();
    let algorithm = fea_provider.algorithm();

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "signature": hex::encode(&signature),
            "public_key": hex::encode(&public_key),
            "signature_algorithm": algorithm,
            "signing_payload": payload,
        }),
        trace,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::AppState;
    use crate::identity::signing::{
        MlDsaSigningProvider, SigningProvider, SoftwareSigningProvider,
    };
    use actix_web::{test, web, App};

    fn make_app_data() -> web::Data<AppState> {
        web::Data::new(AppState::test_default())
    }

    fn ed25519_identity() -> (String, String, SoftwareSigningProvider) {
        let provider = SoftwareSigningProvider::generate();
        let pk_hex = hex::encode(provider.public_key());
        let did = crate::identity::did::did_from_pubkey_hex(&pk_hex);
        (did, pk_hex, provider)
    }

    fn mldsa65_identity() -> (String, String, MlDsaSigningProvider) {
        let provider = MlDsaSigningProvider::generate();
        let pk_hex = hex::encode(provider.public_key());
        let did = crate::identity::did::did_from_pubkey_hex(&pk_hex);
        (did, pk_hex, provider)
    }

    fn content_hash() -> String {
        use pqc_crypto_module::legacy::sha256::Digest;
        let hash = pqc_crypto_module::legacy::sha256::Sha256::digest(b"test document");
        hex::encode(hash)
    }

    // ── E2E: Simple (FES) with Ed25519 ──────────────────────────────

    #[actix_web::test]
    async fn e2e_simple_notarize_and_verify() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(verify_notarization),
            ),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["signature_level"], "simple");
        assert_eq!(body["data"]["signature_algorithm"], "Ed25519");

        // Verify
        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/notarize/verify/{hash}"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["verified"], true);
        assert_eq!(body["data"]["signature_level"], "simple");
    }

    // ── E2E: Advanced (FEA) with ML-DSA-65 + biometric ──────────────

    #[actix_web::test]
    async fn e2e_advanced_notarize_with_mldsa65_and_biometric() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(verify_notarization)
                    .service(get_notarization),
            ),
        )
        .await;

        let (did, pk_hex, provider) = mldsa65_identity();
        let hash = content_hash();
        let fingerprint_commitment = "a".repeat(64);
        let rut_commitment = "b".repeat(64);
        let bio_evidence = vec![
            serde_json::json!({
                "evidence_type": "fingerprint",
                "commitment": fingerprint_commitment,
                "captured_at": 1700000000u64,
            }),
            serde_json::json!({
                "evidence_type": "rut",
                "commitment": rut_commitment,
                "captured_at": 1700000000u64,
            }),
        ];

        // Build the FEA signing payload
        let bio_for_hash = vec![
            crate::signature::BiometricEvidence {
                evidence_type: crate::signature::BiometricType::Fingerprint,
                commitment: fingerprint_commitment.clone(),
                captured_at: 1700000000,
                capture_device: None,
            },
            crate::signature::BiometricEvidence {
                evidence_type: crate::signature::BiometricType::Rut,
                commitment: rut_commitment.clone(),
                captured_at: 1700000000,
                capture_device: None,
            },
        ];
        let bio_hash = crate::signature::compute_biometrics_hash(&bio_for_hash);
        let payload = format!("notarize_fea:{did}:{hash}:{bio_hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
                "signature_level": "advanced",
                "signature_algorithm": "MlDsa65",
                "biometric_evidence": bio_evidence,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201, "FEA notarize should succeed");
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["signature_level"], "advanced");
        assert_eq!(body["data"]["signature_algorithm"], "MlDsa65");

        // Verify — should include biometric evidence
        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/notarize/verify/{hash}"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["verified"], true);
        assert_eq!(body["data"]["signature_level"], "advanced");
        assert_eq!(body["data"]["signature_algorithm"], "MlDsa65");
        let bio = body["data"]["biometric_evidence"].as_array().unwrap();
        assert_eq!(bio.len(), 2);
        assert_eq!(bio[0]["evidence_type"], "fingerprint");
        assert_eq!(bio[1]["evidence_type"], "rut");
    }

    // ── Verify: rejection paths ────────────────────────────────────────

    #[actix_web::test]
    async fn verify_rejects_invalid_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(verify_notarization)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/v1/notarize/verify/tooshort")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn verify_returns_404_for_unknown_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(verify_notarization)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/notarize/verify/{}", "ab".repeat(32)))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ── Rejection: Advanced with Ed25519 ─────────────────────────────

    #[actix_web::test]
    async fn e2e_advanced_with_ed25519_rejected() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
                "signature_level": "advanced",
                "signature_algorithm": "Ed25519",
                "biometric_evidence": [{
                    "evidence_type": "fingerprint",
                    "commitment": "a".repeat(64),
                    "captured_at": 1700000000u64,
                }],
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"]["code"]
            .as_str()
            .unwrap()
            .contains("VALIDATION"));
    }

    // ── Rejection: Advanced without biometric ────────────────────────

    #[actix_web::test]
    async fn e2e_advanced_without_biometric_rejected() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = mldsa65_identity();
        let hash = content_hash();
        let payload = format!("notarize_fea:{did}:{hash}:{}", "0".repeat(64));
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
                "signature_level": "advanced",
                "signature_algorithm": "MlDsa65",
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"]["code"]
            .as_str()
            .unwrap()
            .contains("VALIDATION"));
    }

    // ── Backwards compat: old request without signature_level ────────

    #[actix_web::test]
    async fn e2e_legacy_request_defaults_to_simple() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        // No signature_level, signature_algorithm, or biometric_evidence
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["signature_level"], "simple");
    }

    // ── Rejection: invalid content_hash ────────────────────────────────

    #[actix_web::test]
    async fn submit_rejects_short_content_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let sig = hex::encode(provider.sign(b"whatever").unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": "tooshort",
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_HASH");
    }

    #[actix_web::test]
    async fn submit_rejects_non_hex_content_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let sig = hex::encode(provider.sign(b"whatever").unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": "z".repeat(64),
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_HASH");
    }

    // ── Rejection: signer DID ↔ pubkey mismatch ─────────────────────

    #[actix_web::test]
    async fn submit_rejects_did_pubkey_mismatch() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (_did, _pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let wrong_did = "did:goya:0000000000000000";
        let pk_hex = hex::encode(provider.public_key());
        let payload = format!("notarize:{wrong_did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": wrong_did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "SIGNER_MISMATCH");
    }

    // ── Rejection: invalid signature ────────────────────────────────

    #[actix_web::test]
    async fn submit_rejects_invalid_signature() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, _provider) = ed25519_identity();
        let hash = content_hash();
        let bad_sig = "aa".repeat(32);

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": bad_sig,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_SIGNATURE");
    }

    // ── Rejection: duplicate notarization ────────────────────────────

    #[actix_web::test]
    async fn submit_rejects_duplicate_content_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let body_json = serde_json::json!({
            "content_hash": hash,
            "signer": did,
            "public_key": pk_hex,
            "signature": sig,
        });

        // First submit — success
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(&body_json)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        // Second submit — conflict
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(&body_json)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 409);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "ALREADY_NOTARIZED");
    }

    // ── Transfer: rejection paths ──────────────────────────────────────

    fn notarize_json(
        did: &str,
        pk_hex: &str,
        provider: &SoftwareSigningProvider,
        hash: &str,
    ) -> serde_json::Value {
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());
        serde_json::json!({
            "content_hash": hash,
            "signer": did,
            "public_key": pk_hex,
            "signature": sig,
        })
    }

    #[actix_web::test]
    async fn transfer_rejects_invalid_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(transfer_document)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize/tooshort/transfer")
            .set_json(serde_json::json!({
                "from_did": "did:goya:aaa",
                "to_did": "did:goya:bbb",
                "public_key": "aa".repeat(32),
                "signature": "bb".repeat(32),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn transfer_rejects_nonexistent_document() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(transfer_document)),
        )
        .await;

        let hash = "ab".repeat(32);
        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/notarize/{hash}/transfer"))
            .set_json(serde_json::json!({
                "from_did": "did:goya:aaa",
                "to_did": "did:goya:bbb",
                "public_key": "aa".repeat(32),
                "signature": "bb".repeat(32),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_web::test]
    async fn transfer_rejects_did_mismatch() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(transfer_document),
            ),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(notarize_json(&did, &pk_hex, &provider, &hash))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 201);

        let wrong_did = "did:goya:0000000000000000";
        let transfer_payload = format!("transfer_doc:{hash}:{wrong_did}:did:goya:recipient");
        let sig = hex::encode(provider.sign(transfer_payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/notarize/{hash}/transfer"))
            .set_json(serde_json::json!({
                "from_did": wrong_did,
                "to_did": "did:goya:recipient",
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "SIGNER_MISMATCH");
    }

    #[actix_web::test]
    async fn transfer_rejects_bad_signature() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(transfer_document),
            ),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(notarize_json(&did, &pk_hex, &provider, &hash))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 201);

        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/notarize/{hash}/transfer"))
            .set_json(serde_json::json!({
                "from_did": did,
                "to_did": "did:goya:recipient",
                "public_key": pk_hex,
                "signature": "aa".repeat(32),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_SIGNATURE");
    }

    #[actix_web::test]
    async fn transfer_rejects_non_owner() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(transfer_document),
            ),
        )
        .await;

        // Alice notarizes
        let (alice_did, alice_pk, alice_provider) = ed25519_identity();
        let hash = content_hash();
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(notarize_json(&alice_did, &alice_pk, &alice_provider, &hash))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 201);

        // Bob tries to transfer Alice's document
        let (bob_did, bob_pk, bob_provider) = ed25519_identity();
        let transfer_payload = format!("transfer_doc:{hash}:{bob_did}:did:goya:thief");
        let sig = hex::encode(bob_provider.sign(transfer_payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/notarize/{hash}/transfer"))
            .set_json(serde_json::json!({
                "from_did": bob_did,
                "to_did": "did:goya:thief",
                "public_key": bob_pk,
                "signature": sig,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "NOT_OWNER");
    }

    #[actix_web::test]
    async fn transfer_rejects_advanced_with_ed25519() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(transfer_document),
            ),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(notarize_json(&did, &pk_hex, &provider, &hash))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 201);

        let sig = hex::encode(provider.sign(b"whatever").unwrap());
        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/notarize/{hash}/transfer"))
            .set_json(serde_json::json!({
                "from_did": did,
                "to_did": "did:goya:recipient",
                "public_key": pk_hex,
                "signature": sig,
                "signature_level": "advanced",
                "signature_algorithm": "Ed25519",
                "biometric_evidence": [{
                    "evidence_type": "fingerprint",
                    "commitment": "a".repeat(64),
                    "captured_at": 1700000000u64,
                }],
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "VALIDATION");
    }

    // ── sign_fea: rejection paths ───────────────────────────────────────

    #[actix_web::test]
    async fn sign_fea_rejects_invalid_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(sign_fea)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/sign/fea")
            .set_json(serde_json::json!({
                "content_hash": "short",
                "signer": "did:goya:test",
                "biometric_evidence": [{
                    "evidence_type": "fingerprint",
                    "commitment": "a".repeat(64),
                    "captured_at": 1700000000u64,
                }],
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_HASH");
    }

    #[actix_web::test]
    async fn sign_fea_rejects_empty_biometrics() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(sign_fea)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/sign/fea")
            .set_json(serde_json::json!({
                "content_hash": "a".repeat(64),
                "signer": "did:goya:test",
                "biometric_evidence": [],
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "BIOMETRIC_REQUIRED");
    }

    #[actix_web::test]
    async fn sign_fea_rejects_invalid_biometric() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(sign_fea)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/sign/fea")
            .set_json(serde_json::json!({
                "content_hash": "a".repeat(64),
                "signer": "did:goya:test",
                "biometric_evidence": [{
                    "evidence_type": "fingerprint",
                    "commitment": "tooshort",
                    "captured_at": 1700000000u64,
                }],
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_BIOMETRIC");
    }

    // ── E2E: Qualified rejected (QTSP not supported) ──────────────────

    #[actix_web::test]
    async fn e2e_qualified_notarize_rejected() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = mldsa65_identity();
        let hash = content_hash();
        let bio_commitment = "d".repeat(64);
        let bio_for_hash = vec![crate::signature::BiometricEvidence {
            evidence_type: crate::signature::BiometricType::GovernmentId,
            commitment: bio_commitment.clone(),
            captured_at: 1700000000,
            capture_device: None,
        }];
        let bio_hash = crate::signature::compute_biometrics_hash(&bio_for_hash);
        let payload = format!("notarize_fea:{did}:{hash}:{bio_hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
                "signature_level": "qualified",
                "signature_algorithm": "MlDsa65",
                "biometric_evidence": [{
                    "evidence_type": "government_id",
                    "commitment": bio_commitment,
                    "captured_at": 1700000000u64,
                }],
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let msg = body["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("Qualified") && msg.contains("not yet supported"),
            "Expected QTSP rejection message, got: {msg}"
        );
    }
}
