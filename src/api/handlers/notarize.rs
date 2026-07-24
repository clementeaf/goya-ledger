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
use crate::identity::signing::SigningAlgorithm;
use crate::signature::{compute_biometrics_hash, BiometricEvidence, SignatureLevel};
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

// ── Signature verification ──────────────────────────────────────────────────

/// Verify an Ed25519 signature over a message.
fn verify_ed25519(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let pub_bytes = match hex::decode(public_key_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    use pqc_crypto_module::legacy::ed25519::{Signature, Verifier, VerifyingKey};
    match (
        pub_bytes
            .as_slice()
            .try_into()
            .ok()
            .and_then(|b: &[u8; 32]| VerifyingKey::from_bytes(b).ok()),
        Signature::from_slice(&sig_bytes).ok(),
    ) {
        (Some(vk), Some(sig)) => vk.verify(message, &sig).is_ok(),
        _ => false,
    }
}

/// Verify an ML-DSA-65 signature over a message.
fn verify_mldsa65(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let pub_bytes = match hex::decode(public_key_hex) {
        Ok(b) if b.len() == 1952 => b,
        _ => return false,
    };
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) if b.len() == 3309 => b,
        _ => return false,
    };
    use pqc_crypto_module::legacy::mldsa_raw::{DetachedSignature, PublicKey};
    let pk = match pqc_crypto_module::legacy::mldsa_raw::mldsa65::PublicKey::from_bytes(&pub_bytes)
    {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match pqc_crypto_module::legacy::mldsa_raw::mldsa65::DetachedSignature::from_bytes(
        &sig_bytes,
    ) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    pqc_crypto_module::legacy::mldsa_raw::mldsa65::verify_detached_signature(&sig, message, &pk)
        .is_ok()
}

/// Dispatch signature verification based on algorithm.
fn verify_signature(
    algorithm: SigningAlgorithm,
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> bool {
    match algorithm {
        SigningAlgorithm::Ed25519 => verify_ed25519(public_key_hex, message, signature_hex),
        SigningAlgorithm::MlDsa65 => verify_mldsa65(public_key_hex, message, signature_hex),
    }
}

/// Validate public key hex length for the given algorithm.
fn validate_public_key(algorithm: SigningAlgorithm, public_key_hex: &str) -> Result<(), String> {
    let expected_bytes = match algorithm {
        SigningAlgorithm::Ed25519 => 32,
        SigningAlgorithm::MlDsa65 => 1952,
    };
    let expected_hex = expected_bytes * 2;
    if public_key_hex.len() != expected_hex {
        return Err(format!(
            "public_key must be {expected_hex} hex characters ({expected_bytes} bytes {algorithm})"
        ));
    }
    if hex::decode(public_key_hex).is_err() {
        return Err("public_key is not valid hex".into());
    }
    Ok(())
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

    // Validate algorithm matches signature level
    if !body.level().algorithm_satisfies(body.signature_algorithm) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "ALGORITHM_MISMATCH",
                &format!(
                    "signature level {} requires post-quantum algorithm (ML-DSA-65), got {}",
                    body.signature_level, body.signature_algorithm
                ),
            ),
            400,
        )));
    }

    // Validate biometric evidence for Advanced/Qualified
    if body.level().requires_biometric() && body.biometric_evidence.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "BIOMETRIC_REQUIRED",
                &format!(
                    "signature level {} requires at least one biometric evidence",
                    body.signature_level
                ),
            ),
            400,
        )));
    }

    // Validate each biometric commitment
    for evidence in &body.biometric_evidence {
        if let Err(e) = evidence.validate() {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("INVALID_BIOMETRIC", &e.to_string()),
                400,
            )));
        }
    }

    // Validate public_key for the declared algorithm
    if let Err(msg) = validate_public_key(body.signature_algorithm, &body.public_key) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_PUBLIC_KEY", &msg),
            400,
        )));
    }

    // Verify signer DID matches public key — prevents impersonation.
    if !crate::identity::did::did_matches_pubkey(&body.signer, &body.public_key) {
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

impl NotarizeRequest {
    fn level(&self) -> SignatureLevel {
        self.signature_level
    }
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

    // Validate algorithm matches signature level
    if !body
        .signature_level
        .algorithm_satisfies(body.signature_algorithm)
    {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "ALGORITHM_MISMATCH",
                &format!(
                    "signature level {} requires ML-DSA-65, got {}",
                    body.signature_level, body.signature_algorithm
                ),
            ),
            400,
        )));
    }

    // Validate biometric evidence for Advanced
    if body.signature_level.requires_biometric() && body.biometric_evidence.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "BIOMETRIC_REQUIRED",
                &format!(
                    "signature level {} requires biometric evidence",
                    body.signature_level
                ),
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

    // Validate public_key
    if let Err(msg) = validate_public_key(body.signature_algorithm, &body.public_key) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_PUBLIC_KEY", &msg),
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
