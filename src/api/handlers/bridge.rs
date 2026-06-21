//! Bridge endpoints — cross-chain token transfers.
//!
//!   POST /api/v1/bridge/transfer       — initiate outbound transfer
//!   POST /api/v1/bridge/inbound        — process inbound message
//!   GET  /api/v1/bridge/transfer/{id}  — query transfer status
//!   GET  /api/v1/bridge/chains         — list registered chains
//!   GET  /api/v1/bridge/balances/{account} — wrapped token balances

use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::api::errors::{enforce_acl, ApiError, ApiResponse, ApiResult, ErrorDto};
use crate::app_state::AppState;
use crate::bridge::types::{ChainId, InclusionProof, MessagePayload};

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

fn map_bridge_error(e: crate::bridge::protocol::BridgeError) -> ApiError {
    ApiError::StorageError {
        reason: e.to_string(),
    }
}

// ── Request DTOs ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct InitiateTransferRequest {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub denom: String,
    pub dest_chain: String,
}

#[derive(Deserialize)]
pub struct InboundMessageRequest {
    pub source_chain: String,
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub denom: String,
    pub sequence: u64,
    pub source_height: u64,
    pub source_timestamp: u64,
    pub proof: Option<InclusionProofDto>,
}

#[derive(Deserialize)]
pub struct InclusionProofDto {
    pub merkle_path: Vec<String>,
    pub leaf_index: u64,
    pub root: String,
    pub block_hash: String,
    pub block_height: u64,
}

#[derive(Serialize)]
struct TransferResponse {
    message_id: String,
    source_chain: String,
    dest_chain: String,
    status: String,
}

#[derive(Deserialize)]
pub struct BalanceQuery {
    pub source_chain: Option<String>,
    pub denom: Option<String>,
}

// ── Conversions ──────────────────────────────────────────────────────────────

fn decode_hex_32(hex_str: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(hex_str).map_err(|_| ApiError::ValidationError {
        field: "hex".into(),
        reason: format!("invalid hex: {hex_str}"),
    })?;
    bytes.try_into().map_err(|_| ApiError::ValidationError {
        field: "hex".into(),
        reason: "expected 32 bytes".into(),
    })
}

fn convert_proof(dto: &InclusionProofDto) -> Result<InclusionProof, ApiError> {
    let merkle_path: Result<Vec<[u8; 32]>, _> =
        dto.merkle_path.iter().map(|h| decode_hex_32(h)).collect();
    Ok(InclusionProof {
        merkle_path: merkle_path?,
        leaf_index: dto.leaf_index,
        root: decode_hex_32(&dto.root)?,
        block_hash: decode_hex_32(&dto.block_hash)?,
        block_height: dto.block_height,
    })
}

// ── Validation ───────────────────────────────────────────────────────────────

fn validate_transfer_request(body: &InitiateTransferRequest) -> Result<(), ApiError> {
    [
        (body.sender.is_empty(), "sender", "sender is required"),
        (
            body.recipient.is_empty(),
            "recipient",
            "recipient is required",
        ),
        (
            body.amount == 0,
            "amount",
            "amount must be greater than zero",
        ),
    ]
    .iter()
    .find(|(failed, _, _)| *failed)
    .map(|(_, field, reason)| {
        Err(ApiError::ValidationError {
            field: field.to_string(),
            reason: reason.to_string(),
        })
    })
    .unwrap_or(Ok(()))
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// POST /api/v1/bridge/transfer — initiate an outbound cross-chain transfer.
#[post("/bridge/transfer")]
pub async fn initiate_transfer(
    state: web::Data<AppState>,
    body: web::Json<InitiateTransferRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Propose",
        &req,
    )?;
    let trace = uuid::Uuid::new_v4().to_string();

    // Validate required fields — return on first failure
    validate_transfer_request(&body)?;

    let dest = ChainId(body.dest_chain.clone());
    let msg = state
        .bridge_engine
        .initiate_transfer(
            &body.sender,
            &body.recipient,
            body.amount,
            &body.denom,
            &dest,
            0,
        )
        .map_err(map_bridge_error)?;

    Ok(HttpResponse::Created().json(ApiResponse::success(
        TransferResponse {
            message_id: hex::encode(msg.id),
            source_chain: msg.source_chain.0,
            dest_chain: msg.dest_chain.0,
            status: "Pending".into(),
        },
        trace,
    )))
}

/// POST /api/v1/bridge/inbound — process an inbound cross-chain message.
#[post("/bridge/inbound")]
pub async fn process_inbound(
    state: web::Data<AppState>,
    body: web::Json<InboundMessageRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Propose",
        &req,
    )?;
    let trace = uuid::Uuid::new_v4().to_string();

    let proof = body.proof.as_ref().map(convert_proof).transpose()?;

    let source = ChainId(body.source_chain.clone());
    let dest = ChainId::native();
    let sequence = body.sequence;
    let msg_id = crate::bridge::protocol::BridgeEngine::compute_message_id(
        &body.sender,
        &body.recipient,
        body.amount,
        sequence,
    );

    let message = crate::bridge::types::BridgeMessage {
        id: msg_id,
        source_chain: source,
        dest_chain: dest,
        sequence,
        payload: MessagePayload::TokenTransfer {
            sender: body.sender.clone(),
            recipient: body.recipient.clone(),
            amount: body.amount,
            denom: body.denom.clone(),
        },
        source_height: body.source_height,
        source_timestamp: body.source_timestamp,
        proof,
    };

    state
        .bridge_engine
        .process_inbound(&message, body.source_height + 100)
        .map_err(map_bridge_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "message_id": hex::encode(msg_id),
            "status": "minted",
        }),
        trace,
    )))
}

/// GET /api/v1/bridge/transfer/{id} — query transfer status by message ID.
#[get("/bridge/transfer/{id}")]
pub async fn get_transfer_status(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let id_hex = path.into_inner();
    let id_bytes = decode_hex_32(&id_hex)?;

    match state.bridge_engine.escrow.get_escrow(&id_bytes) {
        Some(entry) => Ok(HttpResponse::Ok().json(ApiResponse::success(
            serde_json::json!({
                "message_id": id_hex,
                "sender": entry.sender,
                "amount": entry.amount,
                "denom": entry.denom,
                "dest_chain": entry.dest_chain.0,
                "status": format!("{:?}", entry.status),
            }),
            trace,
        ))),
        None => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("NOT_FOUND", "transfer not found"),
            404,
        ))),
    }
}

/// GET /api/v1/bridge/chains — list registered external chains.
#[get("/bridge/chains")]
pub async fn list_chains(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let chains: Vec<serde_json::Value> = state
        .bridge_engine
        .registry
        .list()
        .iter()
        .map(|c| {
            serde_json::json!({
                "chain_id": c.chain_id.0,
                "name": c.name,
                "protocol": format!("{:?}", c.protocol),
                "active": c.active,
                "min_confirmations": c.min_confirmations,
                "max_transfer": c.max_transfer,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(ApiResponse::success(chains, trace)))
}

/// GET /api/v1/bridge/balances/{account} — wrapped token balances.
#[get("/bridge/balances/{account}")]
pub async fn get_balances(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<BalanceQuery>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let account = path.into_inner();

    let source_chain = query.source_chain.as_deref().unwrap_or("ethereum");
    let denom = query.denom.as_deref().unwrap_or("ETH");

    let balance = state.bridge_engine.escrow.wrapped_balance(
        &account,
        &ChainId(source_chain.to_string()),
        denom,
    );

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "account": account,
            "source_chain": source_chain,
            "denom": denom,
            "balance": balance,
        }),
        trace,
    )))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_32_valid() {
        let hex = "a".repeat(64);
        assert!(decode_hex_32(&hex).is_ok());
    }

    #[test]
    fn decode_hex_32_invalid_length() {
        assert!(decode_hex_32("abcd").is_err());
    }

    #[test]
    fn decode_hex_32_invalid_chars() {
        let bad = "g".repeat(64);
        assert!(decode_hex_32(&bad).is_err());
    }

    #[test]
    fn convert_proof_valid() {
        let dto = InclusionProofDto {
            merkle_path: vec!["b".repeat(64)],
            leaf_index: 0,
            root: "c".repeat(64),
            block_hash: "d".repeat(64),
            block_height: 42,
        };
        let proof = convert_proof(&dto).unwrap();
        assert_eq!(proof.block_height, 42);
        assert_eq!(proof.merkle_path.len(), 1);
    }

    #[test]
    fn convert_proof_invalid_hex() {
        let dto = InclusionProofDto {
            merkle_path: vec!["not-hex".into()],
            leaf_index: 0,
            root: "c".repeat(64),
            block_hash: "d".repeat(64),
            block_height: 1,
        };
        assert!(convert_proof(&dto).is_err());
    }

    #[test]
    fn transfer_response_serializes() {
        let resp = TransferResponse {
            message_id: "abc".into(),
            source_chain: "rust-bc".into(),
            dest_chain: "ethereum".into(),
            status: "Pending".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "Pending");
    }
}
