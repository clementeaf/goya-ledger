use actix_web::{get, web, HttpResponse};
use pqc_crypto_module::legacy::sha256::{Digest, Sha256};

use crate::api::errors::{ApiError, ApiResponse, ApiResult};
use crate::api::handlers::channels::get_channel_store;
use crate::api::models::{ChainInfoResponse, ChainVerifyResponse};
use crate::app_state::AppState;
use crate::storage::traits::Block;

/// Compute the canonical SHA-256 hash of a block (height || parent_hash || merkle_root || timestamp || proposer).
pub(crate) fn compute_block_hash(block: &Block) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(block.height.to_le_bytes());
    hasher.update(block.parent_hash);
    hasher.update(block.merkle_root);
    hasher.update(block.timestamp.to_le_bytes());
    hasher.update(block.proposer.as_bytes());
    hasher.finalize().into()
}

/// Hex-encode a 32-byte hash.
pub(crate) fn hex_hash(hash: &[u8; 32]) -> String {
    hex::encode(hash)
}

/// GET /api/v1/chain/verify — walk the chain and verify parent_hash linkage.
#[get("/verify")]
pub async fn verify_chain(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let store = get_channel_store(&state, "default")?;
    let height = store.get_latest_height().unwrap_or(0);
    let has_genesis = store.block_exists(0).unwrap_or(false);
    let block_count = if has_genesis {
        (height + 1) as usize
    } else {
        0
    };

    if block_count == 0 {
        let data = ChainVerifyResponse {
            valid: true,
            block_count: 0,
            first_invalid_height: None,
        };
        return Ok(HttpResponse::Ok().json(ApiResponse::success(data, trace_id)));
    }

    // Walk the chain: each block's parent_hash must match the previous block's computed hash.
    let mut first_invalid_height: Option<u64> = None;
    let genesis = store.read_block(0).map_err(|e| ApiError::StorageError {
        reason: e.to_string(),
    })?;
    let mut prev_hash = compute_block_hash(&genesis);

    for h in 1..=height {
        match store.read_block(h) {
            Ok(block) => {
                if block.parent_hash != prev_hash {
                    first_invalid_height = Some(h);
                    break;
                }
                prev_hash = compute_block_hash(&block);
            }
            Err(_) => {
                first_invalid_height = Some(h);
                break;
            }
        }
    }

    let data = ChainVerifyResponse {
        valid: first_invalid_height.is_none(),
        block_count,
        first_invalid_height,
    };
    let body = ApiResponse::success(data, trace_id);
    Ok(HttpResponse::Ok().json(body))
}

/// GET /api/v1/chain/info — chain metadata from BlockStore with real latest block hash.
#[get("/info")]
pub async fn get_blockchain_info(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let store = get_channel_store(&state, "default")?;
    let height = store.get_latest_height().unwrap_or(0);
    let has_genesis = store.block_exists(0).unwrap_or(false);
    let block_count = if has_genesis {
        (height + 1) as usize
    } else {
        0
    };

    let latest_block_hash = if has_genesis {
        match store.read_block(height) {
            Ok(block) => hex_hash(&compute_block_hash(&block)),
            Err(_) => String::new(),
        }
    } else {
        String::new()
    };

    let data = ChainInfoResponse {
        block_count,
        latest_block_hash,
        is_valid: true,
    };
    let body = ApiResponse::success(data, trace_id);
    Ok(HttpResponse::Ok().json(body))
}

#[cfg(test)]
mod tests {
    use super::{get_blockchain_info, verify_chain};

    #[test]
    fn chain_gateway_handlers_are_public() {
        let _ = (verify_chain, get_blockchain_info);
    }
}
