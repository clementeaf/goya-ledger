use actix_web::{get, post, web, HttpRequest, HttpResponse};

use crate::api::errors::{enforce_acl, ApiError, ApiResponse, ApiResult};
use crate::app_state::AppState;
use crate::lexchain::engine;
use crate::lexchain::types::{ContractDefinition, SignRequest};

#[post("/lexchain/deploy")]
async fn deploy_contract(
    state: web::Data<AppState>,
    body: web::Json<ContractDefinition>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "lexchain/Deploy",
        &req,
    )?;
    let trace_id = uuid::Uuid::new_v4().to_string();

    let contract = engine::deploy(&state.lexchain_store, body.into_inner()).map_err(|e| {
        ApiError::ValidationError {
            field: "contract".into(),
            reason: e.to_string(),
        }
    })?;

    Ok(HttpResponse::Created().json(ApiResponse::success(contract, trace_id)))
}

#[post("/lexchain/{id}/sign")]
async fn sign_contract(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<SignRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "lexchain/Sign",
        &req,
    )?;
    let contract_id = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();

    let mut contract =
        engine::sign(&state.lexchain_store, &contract_id, &body).map_err(|e| match &e {
            engine::LexChainError::NotFound(_) => ApiError::NotFound {
                resource: format!("contract {contract_id}"),
            },
            _ => ApiError::ValidationError {
                field: "signature".into(),
                reason: e.to_string(),
            },
        })?;

    if contract.all_signed() && contract.definition.require_notarization {
        if let Some(ref tsa) = state.tsa_provider {
            match engine::notarize(&state.lexchain_store, &contract_id, tsa) {
                Ok(notarized) => contract = notarized,
                Err(e) => log::warn!("auto-notarization failed: {e}"),
            }
        }
    }

    Ok(HttpResponse::Ok().json(ApiResponse::success(contract, trace_id)))
}

#[get("/lexchain/{id}")]
async fn get_contract(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "lexchain/Query",
        &req,
    )?;
    let contract_id = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();

    let contract = state
        .lexchain_store
        .get(&contract_id)
        .ok_or_else(|| ApiError::NotFound {
            resource: format!("contract {contract_id}"),
        })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(contract, trace_id)))
}

#[get("/lexchain")]
async fn list_contracts(state: web::Data<AppState>, req: HttpRequest) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "lexchain/Query",
        &req,
    )?;
    let trace_id = uuid::Uuid::new_v4().to_string();
    let contracts = state.lexchain_store.list();
    Ok(HttpResponse::Ok().json(ApiResponse::success(contracts, trace_id)))
}
