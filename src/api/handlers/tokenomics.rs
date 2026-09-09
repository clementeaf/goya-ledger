use crate::api::errors::{ApiResponse, ApiResult};
use crate::app_state::AppState;
use crate::tokenomics::economics;
use actix_web::{get, web, HttpResponse};
use serde::Serialize;

#[derive(Serialize)]
struct SupplyResponse {
    max_supply: u64,
    total_minted: u64,
    total_burned: u64,
    circulating_supply: u64,
    supply_cap_reached: bool,
}

#[derive(Serialize)]
struct FeeResponse {
    base_fee: u64,
    min_tx_fee: u64,
    fee_burn_percent: u64,
    fee_proposer_percent: u64,
}

#[derive(Serialize)]
struct InflationResponse {
    annual_inflation_percent: f64,
    current_epoch: u64,
    epoch_fees: u64,
    block_height: u64,
    current_block_reward: u64,
    halving_interval: u64,
    next_halving_at: u64,
}

#[get("/tokenomics/supply")]
pub async fn supply(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let econ = state
        .economics_state
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        SupplyResponse {
            max_supply: economics::MAX_SUPPLY,
            total_minted: econ.total_minted,
            total_burned: econ.total_burned,
            circulating_supply: econ.circulating_supply(),
            supply_cap_reached: econ.supply_cap_reached(),
        },
        trace_id,
    )))
}

#[get("/tokenomics/fee")]
pub async fn fee(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let econ = state
        .economics_state
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        FeeResponse {
            base_fee: econ.base_fee,
            min_tx_fee: economics::MIN_TX_FEE,
            fee_burn_percent: economics::FEE_BURN_PERCENT,
            fee_proposer_percent: economics::FEE_PROPOSER_PERCENT,
        },
        trace_id,
    )))
}

#[get("/tokenomics/inflation")]
pub async fn inflation(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let econ = state
        .economics_state
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let current_reward = economics::block_reward(econ.height);
    let halvings_done = econ.height / economics::HALVING_INTERVAL;
    let next_halving = (halvings_done + 1) * economics::HALVING_INTERVAL;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        InflationResponse {
            annual_inflation_percent: econ.annual_inflation_percent(),
            current_epoch: econ.current_epoch(),
            epoch_fees: econ.epoch_fees,
            block_height: econ.height,
            current_block_reward: current_reward,
            halving_interval: economics::HALVING_INTERVAL,
            next_halving_at: next_halving,
        },
        trace_id,
    )))
}
