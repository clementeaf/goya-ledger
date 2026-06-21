//! Stress test endpoint:
//!   GET /api/v1/stress/report?ops=1000 — run module stress tests

use actix_web::{get, web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::api::errors::{enforce_acl, ApiResponse, ApiResult};
use crate::app_state::AppState;

#[derive(Deserialize)]
pub struct StressQuery {
    pub ops: Option<u64>,
}

/// GET /api/v1/stress/report — run all module stress tests (admin only)
#[get("/stress/report")]
pub async fn stress_report(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<StressQuery>,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Admin",
        &req,
    )?;
    let trace = uuid::Uuid::new_v4().to_string();
    let ops = query.ops.unwrap_or(1000).min(100_000);

    let report = tokio::task::spawn_blocking(move || crate::stress::run_full_stress(ops))
        .await
        .unwrap();

    Ok(HttpResponse::Ok().json(ApiResponse::success(report, trace)))
}
