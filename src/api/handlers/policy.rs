//! CP/CPS policy API handlers — RFC 3647 / ETSI TS 102 042.

use crate::api::errors::{ApiResponse, ApiResult};
use crate::pki_policy;
use actix_web::{get, HttpResponse};

/// Get the Certificate Policy (CP).
#[get("/policy/cp")]
pub async fn get_cp() -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let cp = pki_policy::default_cp();
    Ok(HttpResponse::Ok().json(ApiResponse::success(cp, trace)))
}

/// Get the Certification Practice Statement (CPS).
#[get("/policy/cps")]
pub async fn get_cps() -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let cps = pki_policy::default_cps();
    Ok(HttpResponse::Ok().json(ApiResponse::success(cps, trace)))
}

/// Get all OIDs in the Goya namespace.
#[get("/policy/oids")]
pub async fn get_oids() -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "root": pki_policy::GOYA_OID_ROOT,
            "certificate_policy": pki_policy::CP_OID,
            "certification_practice_statement": pki_policy::CPS_OID,
            "tsa_policy": pki_policy::TSA_POLICY_OID,
            "signature_policy": pki_policy::SIGNATURE_POLICY_OID,
        }),
        trace,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::AppState;
    use actix_web::{test, web, App};

    macro_rules! policy_app {
        () => {{
            let state = web::Data::new(AppState::test_default());
            test::init_service(
                App::new().app_data(state).service(
                    web::scope("/api/v1")
                        .service(get_cp)
                        .service(get_cps)
                        .service(get_oids),
                ),
            )
            .await
        }};
    }

    #[actix_web::test]
    async fn e2e_get_cp() {
        let app = policy_app!();
        let req = test::TestRequest::get()
            .uri("/api/v1/policy/cp")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["oid"], pki_policy::CP_OID);
        assert_eq!(body["data"]["status"], "draft");
        assert!(body["data"]["legal_framework"]["primary_law"]
            .as_str()
            .unwrap()
            .contains("19.799"));
    }

    #[actix_web::test]
    async fn e2e_get_cps() {
        let app = policy_app!();
        let req = test::TestRequest::get()
            .uri("/api/v1/policy/cps")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["oid"], pki_policy::CPS_OID);
        assert!(body["data"]["identity_proofing"]["rut_validation_required"]
            .as_bool()
            .unwrap());
    }

    #[actix_web::test]
    async fn e2e_get_oids() {
        let app = policy_app!();
        let req = test::TestRequest::get()
            .uri("/api/v1/policy/oids")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["root"], pki_policy::GOYA_OID_ROOT);
        assert_eq!(body["data"]["certificate_policy"], pki_policy::CP_OID);
    }
}
