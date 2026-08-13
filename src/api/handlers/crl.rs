//! CRL Distribution Point — RFC 5280 §5.
//!
//! Serves the Certificate Revocation List as DER or PEM.

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::app_state::AppState;
use actix_web::{get, web, HttpResponse};

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

/// Download the current CRL in DER format.
/// Content-Type: application/pkix-crl
#[get("/crl/{msp_id}")]
pub async fn get_crl_der(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let msp_id = path.into_inner();
    let crl_store = match state.crl_store.as_ref() {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("CRL_UNAVAILABLE", "CRL store is not configured"),
                    503,
                )),
            );
        }
    };

    let ca = match crate::pki::NodeCaConfig::from_env() {
        Ok(ca) => ca,
        Err(_) => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto(
                        "CA_UNAVAILABLE",
                        "CA not configured (TLS_CA_CERT_PATH/TLS_CA_KEY_PATH)",
                    ),
                    503,
                )),
            );
        }
    };

    let serials = crl_store.read_crl(&msp_id).unwrap_or_default();

    match crate::msp::crl_rfc5280::generate_crl_der(&serials, &ca, 1, 7) {
        Ok(der) => Ok(HttpResponse::Ok()
            .content_type("application/pkix-crl")
            .body(der)),
        Err(e) => Ok(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                err_dto("CRL_ERROR", &e.to_string()),
                500,
            )),
        ),
    }
}

/// Download the current CRL in PEM format.
#[get("/crl/{msp_id}/pem")]
pub async fn get_crl_pem(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let msp_id = path.into_inner();
    let crl_store = match state.crl_store.as_ref() {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("CRL_UNAVAILABLE", "CRL store is not configured"),
                    503,
                )),
            );
        }
    };

    let ca = match crate::pki::NodeCaConfig::from_env() {
        Ok(ca) => ca,
        Err(_) => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("CA_UNAVAILABLE", "CA not configured"),
                    503,
                )),
            );
        }
    };

    let serials = crl_store.read_crl(&msp_id).unwrap_or_default();

    match crate::msp::crl_rfc5280::generate_crl_pem(&serials, &ca, 1, 7) {
        Ok(pem) => Ok(HttpResponse::Ok()
            .content_type("application/x-pem-file")
            .body(pem)),
        Err(e) => Ok(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                err_dto("CRL_ERROR", &e.to_string()),
                500,
            )),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msp::{CrlStore, MemoryCrlStore};
    use actix_web::{test, web, App};
    use std::sync::Arc;

    fn make_state_with_crl(revoked: &[&str]) -> web::Data<AppState> {
        let mut state = AppState::test_default();
        let crl = Arc::new(MemoryCrlStore::new());
        let serials: Vec<String> = revoked.iter().map(|s| s.to_string()).collect();
        crl.write_crl("default", &serials).unwrap();
        state.crl_store = Some(crl);
        web::Data::new(state)
    }

    #[actix_web::test]
    async fn crl_503_when_no_store() {
        let state = web::Data::new(AppState::test_default());
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(get_crl_der)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/v1/crl/default")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 503);
    }

    #[actix_web::test]
    async fn crl_503_when_no_ca() {
        let state = make_state_with_crl(&[]);
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(get_crl_der)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/v1/crl/default")
            .to_request();
        let resp = test::call_service(&app, req).await;
        // Without TLS_CA_CERT_PATH/TLS_CA_KEY_PATH env vars, returns 503
        assert_eq!(resp.status(), 503);
    }
}
