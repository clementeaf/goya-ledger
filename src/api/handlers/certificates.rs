use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::pki::NodeCaConfig;
use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

#[derive(Deserialize)]
pub struct IssueFEACertRequest {
    pub did: String,
    pub rut: String,
    pub given_name: String,
    pub surname: String,
    #[serde(default = "default_country")]
    pub country: String,
    #[serde(default = "default_ttl")]
    pub ttl_days: u32,
}

fn default_country() -> String {
    "CL".into()
}

fn default_ttl() -> u32 {
    365
}

#[derive(Serialize)]
struct IssueFEACertResponse {
    serial_hex: String,
    did: String,
    rut: String,
    cert_pem: String,
    not_before: String,
    not_after: String,
}

#[post("/certificates/fea")]
pub async fn issue_fea_cert(
    ca: Option<web::Data<std::sync::Arc<NodeCaConfig>>>,
    body: web::Json<IssueFEACertRequest>,
) -> ApiResult<HttpResponse> {
    if body.did.is_empty() || !body.did.starts_with("did:goya:") {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_DID", "did must start with did:goya:"),
            400,
        )));
    }

    if body.rut.len() < 9 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "INVALID_RUT",
                "rut must be at least 9 characters (e.g. 12345678-9)",
            ),
            400,
        )));
    }

    if body.given_name.is_empty() || body.surname.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("MISSING_NAME", "given_name and surname are required"),
            400,
        )));
    }

    let ca = ca.ok_or_else(|| crate::api::errors::ApiError::StorageError {
        reason: "CA not configured".into(),
    })?;

    let req = crate::pki::FeaCertRequest {
        did: body.did.clone(),
        rut: body.rut.clone(),
        given_name: body.given_name.clone(),
        surname: body.surname.clone(),
        country: body.country.clone(),
        ttl_days: body.ttl_days,
    };

    let issued = crate::pki::issue_fea_certificate(&req, ca.as_ref()).map_err(|e| {
        crate::api::errors::ApiError::StorageError {
            reason: format!("certificate issuance failed: {e}"),
        }
    })?;

    let serial = crate::pki::did_to_cert_serial(&body.did);
    let serial_hex = hex::encode(&serial);

    let (_, cert) = x509_parser::parse_x509_certificate(issued.cert_der.as_ref()).map_err(|e| {
        crate::api::errors::ApiError::StorageError {
            reason: format!("certificate parse failed: {e}"),
        }
    })?;

    let not_before = cert.validity().not_before.to_rfc2822().unwrap_or_default();
    let not_after = cert.validity().not_after.to_rfc2822().unwrap_or_default();

    let trace = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Created().json(ApiResponse::success(
        IssueFEACertResponse {
            serial_hex,
            did: body.did.clone(),
            rut: body.rut.clone(),
            cert_pem: issued.cert_pem,
            not_before,
            not_after,
        },
        trace,
    )))
}

#[derive(Deserialize)]
pub struct RevokeFEACertRequest {
    pub did: String,
    pub reason: Option<String>,
}

#[derive(Serialize)]
struct RevokeFEACertResponse {
    did: String,
    serial_hex: String,
    revoked: bool,
}

#[post("/certificates/fea/revoke")]
pub async fn revoke_fea_cert(
    crl_store: Option<web::Data<std::sync::Arc<dyn crate::msp::CrlStore>>>,
    body: web::Json<RevokeFEACertRequest>,
) -> ApiResult<HttpResponse> {
    if body.did.is_empty() || !body.did.starts_with("did:goya:") {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_DID", "did must start with did:goya:"),
            400,
        )));
    }

    let crl_store = crl_store.ok_or_else(|| crate::api::errors::ApiError::StorageError {
        reason: "CRL store not configured".into(),
    })?;

    let serial = crate::pki::did_to_cert_serial(&body.did);
    let serial_hex = hex::encode(&serial);

    let existing = crl_store.read_crl("fea").unwrap_or_default();
    if existing.contains(&serial_hex) {
        return Ok(HttpResponse::Conflict().json(ApiResponse::<()>::error(
            err_dto("ALREADY_REVOKED", "certificate already revoked"),
            409,
        )));
    }

    let mut updated = existing;
    updated.push(serial_hex.clone());
    crl_store.write_crl("fea", &updated).map_err(|e| {
        crate::api::errors::ApiError::StorageError {
            reason: format!("CRL write failed: {e}"),
        }
    })?;

    let trace = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        RevokeFEACertResponse {
            did: body.did.clone(),
            serial_hex,
            revoked: true,
        },
        trace,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    fn make_ca() -> std::sync::Arc<NodeCaConfig> {
        let (ca, _, _) = NodeCaConfig::generate().unwrap();
        std::sync::Arc::new(ca)
    }

    #[actix_web::test]
    async fn issue_fea_cert_returns_201_with_pem() {
        let ca = make_ca();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(ca))
                .service(web::scope("/api/v1").service(issue_fea_cert)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/certificates/fea")
            .set_json(serde_json::json!({
                "did": "did:goya:abcdef01234567",
                "rut": "12345678-9",
                "given_name": "Juan",
                "surname": "Perez"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["data"]["cert_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
        assert!(!body["data"]["serial_hex"].as_str().unwrap().is_empty());
        assert_eq!(body["data"]["did"], "did:goya:abcdef01234567");
        assert_eq!(body["data"]["rut"], "12345678-9");
    }

    #[actix_web::test]
    async fn issue_fea_cert_rejects_invalid_did() {
        let ca = make_ca();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(ca))
                .service(web::scope("/api/v1").service(issue_fea_cert)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/certificates/fea")
            .set_json(serde_json::json!({
                "did": "not-a-did",
                "rut": "12345678-9",
                "given_name": "Test",
                "surname": "User"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn issue_fea_cert_rejects_short_rut() {
        let ca = make_ca();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(ca))
                .service(web::scope("/api/v1").service(issue_fea_cert)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/certificates/fea")
            .set_json(serde_json::json!({
                "did": "did:goya:abcdef01234567",
                "rut": "123",
                "given_name": "Test",
                "surname": "User"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    fn make_crl_store() -> std::sync::Arc<dyn crate::msp::CrlStore> {
        std::sync::Arc::new(crate::msp::MemoryCrlStore::new())
    }

    #[actix_web::test]
    async fn revoke_fea_cert_returns_200() {
        let crl = make_crl_store();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(crl))
                .service(web::scope("/api/v1").service(revoke_fea_cert)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/certificates/fea/revoke")
            .set_json(serde_json::json!({
                "did": "did:goya:abcdef01234567"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["revoked"], true);
        assert!(!body["data"]["serial_hex"].as_str().unwrap().is_empty());
    }

    #[actix_web::test]
    async fn revoke_fea_cert_returns_409_if_already_revoked() {
        let crl = make_crl_store();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(crl))
                .service(web::scope("/api/v1").service(revoke_fea_cert)),
        )
        .await;

        let payload = serde_json::json!({
            "did": "did:goya:abcdef01234567"
        });

        let req = test::TestRequest::post()
            .uri("/api/v1/certificates/fea/revoke")
            .set_json(&payload)
            .to_request();
        test::call_service(&app, req).await;

        let req2 = test::TestRequest::post()
            .uri("/api/v1/certificates/fea/revoke")
            .set_json(&payload)
            .to_request();
        let resp2 = test::call_service(&app, req2).await;
        assert_eq!(resp2.status(), 409);
    }

    #[actix_web::test]
    async fn revoke_fea_cert_rejects_invalid_did() {
        let crl = make_crl_store();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(crl))
                .service(web::scope("/api/v1").service(revoke_fea_cert)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/certificates/fea/revoke")
            .set_json(serde_json::json!({"did": "bad"}))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn issue_fea_cert_rejects_missing_name() {
        let ca = make_ca();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(ca))
                .service(web::scope("/api/v1").service(issue_fea_cert)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/certificates/fea")
            .set_json(serde_json::json!({
                "did": "did:goya:abcdef01234567",
                "rut": "12345678-9",
                "given_name": "",
                "surname": "User"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }
}
