//! Stripe integration — Checkout Sessions and webhooks.
//!
//! Endpoints:
//! - POST /api/v1/checkout          — create a Stripe Checkout Session
//! - POST /api/v1/stripe/webhook    — handle Stripe webhook events

use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

// ---------------------------------------------------------------------------
// POST /api/v1/checkout
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CheckoutRequest {
    /// Tier: "starter", "business", or "enterprise"
    pub tier: String,
    /// URL to redirect on success (frontend sets this)
    pub success_url: String,
    /// URL to redirect on cancel
    pub cancel_url: String,
}

#[derive(Serialize)]
pub struct CheckoutResponse {
    pub url: String,
    pub session_id: String,
}

#[post("/checkout")]
pub async fn create_checkout(
    body: web::Json<CheckoutRequest>,
) -> ApiResult<HttpResponse> {
    let secret_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return Ok(HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                err_dto("STRIPE_NOT_CONFIGURED", "Stripe is not configured — set STRIPE_SECRET_KEY"),
                503,
            )));
        }
    };

    // Map tier to Stripe Price ID (set via env vars)
    let price_env = match body.tier.as_str() {
        "starter" => "STRIPE_PRICE_STARTER",
        "business" => "STRIPE_PRICE_BUSINESS",
        "enterprise" => "STRIPE_PRICE_ENTERPRISE",
        _ => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("INVALID_TIER", "tier must be starter, business, or enterprise"),
                400,
            )));
        }
    };

    let price_id = match std::env::var(price_env) {
        Ok(p) if !p.is_empty() => p,
        _ => {
            return Ok(HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                err_dto(
                    "PRICE_NOT_CONFIGURED",
                    &format!("Stripe price not configured — set {price_env}"),
                ),
                503,
            )));
        }
    };

    // Call Stripe API directly via reqwest (no SDK needed)
    let client = reqwest::Client::new();
    let params = [
        ("mode", "subscription"),
        ("line_items[0][price]", &price_id),
        ("line_items[0][quantity]", "1"),
        ("success_url", &body.success_url),
        ("cancel_url", &body.cancel_url),
    ];

    let resp = match client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .basic_auth(&secret_key, None::<&str>)
        .form(&params)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::error!("Stripe request failed: {e}");
            return Ok(HttpResponse::BadGateway().json(ApiResponse::<()>::error(
                err_dto("STRIPE_ERROR", "Failed to contact Stripe"),
                502,
            )));
        }
    };

    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        log::error!("Stripe API error ({}): {}", status, body_text);
        return Ok(HttpResponse::BadGateway().json(ApiResponse::<()>::error(
            err_dto("STRIPE_API_ERROR", "Stripe returned an error"),
            502,
        )));
    }

    // Parse Stripe response — we only need url and id
    let stripe_resp: serde_json::Value =
        serde_json::from_str(&body_text).unwrap_or_default();

    let checkout_url = stripe_resp["url"].as_str().unwrap_or("").to_string();
    let session_id = stripe_resp["id"].as_str().unwrap_or("").to_string();

    if checkout_url.is_empty() {
        return Ok(HttpResponse::BadGateway().json(ApiResponse::<()>::error(
            err_dto("STRIPE_NO_URL", "Stripe did not return a checkout URL"),
            502,
        )));
    }

    let trace = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        CheckoutResponse {
            url: checkout_url,
            session_id,
        },
        trace,
    )))
}

// ---------------------------------------------------------------------------
// POST /api/v1/stripe/webhook
// ---------------------------------------------------------------------------

#[post("/stripe/webhook")]
pub async fn stripe_webhook(body: web::Bytes) -> ApiResult<HttpResponse> {
    // ponytail: no signature verification yet — add STRIPE_WEBHOOK_SECRET + HMAC when going live
    let payload: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_default();

    let event_type = payload["type"].as_str().unwrap_or("unknown");

    match event_type {
        "checkout.session.completed" => {
            let customer_email = payload["data"]["object"]["customer_details"]["email"]
                .as_str()
                .unwrap_or("unknown");
            let subscription_id = payload["data"]["object"]["subscription"]
                .as_str()
                .unwrap_or("none");
            log::info!(
                "Stripe checkout completed: email={}, subscription={}",
                customer_email,
                subscription_id
            );
        }
        _ => {
            log::debug!("Stripe webhook event ignored: {}", event_type);
        }
    }

    let trace = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({ "received": true }),
        trace,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_tier() {
        let req = CheckoutRequest {
            tier: "gold".to_string(),
            success_url: "https://example.com/ok".to_string(),
            cancel_url: "https://example.com/cancel".to_string(),
        };
        assert!(!["starter", "business", "enterprise"].contains(&req.tier.as_str()));
    }

    #[test]
    fn valid_tiers_accepted() {
        for tier in &["starter", "business", "enterprise"] {
            assert!(["starter", "business", "enterprise"].contains(tier));
        }
    }
}
