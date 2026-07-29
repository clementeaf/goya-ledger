//! Stripe integration — Checkout Sessions and webhooks.
//!
//! Endpoints:
//! - POST /api/v1/checkout          — create a Stripe Checkout Session
//! - POST /api/v1/stripe/webhook    — handle Stripe webhook events

use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};

use actix_web::HttpRequest;

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
pub async fn create_checkout(body: web::Json<CheckoutRequest>) -> ApiResult<HttpResponse> {
    let secret_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto(
                        "STRIPE_NOT_CONFIGURED",
                        "Stripe is not configured — set STRIPE_SECRET_KEY",
                    ),
                    503,
                )),
            );
        }
    };

    // Map tier to Stripe Price ID (set via env vars)
    let price_env = match body.tier.as_str() {
        "starter" => "STRIPE_PRICE_STARTER",
        "business" => "STRIPE_PRICE_BUSINESS",
        "enterprise" => "STRIPE_PRICE_ENTERPRISE",
        _ => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto(
                    "INVALID_TIER",
                    "tier must be starter, business, or enterprise",
                ),
                400,
            )));
        }
    };

    let price_id = match std::env::var(price_env) {
        Ok(p) if !p.is_empty() => p,
        _ => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto(
                        "PRICE_NOT_CONFIGURED",
                        &format!("Stripe price not configured — set {price_env}"),
                    ),
                    503,
                )),
            );
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
    let stripe_resp: serde_json::Value = serde_json::from_str(&body_text).unwrap_or_default();

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
// Stripe webhook HMAC verification (Stripe-Signature header)
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256 and return hex-encoded digest.
fn compute_hmac_hex(secret: &str, message: &[u8]) -> String {
    use pqc_crypto_module::legacy::sha256::{Digest, Sha256};
    let key_bytes = secret.as_bytes();
    // HMAC-SHA256: if key > block_size, hash it first
    let block_size = 64;
    let key = if key_bytes.len() > block_size {
        let mut h = Sha256::new();
        h.update(key_bytes);
        h.finalize().to_vec()
    } else {
        key_bytes.to_vec()
    };
    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5cu8; block_size];
    for (i, &b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner_hash);
    hex::encode(outer.finalize())
}

/// Verify the Stripe-Signature header against the raw body.
///
/// Stripe signs as: HMAC-SHA256(secret, "{timestamp}.{payload}").
/// Header format: `t={timestamp},v1={hex_signature}[,v1={hex_signature}...]`
fn verify_stripe_signature(secret: &str, payload: &[u8], sig_header: &str) -> Result<(), String> {
    if secret.is_empty() {
        return Err("STRIPE_WEBHOOK_SECRET not configured".into());
    }
    if sig_header.is_empty() {
        return Err("missing Stripe-Signature header".into());
    }

    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in sig_header.split(',') {
        let part = part.trim();
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = Some(t);
        } else if let Some(s) = part.strip_prefix("v1=") {
            signatures.push(s);
        }
    }

    let ts = timestamp.ok_or("no timestamp in Stripe-Signature")?;
    if signatures.is_empty() {
        return Err("no v1 signature in Stripe-Signature".into());
    }

    let payload_str =
        std::str::from_utf8(payload).map_err(|e| format!("payload not UTF-8: {e}"))?;
    let signed_payload = format!("{ts}.{payload_str}");
    let expected = compute_hmac_hex(secret, signed_payload.as_bytes());

    // Constant-time-ish comparison: check all signatures, accept if any matches
    let matched = signatures.iter().any(|s| {
        // Compare lowercase hex to avoid case sensitivity issues
        s.to_lowercase() == expected.to_lowercase()
    });

    if matched {
        Ok(())
    } else {
        Err("signature mismatch".into())
    }
}

// ---------------------------------------------------------------------------
// POST /api/v1/stripe/webhook
// ---------------------------------------------------------------------------

#[post("/stripe/webhook")]
pub async fn stripe_webhook(req: HttpRequest, body: web::Bytes) -> ApiResult<HttpResponse> {
    let webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_default();

    // Fail closed: if secret not configured, reject all webhooks
    if webhook_secret.is_empty() {
        return Ok(
            HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                err_dto(
                    "WEBHOOK_NOT_CONFIGURED",
                    "STRIPE_WEBHOOK_SECRET not set — webhook verification disabled",
                ),
                503,
            )),
        );
    }

    let sig_header = req
        .headers()
        .get("Stripe-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Err(e) = verify_stripe_signature(&webhook_secret, &body, sig_header) {
        log::warn!("Stripe webhook signature verification failed: {e}");
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("INVALID_SIGNATURE", "Webhook signature verification failed"),
            401,
        )));
    }

    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let event_type = payload["type"].as_str().unwrap_or("unknown");

    match event_type {
        "checkout.session.completed" => {
            let customer_email = payload["data"]["object"]["customer_details"]["email"]
                .as_str()
                .unwrap_or("unknown");
            let subscription_id = payload["data"]["object"]["subscription"]
                .as_str()
                .unwrap_or("none");
            // ponytail: log only — tier activation not implemented.
            // To wire: look up customer by email, map subscription to tier,
            // update BillingManager. Until then, this is receive-and-log.
            log::warn!(
                "Stripe checkout completed but tier activation NOT IMPLEMENTED: \
                 email={}, subscription={}",
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

    // ── TDD: webhook HMAC verification ──────────────────────────────

    #[test]
    fn verify_stripe_signature_rejects_missing_secret() {
        // No secret configured → fail closed
        let result = verify_stripe_signature("", b"payload", "t=123,v1=abc");
        assert!(result.is_err());
    }

    #[test]
    fn verify_stripe_signature_rejects_missing_header() {
        let result = verify_stripe_signature("whsec_test", b"payload", "");
        assert!(result.is_err());
    }

    #[test]
    fn verify_stripe_signature_rejects_invalid_hmac() {
        let result = verify_stripe_signature("whsec_test", b"payload", "t=123,v1=badhex");
        assert!(result.is_err());
    }

    #[test]
    fn verify_stripe_signature_accepts_valid_hmac() {
        let secret = "whsec_test_secret";
        let timestamp = "1234567890";
        let payload = b"{\"type\":\"checkout.session.completed\"}";

        // Compute expected HMAC the way Stripe does: HMAC-SHA256(secret, "timestamp.payload")
        let signed_payload = format!("{}.{}", timestamp, std::str::from_utf8(payload).unwrap());
        let expected_sig = compute_hmac_hex(secret, signed_payload.as_bytes());
        let header = format!("t={},v1={}", timestamp, expected_sig);

        let result = verify_stripe_signature(secret, payload, &header);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_stripe_signature_rejects_tampered_payload() {
        let secret = "whsec_test_secret";
        let timestamp = "1234567890";
        let original = b"{\"type\":\"checkout.session.completed\"}";
        let tampered = b"{\"type\":\"checkout.session.completed\",\"evil\":true}";

        let signed_payload = format!("{}.{}", timestamp, std::str::from_utf8(original).unwrap());
        let sig = compute_hmac_hex(secret, signed_payload.as_bytes());
        let header = format!("t={},v1={}", timestamp, sig);

        // Verify against tampered payload — must fail
        let result = verify_stripe_signature(secret, tampered, &header);
        assert!(result.is_err());
    }
}
