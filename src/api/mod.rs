//! API Tier (Tier 4): REST Gateway and HTTP Interface
//!
//! Responsibilities:
//! - REST API endpoint definitions
//! - Request/response serialization (JSON, binary)
//! - Parameter validation and error formatting
//! - Rate limiting and access control (mTLS + ACL)
//! - API versioning and backward compatibility

pub mod cors;
pub mod errors;
pub mod handlers;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod openapi;
pub mod pagination;
pub mod rate_limit;
pub mod routes;
pub mod traits;
pub mod versioning;

/// API configuration
#[allow(dead_code)] // Config struct fields read via from_env()
#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
    pub rate_limit_per_minute: u32,
    pub max_request_size_bytes: usize,
}

impl ApiConfig {
    /// Build config from environment.
    pub fn from_env() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            rate_limit_per_minute: 1000,
            max_request_size_bytes: 10 * 1024 * 1024,
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let cfg = ApiConfig::default();
        assert_eq!(cfg.port, 8080);
    }
}
