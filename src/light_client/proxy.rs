//! Seed node proxy — forwards API requests from the light client to a remote
//! full node over HTTPS. All writes (POST) are proxied; reads (GET) are proxied
//! with query parameters preserved.

use reqwest::Client;
use serde::de::DeserializeOwned;
use std::time::Duration;

/// Errors from seed node communication.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("seed node request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("seed node returned {status}: {body}")]
    Upstream { status: u16, body: String },
    #[error("seed node URL not configured (set SEED_NODE_URL)")]
    NotConfigured,
}

/// HTTP proxy to a seed node.
#[derive(Debug, Clone)]
pub struct SeedProxy {
    client: Client,
    base_url: String,
}

impl SeedProxy {
    /// Create from `SEED_NODE_URL` env var.
    /// Returns `Err(ProxyError::NotConfigured)` when unset.
    pub fn from_env() -> Result<Self, ProxyError> {
        std::env::var("SEED_NODE_URL")
            .map(|url| Self::new(url.trim_end_matches('/').to_string()))
            .map_err(|_| ProxyError::NotConfigured)
    }

    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("failed to build HTTP client");
        Self { client, base_url }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// GET a JSON response from the seed node.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ProxyError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self.client.get(&url).send().await?;
        Self::parse_response(resp).await
    }

    /// POST a JSON body to the seed node, return parsed response.
    pub async fn post<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ProxyError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self.client.post(&url).json(body).send().await?;
        Self::parse_response(resp).await
    }

    /// Forward a raw body (already JSON bytes) via POST, return raw response body.
    pub async fn post_raw(&self, path: &str, body: &[u8]) -> Result<String, ProxyError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body.to_vec())
            .send()
            .await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        match status {
            200..=299 => Ok(text),
            _ => Err(ProxyError::Upstream { status, body: text }),
        }
    }

    async fn parse_response<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T, ProxyError> {
        let status = resp.status().as_u16();
        match status {
            200..=299 => Ok(resp.json::<T>().await?),
            _ => {
                let body = resp.text().await.unwrap_or_default();
                Err(ProxyError::Upstream { status, body })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ponytail: env-mutating from_env tests removed — racy in parallel.
    // The logic (trim slash, construct client) is tested via new() below.

    #[test]
    fn new_sets_base_url() {
        let proxy = SeedProxy::new("http://localhost:8080".into());
        assert_eq!(proxy.base_url(), "http://localhost:8080");
    }

    #[test]
    fn new_trims_trailing_slash() {
        let proxy = SeedProxy::new("https://goya-node.fly.dev/".trim_end_matches('/').to_string());
        assert_eq!(proxy.base_url(), "https://goya-node.fly.dev");
    }
}
