use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};
use zt_common::token::{self, TokenPurpose};
use zt_common::types::EndpointRecord;

#[derive(Debug, Error)]
pub enum RegisterError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("registry returned {status}: {body}")]
    Unexpected { status: u16, body: String },
    #[error("registry URL not configured")]
    NoUrl,
    #[error("secret not configured")]
    NoSecret,
}

pub struct RegistryClient {
    base_url: String,
    secret: Vec<u8>,
    client: reqwest::Client,
    time_offset: i64,
}

impl RegistryClient {
    pub fn new(base_url: &str, secret: &[u8]) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            secret: secret.to_vec(),
            client: reqwest::ClientBuilder::new()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest ClientBuilder::build"),
            time_offset: 0,
        }
    }

    pub async fn sync_time(&mut self) {
        let url = format!("{}/api?cmd=time", self.base_url);
        match self.client.get(&url).send().await {
            Ok(resp) => {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(ts) = body["ts"].as_i64() {
                        let local = token::now_secs();
                        self.time_offset = ts - local;
                        info!(offset = self.time_offset, "time synced with registry");
                        return;
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "time sync failed, using local clock");
            }
        }
    }

    pub async fn register(&self, record: &EndpointRecord) -> Result<(), RegisterError> {
        let window = token::adjusted_window(self.time_offset);
        let token = token::generate(&self.secret, TokenPurpose::Register, window);
        let auth = format!("Bearer {token}");

        let url = format!("{}/api", self.base_url);
        debug!(url = %url, "registering endpoint");

        let resp = self
            .client
            .post(&url)
            .header("Authorization", &auth)
            .json(record)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            debug!("registration succeeded");
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            warn!(%status, body = %body, "registration rejected");
            Err(RegisterError::Unexpected {
                status: status.as_u16(),
                body,
            })
        }
    }
}
