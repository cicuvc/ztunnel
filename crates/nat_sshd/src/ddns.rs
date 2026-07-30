use std::net::Ipv4Addr;
use std::path::PathBuf;
use tracing::{info, warn};

pub struct DdnsConfig {
    pub domain: String,
    pub zone_id: String,
    pub record_id: String,
    pub token: String,
}

impl DdnsConfig {
    pub fn from_env() -> Option<Self> {
        let domain = std::env::var("WEB_DOMAIN").ok()?;
        let zone_id = std::env::var("CF_ZONE_ID").ok()?;
        let record_id = std::env::var("CF_RECORD_ID").ok()?;
        let token = load_cf_token()?;
        Some(Self {
            domain,
            zone_id,
            record_id,
            token,
        })
    }
}

fn load_cf_token() -> Option<String> {
    if let Ok(t) = std::env::var("CF_TOKEN") {
        if !t.is_empty() {
            return Some(t);
        }
    }
    let path = std::env::var("CF_TOKEN_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
            PathBuf::from(home).join(".config").join("ztunnel").join("cf_token")
        });
    let content = std::fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Key:") {
            let t = rest.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
        let t = line.trim();
        if !t.is_empty() && !t.starts_with('#') {
            return Some(t.to_string());
        }
    }
    None
}

/// Update the Cloudflare A record to point at the current public IP.
/// No-op when DDNS is not configured (e.g. the ssh instance).
pub async fn update_a_record(config: &DdnsConfig, ip: Ipv4Addr) {
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
        config.zone_id, config.record_id
    );
    let body = serde_json::json!({
        "type": "A",
        "name": config.domain,
        "content": ip.to_string(),
        "ttl": 60,
        "proxied": false,
    });

    let client = reqwest::Client::new();
    match client
        .put(&url)
        .bearer_auth(&config.token)
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                info!(domain = %config.domain, %ip, "DNS A record updated");
            } else {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                warn!(%status, body = %text, "DNS update rejected");
            }
        }
        Err(e) => {
            warn!(error = %e, "DNS update request failed");
        }
    }
}
