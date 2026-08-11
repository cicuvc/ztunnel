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
    token_from_content(&content)
}

/// Parse a CF token from file content: prefer a `Key:` line, else the first
/// bare (no-colon) non-empty, non-comment line.  Labels like `Account: ...`
/// and example blocks are skipped.
fn token_from_content(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Key:") {
            let t = rest.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        } else if !trimmed.contains(':') {
            // Bare token line (no "key:" prefix) — accept it.
            return Some(trimmed.to_string());
        }
        // Lines like "Account: ..." or "======== Example ========" are skipped.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_key_line() {
        let content = "Account: abc123\nKey: realtoken123\n\n==== Example ====\ncurl ... Bearer realtoken123\n";
        assert_eq!(token_from_content(content).as_deref(), Some("realtoken123"));
    }

    #[test]
    fn loads_bare_token_line() {
        assert_eq!(token_from_content("realtoken456\n").as_deref(), Some("realtoken456"));
    }

    #[test]
    fn does_not_misread_account_line() {
        // Regression: fallback used to return "Account: ..." as the token.
        let content = "Account: 5b56358842553e7b84fa3890dae7944c\nKey: cfat_realkey\n";
        assert_eq!(token_from_content(content).as_deref(), Some("cfat_realkey"));
    }

    #[test]
    fn ignores_example_block() {
        let content = "Account: abc\nKey: tok\n\n==== Example ====\ncurl -H \"Authorization: Bearer tok\"\n";
        assert_eq!(token_from_content(content).as_deref(), Some("tok"));
    }
}
