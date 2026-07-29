use std::path::PathBuf;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub registry_url: Option<String>,
}

impl Config {
    pub fn load() -> Self {
        let path = config_path();
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str(&content) {
                return cfg;
            }
        }
        Config { registry_url: None }
    }

    pub fn registry_url(&self) -> String {
        if let Ok(url) = std::env::var("ZT_REGISTRY") {
            if !url.is_empty() {
                return url;
            }
        }
        self.registry_url
            .clone()
            .unwrap_or_else(|| "https://tapi3.cicuvc.top".to_string())
    }

    pub fn secret_path() -> PathBuf {
        dirs().join("secret")
    }

    pub fn load_secret() -> Result<Vec<u8>, String> {
        let path = Self::secret_path();
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
        let secret = content.trim().to_string();
        if secret.len() != 64 {
            return Err(format!("secret must be 64 hex chars, got {} chars", secret.len()));
        }
        // Return the hex string as raw bytes — Node.js side uses the same
        // hex string directly as the HMAC key.  Both sides must agree.
        Ok(secret.as_bytes().to_vec())
    }
}

fn dirs() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".config").join("ztunnel")
}

fn config_path() -> PathBuf {
    dirs().join("config.toml")
}
