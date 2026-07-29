mod gate;
mod keepalive;
pub mod punch;
mod register;
mod relay;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::info;
use zt_common::types::{EndpointRecord, EndpointStatus};

use crate::gate::Gate;
use crate::punch::PunchConfig;
use crate::register::RegistryClient;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nat_sshd=info".into()),
        )
        .init();

    info!("nat-sshd v{}", env!("CARGO_PKG_VERSION"));

    let secret = load_secret().expect("failed to load secret");
    let local_port: u16 = std::env::var("LOCAL_PORT")
        .unwrap_or_else(|_| "2222".into())
        .parse()
        .expect("invalid LOCAL_PORT");
    let target: SocketAddr = std::env::var("TARGET")
        .unwrap_or_else(|_| "127.0.0.1:22".into())
        .parse()
        .expect("invalid TARGET");
    let stun_server_str = std::env::var("STUN_SERVER")
        .unwrap_or_else(|_| "stunserver2025.stunprotocol.org:3478".into());
    let stun_server: SocketAddr = resolve_v4(&stun_server_str);
    let registry_url = std::env::var("REGISTRY_URL")
        .unwrap_or_else(|_| "https://tapi3.cicuvc.top".into());

    let config = PunchConfig {
        local_port,
        stun_addr: stun_server,
    };

    let (listener, mapping) = punch::punch_and_listen(&config)
        .await
        .expect("STUN punch failed");

    let public_addr: SocketAddr = SocketAddr::new(mapping.ip.into(), mapping.port);
    info!(%public_addr, "gate listening");

    let gate = Arc::new(Gate::new(target, &secret));
    let shutdown = CancellationToken::new();

    let ka_shutdown = shutdown.child_token();
    tokio::spawn(keepalive::spawn_hairpin_keepalive(public_addr, ka_shutdown));

    let mut registry = RegistryClient::new(&registry_url, &secret);
    registry.sync_time().await;
    let record = EndpointRecord {
        ip: mapping.ip.to_string(),
        port: mapping.port,
        ts: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        host_pubkey: load_host_pubkey(),
        status: EndpointStatus::Active,
        nat_type_suspect: false,
    };

    let reg_record = record.clone();
    let reg_shutdown = shutdown.child_token();
    tokio::spawn(register_loop(registry, reg_record, reg_shutdown));

    info!("accepting connections...");

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        info!(remote = %addr.ip(), "incoming connection");
                        let gate = gate.clone();
                        tokio::spawn(async move {
                            gate.handle(stream).await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept error");
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutting down...");
                shutdown.cancel();
                break;
            }
        }
    }
}

fn resolve_v4(addr: &str) -> SocketAddr {
    if let Ok(ip) = addr.parse::<SocketAddr>() {
        return ip;
    }
    std::net::ToSocketAddrs::to_socket_addrs(addr)
        .expect("failed to resolve address")
        .find(|a| a.is_ipv4())
        .expect("no IPv4 address found")
}

fn load_host_pubkey() -> String {
    for path in [
        "/etc/ssh/ssh_host_ed25519_key.pub",
        "/etc/ssh/ssh_host_rsa_key.pub",
        "/etc/ssh/ssh_host_ecdsa_key.pub",
    ] {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Some(line) = content.lines().next() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    return trimmed.to_string();
                }
            }
        }
    }
    "(unknown)".into()
}

fn load_secret() -> Result<Vec<u8>, String> {
    let path = secret_path();
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    let secret = content.trim().to_string();
    if secret.len() != 64 {
        return Err(format!("expected 64 hex chars, got {} chars", secret.len()));
    }
    // Return the hex string as raw bytes — Node.js side uses the same
    // hex string directly as the HMAC key.  Both sides must agree.
    Ok(secret.as_bytes().to_vec())
}

fn secret_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".config").join("ztunnel").join("secret")
}

async fn register_loop(registry: RegistryClient, mut record: EndpointRecord, shutdown: CancellationToken) {
    loop {
        record.ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        match registry.register(&record).await {
            Ok(()) => tracing::debug!("registration successful"),
            Err(e) => tracing::warn!(error = %e, "registration failed"),
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(20)) => {}
            _ = shutdown.cancelled() => {
                info!("register loop stopped");
                break;
            }
        }
    }
}
