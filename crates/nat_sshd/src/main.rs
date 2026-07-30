mod gate;
mod keepalive;
pub mod punch;
mod register;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zt_common::types::{EndpointRecord, EndpointStatus};

use crate::gate::Gate;
use crate::punch::PunchConfig;
use crate::register::RegistryClient;

const SUSPECT_THRESHOLD: u32 = 3;
const REINFORCE_THRESHOLD: u32 = 1;
const REGISTER_INTERVAL: Duration = Duration::from_secs(20);

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
        .unwrap_or_else(|_| "https://tapi.cicuvc.top".into());

    let config = PunchConfig { local_port, stun_addr: stun_server };

    let (listener, mapping) = punch::punch_and_listen(&config)
        .await
        .expect("STUN punch failed");
    let mut listener = Some(listener);
    let mut mapping = mapping;
    let mut public_addr: SocketAddr = SocketAddr::new(mapping.ip.into(), mapping.port);
    info!(%public_addr, "gate listening");

    let mut registry = RegistryClient::new(&registry_url, &secret);
    registry.sync_time().await;
    let time_offset = registry.time_offset();

    let gate = Arc::new(Gate::new(target, &secret, time_offset));
    let shutdown = CancellationToken::new();

    let (ka_tx, mut ka_rx) = mpsc::channel::<keepalive::Signal>(16);

    let mut ka_shutdown = shutdown.child_token();
    tokio::spawn(keepalive::run(public_addr, ka_tx.clone(), ka_shutdown.child_token()));

    let record = EndpointRecord {
        ip: mapping.ip.to_string(),
        port: mapping.port,
        ts: unix_now(),
        host_pubkey: load_host_pubkey(),
        status: EndpointStatus::Active,
        nat_type_suspect: false,
    };

    let (record_tx, record_rx) = watch::channel(record);

    let reg_shutdown = shutdown.child_token();
    tokio::spawn(register_loop(registry.new_handle(), record_rx, reg_shutdown));

    info!("accepting connections...");

    let mut failures: u32 = 0;

    loop {
        tokio::select! {
            conn = listener.as_mut().unwrap().accept() => {
                match conn {
                    Ok((stream, addr)) => {
                        info!(remote = %addr.ip(), "incoming connection");
                        let gate = gate.clone();
                        tokio::spawn(async move { gate.handle(stream).await; });
                    }
                    Err(e) => warn!(error = %e, "accept error"),
                }
            }
            Some(signal) = ka_rx.recv() => {
                match signal {
                    keepalive::Signal::Failed => {
                        failures += 1;
                        let threshold = if in_reinforce_window() { REINFORCE_THRESHOLD } else { SUSPECT_THRESHOLD };
                        if failures >= threshold {
                            warn!(failures, "re-punching (suspect state)");

                            // Close old listener so the new STUN socket can bind
                            drop(listener.take());

                            match punch::punch_and_listen(&config).await {
                                Ok((new_l, new_m)) => {
                                    if new_m.port != mapping.port || new_m.ip != mapping.ip {
                                        info!(old = %public_addr, new = %SocketAddr::new(new_m.ip.into(), new_m.port), "NAT mapping changed");
                                    }
                                    mapping = new_m;
                                    public_addr = SocketAddr::new(mapping.ip.into(), mapping.port);
                                    listener = Some(new_l);

                                    // Update shared record & re-register
                                    let mut rec = EndpointRecord {
                                        ip: mapping.ip.to_string(),
                                        port: mapping.port,
                                        ts: unix_now(),
                                        host_pubkey: load_host_pubkey(),
                                        status: EndpointStatus::Active,
                                        nat_type_suspect: false,
                                    };
                                    let _ = registry.register(&rec).await;
                                    rec.ts = unix_now();
                                    let _ = record_tx.send(rec);
                                }
                                Err(e) => {
                                    warn!(error = %e, "re-punch failed");
                                    // The old listener was dropped; re-create one on the same port
                                    match punch::punch_and_listen(&config).await {
                                        Ok((l, m)) => {
                                            mapping = m;
                                            public_addr = SocketAddr::new(mapping.ip.into(), mapping.port);
                                            listener = Some(l);
                                        }
                                        Err(e2) => {
                                            warn!(error = %e2, "recovery punch also failed");
                                        }
                                    }
                                }
                            }

                            // Restart keepalive
                            ka_shutdown.cancel();
                            ka_shutdown = shutdown.child_token();
                            tokio::spawn(keepalive::run(public_addr, ka_tx.clone(), ka_shutdown.child_token()));

                            failures = 0;
                        }
                    }
                    keepalive::Signal::Succeeded => { failures = 0; }
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

fn in_reinforce_window() -> bool {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let day_secs = secs % 86400;
    day_secs >= 64500 && day_secs <= 66000
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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
    Ok(secret.as_bytes().to_vec())
}

fn secret_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".config").join("ztunnel").join("secret")
}

async fn register_loop(registry: RegistryClient, mut record_rx: watch::Receiver<EndpointRecord>, shutdown: CancellationToken) {
    let mut record = record_rx.borrow().clone();
    loop {
        record.ts = unix_now();

        match registry.register(&record).await {
            Ok(()) => tracing::debug!("registration successful"),
            Err(e) => tracing::warn!(error = %e, "registration failed"),
        }

        tokio::select! {
            _ = record_rx.changed() => {
                record = record_rx.borrow().clone();
                tracing::debug!("register_loop: picked up updated endpoint");
            }
            _ = tokio::time::sleep(REGISTER_INTERVAL) => {}
            _ = shutdown.cancelled() => {
                info!("register loop stopped");
                break;
            }
        }
    }
}
