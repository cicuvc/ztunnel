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
use tokio::sync::mpsc;
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

    let (mut listener, mapping) = punch::punch_and_listen(&config)
        .await
        .expect("STUN punch failed");
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
    tokio::spawn(keepalive::run(public_addr, ka_tx.clone(), ka_shutdown.child_token(), in_reinforce_window()));

    let mut record = EndpointRecord {
        ip: mapping.ip.to_string(),
        port: mapping.port,
        ts: unix_now(),
        host_pubkey: load_host_pubkey(),
        status: EndpointStatus::Active,
        nat_type_suspect: false,
    };

    let reg_shutdown = shutdown.child_token();
    let reg_record = record.clone();
    tokio::spawn(register_loop(registry.new_handle(), reg_record, reg_shutdown));

    info!("accepting connections...");

    let mut failures: u32 = 0;

    loop {
        tokio::select! {
            conn = listener.accept() => {
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
                            repunch(&config, &mut listener, &mut mapping, &mut public_addr,
                                    &shutdown, &mut ka_shutdown, &ka_tx,
                                    &mut registry, &mut record).await;
                            failures = 0;
                        }
                    }
                    keepalive::Signal::Succeeded => {
                        failures = 0;
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

async fn repunch(
    config: &PunchConfig,
    _listener: &mut tokio::net::TcpListener,
    mapping: &mut zt_common::stun::XorMappedAddress,
    public_addr: &mut SocketAddr,
    shutdown: &CancellationToken,
    ka_shutdown: &mut CancellationToken,
    ka_tx: &mpsc::Sender<keepalive::Signal>,
    registry: &mut RegistryClient,
    record: &mut EndpointRecord,
) {
    info!("re-punching NAT hole...");

    // Punch again on the same local port.  SO_REUSEADDR allows the new
    // STUN socket to bind while the old listener is still active.
    let (new_listener, new_mapping) = match punch::punch_and_listen(config).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "re-punch failed, will retry via keepalive");
            return;
        }
    };

    // Keep the OLD listener — it survives because SO_REUSEADDR lets
    // both sockets coexist.  The NAT now routes to the new mapping.
    drop(new_listener);

    if new_mapping.port == mapping.port && new_mapping.ip == mapping.ip {
        info!("mapping unchanged after re-punch");
        // Still re-register to refresh timestamp
    } else {
        info!(
            old = %public_addr,
            new = %SocketAddr::new(new_mapping.ip.into(), new_mapping.port),
            "NAT mapping changed (BRAS reset?)"
        );
        *mapping = new_mapping;
        *public_addr = SocketAddr::new(mapping.ip.into(), mapping.port);
    }

    record.ip = mapping.ip.to_string();
    record.port = mapping.port;
    record.ts = unix_now();

    // Re-register immediately
    match registry.register(record).await {
        Ok(()) => info!("re-registration succeeded"),
        Err(e) => warn!(error = %e, "re-registration failed"),
    }

    // Restart keepalive with the (possibly new) address
    ka_shutdown.cancel();
    *ka_shutdown = shutdown.child_token();
    tokio::spawn(keepalive::run(
        *public_addr,
        ka_tx.clone(),
        ka_shutdown.child_token(),
        in_reinforce_window(),
    ));

    info!("re-punch complete, back to ACTIVE");
}

fn in_reinforce_window() -> bool {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // UTC 17:55–18:20 = CST 01:55–02:20 (BRAS reset window)
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

async fn register_loop(registry: RegistryClient, mut record: EndpointRecord, shutdown: CancellationToken) {
    loop {
        record.ts = unix_now();

        match registry.register(&record).await {
            Ok(()) => tracing::debug!("registration successful"),
            Err(e) => tracing::warn!(error = %e, "registration failed"),
        }

        tokio::select! {
            _ = tokio::time::sleep(REGISTER_INTERVAL) => {}
            _ = shutdown.cancelled() => {
                info!("register loop stopped");
                break;
            }
        }
    }
}
