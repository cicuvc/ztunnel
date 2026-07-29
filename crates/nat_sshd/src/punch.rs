use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;
use zt_common::stun::{discover_mapping, XorMappedAddress};

pub struct PunchConfig {
    pub local_port: u16,
    pub stun_addr: SocketAddr,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            local_port: 2222,
            stun_addr: SocketAddr::from(([188, 166, 223, 240], 3478)),
        }
    }
}

pub async fn punch_and_listen(
    config: &PunchConfig,
) -> anyhow::Result<(TcpListener, XorMappedAddress)> {
    info!(
        local_port = config.local_port,
        stun_server = %config.stun_addr,
        "punching NAT hole via STUN"
    );

    let (listener, mapping) = discover_mapping(config.local_port, config.stun_addr, 5).await?;

    info!(
        local_port = config.local_port,
        public_ip = %mapping.ip,
        public_port = mapping.port,
        "NAT mapping discovered"
    );

    Ok((listener, mapping))
}
