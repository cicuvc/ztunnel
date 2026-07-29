use std::net::SocketAddr;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub async fn spawn_relay(mut client: TcpStream, target: SocketAddr) {
    let peer = client.peer_addr().ok();

    info!(target = %target, remote = ?peer, "relay: new connection");

    match TcpStream::connect(target).await {
        Ok(mut server) => {
            if let Err(e) = copy_bidirectional(&mut client, &mut server).await {
                debug!(error = %e, "relay: connection closed");
            }
        }
        Err(e) => {
            warn!(
                target = %target,
                error = %e,
                "relay: failed to connect to target"
            );
            let _ = client.shutdown().await;
        }
    }

    info!(target = %target, remote = ?peer, "relay: connection closed");
}
