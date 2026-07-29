use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

// NAT TCP mapping idle timeout is ~5-8s.  Keepalive must fire before that.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);
const INITIAL_RETRY: Duration = Duration::from_millis(300);
const MAX_RETRY: Duration = Duration::from_secs(5);

pub async fn spawn_hairpin_keepalive(
    public_addr: SocketAddr,
    shutdown: CancellationToken,
) {
    let mut retry = INITIAL_RETRY;

    info!(
        target_addr = %public_addr,
        "hairpin keepalive started"
    );

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("hairpin keepalive stopped");
                break;
            }
            _ = sleep(retry) => {}
        }

        match TcpStream::connect(public_addr).await {
            Ok(mut stream) => {
                // SYN-ACK from the listener port (2222) refreshes the NAT mapping.
                // Gate recognizes ZTKEEPALIVE1 and drops silently (no ban count).
                if let Err(e) = stream.write_all(b"ZTKEEPALIVE1\n").await {
                    debug!(error = %e, "keepalive write failed");
                }
                drop(stream);
                retry = HEARTBEAT_INTERVAL;
                debug!("hairpin keepalive succeeded");
            }
            Err(e) => {
                warn!(
                    error = %e,
                    retry_ms = retry.as_millis(),
                    "hairpin keepalive failed"
                );
                retry = (retry * 3 / 2).min(MAX_RETRY);
            }
        }
    }
}
