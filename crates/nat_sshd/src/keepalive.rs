use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use tracing::debug;

// NAT TCP mapping idle timeout is ~5-8s.  Keepalive must fire before that.
const INTERVAL_NORMAL: Duration = Duration::from_secs(3);
const INTERVAL_REINFORCE: Duration = Duration::from_secs(1);
const INITIAL_RETRY: Duration = Duration::from_millis(300);
const MAX_RETRY: Duration = Duration::from_secs(5);
// A dead mapping makes the hairpin SYN be silently dropped by the NAT; the
// plain connect would block until the OS TCP timeout (~2 min).  Bound it so
// a dead mapping yields a fast failure → repunch instead of a silent hang.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub enum Signal {
    Succeeded,
    Failed,
}

/// Connect-then-close keepalive.  The TCP handshake's SYN-ACK from the
/// listener port (8443) is outbound traffic through the NAT mapping, which
/// refreshes the idle timer.  We intentionally send no payload: a persistent
/// connection does not survive the HTTP gate (it demands TLS + HTTP
/// headers), so we simply re-establish the handshake on an interval.
pub async fn run(
    public_addr: SocketAddr,
    tx: mpsc::Sender<Signal>,
    shutdown: CancellationToken,
) {
    let mut retry = INITIAL_RETRY;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = sleep(retry) => {}
        }

        match timeout(CONNECT_TIMEOUT, TcpStream::connect(public_addr)).await {
            Ok(Ok(stream)) => {
                drop(stream); // handshake already refreshed the mapping
                retry = if in_reinforce_window() { INTERVAL_REINFORCE } else { INTERVAL_NORMAL };
                let _ = tx.send(Signal::Succeeded).await;
            }
            Ok(Err(e)) => {
                debug!(error = %e, "keepalive connect failed");
                retry = (retry * 3 / 2).min(MAX_RETRY);
                let _ = tx.send(Signal::Failed).await;
            }
            Err(_) => {
                debug!("keepalive connect timed out");
                retry = (retry * 3 / 2).min(MAX_RETRY);
                let _ = tx.send(Signal::Failed).await;
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
