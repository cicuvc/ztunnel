use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::debug;

const INTERVAL_NORMAL: Duration = Duration::from_secs(3);
const INTERVAL_REINFORCE: Duration = Duration::from_secs(1);
const INITIAL_RETRY: Duration = Duration::from_millis(300);
const MAX_RETRY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub enum Signal {
    Succeeded,
    Failed,
}

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

        match TcpStream::connect(public_addr).await {
            Ok(mut stream) => {
                // Persistent connection: send heartbeats until the stream dies.
                loop {
                    let interval = if in_reinforce_window() { INTERVAL_REINFORCE } else { INTERVAL_NORMAL };

                    if let Err(e) = stream.write_all(b"ZTKEEPALIVE1\n").await {
                        debug!(error = %e, "keepalive write failed, reconnecting");
                        break;
                    }
                    let _ = tx.send(Signal::Succeeded).await;
                    retry = interval;

                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = sleep(interval) => {}
                    }
                }
            }
            Err(_) => {
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
