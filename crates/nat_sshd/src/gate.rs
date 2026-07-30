use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use zt_common::token::{self, TokenPurpose};

const READ_TIMEOUT: Duration = Duration::from_secs(3);
const BAN_THRESHOLD: u32 = 5;
const BAN_DURATION: Duration = Duration::from_secs(3600);

pub struct Gate {
    target: SocketAddr,
    secret: Vec<u8>,
    bans: Arc<Mutex<HashMap<IpAddr, BanEntry>>>,
    time_offset: i64,
}

struct BanEntry {
    count: u32,
    last_failure: Instant,
}

impl Gate {
    pub fn new(target: SocketAddr, secret: &[u8], time_offset: i64) -> Self {
        Self {
            target,
            secret: secret.to_vec(),
            bans: Arc::new(Mutex::new(HashMap::new())),
            time_offset,
        }
    }

    pub async fn handle(self: &Arc<Self>, stream: TcpStream) {
        let peer = stream.peer_addr().ok();
        let ip = peer.map(|p| p.ip());

        if let Some(ip) = ip {
            if self.is_banned(ip).await {
                debug!(%ip, "banned ip, dropping silently");
                drop(stream);
                return;
            }
        }

        let result = self.gate_connection(stream).await;

        if let Some(ip) = ip {
            match result {
                Err(()) => self.record_failure(ip).await,
                Ok(true) => self.clear_failures(ip).await,
                Ok(false) => {}
            }
        }
    }

    async fn gate_connection(self: &Arc<Self>, mut stream: TcpStream) -> Result<bool, ()> {
        let first_line = {
            let mut line = String::new();
            let mut reader = BufReader::new(&mut stream);
            timeout(READ_TIMEOUT, reader.read_line(&mut line))
                .await
                .map_err(|_| debug!("gate read timeout"))?
                .map_err(|e| debug!(error = %e, "gate read error"))?;
            // Drop reader to release the borrow on stream
            drop(reader);
            line
        };

        let trimmed = first_line.trim();

        if trimmed == "ZTKEEPALIVE1" {
            // Persistent keepalive: keep reading heartbeats until EOF.
            debug!("keepalive persistent connection established");
            let mut buf = [0u8; 128];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {} // discard heartbeat bytes
                }
            }
            debug!("keepalive connection closed");
            return Ok(false);
        }

        if !self.verify_line(trimmed) {
            debug!("gate token rejected");
            return Err(());
        }

        debug!("gate token accepted");

        let peer = stream.peer_addr().ok();
        info!(target = %self.target, remote = ?peer, "gate: bridging to target");

        match TcpStream::connect(self.target).await {
            Ok(mut server) => {
                tokio::io::copy_bidirectional(&mut stream, &mut server)
                    .await
                    .ok();
            }
            Err(e) => {
                warn!(error = %e, "gate: failed to connect to target");
                let _ = stream.shutdown().await;
            }
        }

        info!(target = %self.target, remote = ?peer, "gate: connection closed");
        Ok(true)
    }

    fn verify_line(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() != 3 || parts[0] != "ZTGATE1" {
            return false;
        }

        let client_window: i64 = match parts[1].parse() {
            Ok(w) => w,
            Err(_) => return false,
        };

        let token = parts[2];
        let server_window = token::adjusted_window(self.time_offset);
        token::verify_synced(&self.secret, TokenPurpose::Gate, token, client_window, server_window)
    }

    async fn is_banned(&self, ip: IpAddr) -> bool {
        let bans = self.bans.lock().await;
        bans.get(&ip)
            .map(|e| e.count >= BAN_THRESHOLD && e.last_failure.elapsed() < BAN_DURATION)
            .unwrap_or(false)
    }

    async fn record_failure(&self, ip: IpAddr) {
        let mut bans = self.bans.lock().await;
        let entry = bans.entry(ip).or_insert(BanEntry {
            count: 0,
            last_failure: Instant::now(),
        });
        entry.count += 1;
        entry.last_failure = Instant::now();

        if entry.count >= BAN_THRESHOLD {
            warn!(%ip, count = entry.count, "ip banned for 1h");
        }
    }

    async fn clear_failures(&self, ip: IpAddr) {
        let mut bans = self.bans.lock().await;
        bans.remove(&ip);
    }
}
