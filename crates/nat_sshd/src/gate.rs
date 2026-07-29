use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
}

struct BanEntry {
    count: u32,
    last_failure: Instant,
}

impl Gate {
    pub fn new(target: SocketAddr, secret: &[u8]) -> Self {
        Self {
            target,
            secret: secret.to_vec(),
            bans: Arc::new(Mutex::new(HashMap::new())),
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
            if result.is_err() {
                self.record_failure(ip).await;
            }
        }
    }

    async fn gate_connection(self: &Arc<Self>, mut stream: TcpStream) -> Result<(), ()> {
        let mut line = String::new();
        {
            let mut reader = BufReader::new(&mut stream);
            timeout(READ_TIMEOUT, reader.read_line(&mut line))
                .await
                .map_err(|_| {
                    debug!("gate read timeout");
                })?
                .map_err(|e| {
                    debug!(error = %e, "gate read error");
                })?;
        }

        let line = line.trim();
        if !self.verify_line(line) {
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
        Ok(())
    }

    fn verify_line(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() != 3 || parts[0] != "ZTGATE1" {
            return false;
        }

        let window: i64 = match parts[1].parse() {
            Ok(w) => w,
            Err(_) => return false,
        };

        let token = parts[2];
        token::verify(&self.secret, TokenPurpose::Gate, token, window)
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
}
