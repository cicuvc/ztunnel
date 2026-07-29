use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use zt_common::token::{self, TokenPurpose};

pub fn run(hostname: &str) -> anyhow::Result<()> {
    let secret = crate::config::Config::load_secret()
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let cfg = crate::config::Config::load();
    let registry = cfg.registry_url();

    // Discover endpoint from registry
    let offset = sync_time(&registry);
    let window = token::adjusted_window(offset);
    let dis_token = token::generate(&secret, TokenPurpose::Discover, window);
    let url = format!("{}/api?w={}&t={}", registry, window, dis_token);

    let response = ureq::get(&url)
        .call()
        .map_err(|e| anyhow::anyhow!("failed to fetch endpoint from {}: {}", registry, e))?;

    let body = response
        .into_body()
        .read_to_string()
        .map_err(|e| anyhow::anyhow!("failed to read response: {}", e))?;
    let data: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("invalid response JSON: {}", e))?;

    if let Some(err) = data.get("error") {
        anyhow::bail!("registry error: {}", err);
    }

    let ip = data["ip"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing ip"))?;
    let port = data["port"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing port"))? as u16;

    let addr: SocketAddr = format!("{}:{}", ip, port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid endpoint {}:{}: {}", ip, port, e))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    // Use adjusted window for gate token as well
    let gate_token = token::generate(&secret, TokenPurpose::Gate, window);
    let line = format!("ZTGATE1 {} {}\r\n", window, gate_token);
    stream.write_all(line.as_bytes())?;

    let (tx, rx) = mpsc::channel::<io::Result<()>>();

    let mut read_stream = stream.try_clone()?;
    let tx_read = tx.clone();
    thread::spawn(move || {
        let mut stdout = io::stdout();
        let mut buf = [0u8; 8192];
        loop {
            match read_stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).is_err() { break; }
                    if stdout.flush().is_err() { break; }
                }
            }
        }
        let _ = tx_read.send(Ok(()));
    });

    let mut write_stream = stream;
    let tx_write = tx;
    thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if write_stream.write_all(&buf[..n]).is_err() { break; }
                    if write_stream.flush().is_err() { break; }
                }
            }
        }
        let _ = tx_write.send(Ok(()));
    });

    let _ = rx.recv();
    Ok(())
}

fn sync_time(registry_url: &str) -> i64 {
    let url = format!("{}/api?cmd=time", registry_url);
    match ureq::get(&url).call() {
        Ok(resp) => {
            if let Ok(body) = resp.into_body().read_to_string() {
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(ts) = data["ts"].as_i64() {
                        let local = token::now_secs();
                        return ts - local;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("[ssh-nat] time sync failed: {}, using local clock", e);
        }
    }
    0
}
