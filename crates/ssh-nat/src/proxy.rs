use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use zt_common::token::{self, TokenPurpose};

pub fn run(ip: &str, port: u16) -> anyhow::Result<()> {
    let secret = crate::config::Config::load_secret()
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let addr: SocketAddr = format!("{}:{}", ip, port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid address: {}", e))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    // Only write timeout; reads can block indefinitely (idle SSH connections).
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let window = token::current_window();
    let token = token::generate(&secret, TokenPurpose::Gate, window);
    let line = format!("ZTGATE1 {} {}\r\n", window, token);
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
                    if stdout.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    if stdout.flush().is_err() {
                        break;
                    }
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
                    if write_stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    if write_stream.flush().is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tx_write.send(Ok(()));
    });

    let _ = rx.recv();
    Ok(())
}
