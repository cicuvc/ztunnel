use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use zt_common::token::{self, TokenPurpose};

use crate::gate::BanList;

const READ_TIMEOUT: Duration = Duration::from_secs(3);
const TLS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADER_BYTES: usize = 16384;
const GATE_HEADER: &[u8] = b"x-zt-gate:";

const CORS_PREFLIGHT_RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\n\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n\
Access-Control-Allow-Headers: *\r\n\
Access-Control-Max-Age: 86400\r\n\
Content-Length: 0\r\n\
\r\n";

pub struct HttpGate {
    target: SocketAddr,
    secret: Vec<u8>,
    bans: BanList,
    time_offset: i64,
    tls: TlsAcceptor,
}

impl HttpGate {
    pub fn new(target: SocketAddr, secret: &[u8], time_offset: i64, tls: TlsAcceptor) -> Self {
        Self {
            target,
            secret: secret.to_vec(),
            bans: BanList::new(),
            time_offset,
            tls,
        }
    }

    pub async fn handle(self: &Arc<Self>, stream: TcpStream) {
        let peer = stream.peer_addr().ok();
        let ip = peer.map(|p| p.ip());

        if let Some(ip) = ip {
            if self.bans.is_banned(ip).await {
                debug!(%ip, "banned ip, dropping silently");
                drop(stream);
                return;
            }
        }

        // TLS first.  Anything that is not a TLS ClientHello (scanners,
        // our own cleartext ZTKEEPALIVE1 probes) dies here, silently,
        // without touching the ban list.
        let tls_result = timeout(TLS_TIMEOUT, self.tls.accept(stream)).await;
        let mut tls_stream = match tls_result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                debug!(error = %e, "TLS handshake failed, dropping");
                return;
            }
            Err(_) => {
                debug!("TLS handshake timeout, dropping");
                return;
            }
        };

        let result = self.gate_connection(&mut tls_stream).await;

        if let Some(ip) = ip {
            match result {
                Err(()) => self.bans.record_failure(ip).await,
                Ok(true) => self.bans.clear_failures(ip).await,
                Ok(false) => {}
            }
        }
    }

    async fn gate_connection<S>(&self, stream: &mut S) -> Result<bool, ()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let buf = match read_headers(stream).await {
            Some(b) => b,
            None => return Err(()),
        };

        // CORS preflight never carries custom headers — answer it directly.
        if buf.starts_with(b"OPTIONS ") {
            debug!("CORS preflight, answering directly");
            if stream.write_all(CORS_PREFLIGHT_RESPONSE).await.is_err() {
                return Err(());
            }
            return Ok(false);
        }

        let (header_range, window, gate_token) = match find_gate_header(&buf) {
            Some(v) => v,
            None => {
                debug!("no gate header, dropping");
                return Err(());
            }
        };

        let server_window = token::adjusted_window(self.time_offset);
        if !token::verify_synced(&self.secret, TokenPurpose::Gate, &gate_token, window, server_window) {
            debug!("gate token rejected");
            return Err(());
        }

        debug!("gate token accepted");
        info!(target = %self.target, "http gate: bridging to target");

        // Strip the gate header line, forward the rest verbatim.
        let mut forwarded = Vec::with_capacity(buf.len());
        forwarded.extend_from_slice(&buf[..header_range.0]);
        forwarded.extend_from_slice(&buf[header_range.1..]);

        match TcpStream::connect(self.target).await {
            Ok(mut server) => {
                if let Err(e) = server.write_all(&forwarded).await {
                    warn!(error = %e, "http gate: failed to forward request head");
                    return Err(());
                }
                tokio::io::copy_bidirectional(stream, &mut server)
                    .await
                    .ok();
            }
            Err(e) => {
                warn!(error = %e, "http gate: failed to connect to target");
                let _ = stream.shutdown().await;
            }
        }

        info!(target = %self.target, "http gate: connection closed");
        Ok(true)
    }
}

/// Build a TLS acceptor from PEM cert chain / key files, ALPN http/1.1 only
/// (h2's connection preface would break HTTP header inspection).
pub fn build_tls_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<TlsAcceptor> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", cert_path, e))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", key_path, e))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse cert PEM: {}", e))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path);
    }

    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| anyhow::anyhow!("failed to parse key PEM: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path))?;

    let mut config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("invalid cert/key pair: {}", e))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn read_headers<S>(stream: &mut S) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];

    let result = timeout(READ_TIMEOUT, async {
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                return Some(buf);
            }
            if buf.len() >= MAX_HEADER_BYTES {
                return None;
            }
        }
    })
    .await;

    match result {
        Ok(v) => v,
        Err(_) => {
            debug!("http gate read timeout");
            None
        }
    }
}

/// Locate `X-ZT-Gate: <window> <token>` (case-insensitive) in the header
/// block.  Returns ((line_start, line_end_incl_crlf), window, token).
fn find_gate_header(buf: &[u8]) -> Option<((usize, usize), i64, String)> {
    let mut pos = 0;
    while pos + 2 <= buf.len() {
        let line_end = buf[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|i| pos + i)?;
        let line = &buf[pos..line_end];

        if line.len() >= GATE_HEADER.len()
            && line[..GATE_HEADER.len()].eq_ignore_ascii_case(GATE_HEADER)
        {
            let value = String::from_utf8_lossy(&line[GATE_HEADER.len()..]);
            let mut parts = value.split_whitespace();
            let window: i64 = parts.next()?.parse().ok()?;
            let gate_token = parts.next()?.to_string();
            return Some(((pos, line_end + 2), window, gate_token));
        }

        if line.is_empty() {
            break; // end of headers
        }
        pos = line_end + 2;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_gate_header() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-ZT-Gate: 12345 abcdef\r\n\r\n";
        let ((start, end), window, tok) = find_gate_header(req).unwrap();
        assert_eq!(window, 12345);
        assert_eq!(tok, "abcdef");
        assert_eq!(&req[start..end], b"X-ZT-Gate: 12345 abcdef\r\n");
    }

    #[test]
    fn test_find_gate_header_case_insensitive() {
        let req = b"GET / HTTP/1.1\r\nx-zt-GATE: 99 deadbeef\r\n\r\n";
        let (_, window, tok) = find_gate_header(req).unwrap();
        assert_eq!(window, 99);
        assert_eq!(tok, "deadbeef");
    }

    #[test]
    fn test_no_gate_header() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(find_gate_header(req).is_none());
    }

    #[test]
    fn test_gate_header_bad_window() {
        let req = b"GET / HTTP/1.1\r\nX-ZT-Gate: notanumber tok\r\n\r\n";
        assert!(find_gate_header(req).is_none());
    }

    #[test]
    fn test_strip_keeps_rest_intact() {
        let req = b"GET /x HTTP/1.1\r\nX-ZT-Gate: 1 t\r\nHost: h\r\n\r\nBODY";
        let ((start, end), _, _) = find_gate_header(req).unwrap();
        let mut forwarded = Vec::new();
        forwarded.extend_from_slice(&req[..start]);
        forwarded.extend_from_slice(&req[end..]);
        assert_eq!(forwarded, b"GET /x HTTP/1.1\r\nHost: h\r\n\r\nBODY");
    }
}
