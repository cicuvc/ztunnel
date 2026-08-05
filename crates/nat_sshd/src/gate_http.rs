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

const CORS_PREFLIGHT_HEAD: &[u8] = b"HTTP/1.1 204 No Content\r\n\
Access-Control-Allow-Origin: ";
const CORS_PREFLIGHT_MID: &[u8] = b"\r\n\
Access-Control-Allow-Credentials: true\r\n\
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

        // Send TLS close_notify before dropping, so clients see a clean
        // shutdown instead of an abrupt connection reset.
        let _ = tls_stream.shutdown().await;

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
            let origin = extract_origin(&buf).unwrap_or_else(|| "*".to_string());
            let mut preflight = Vec::with_capacity(256);
            preflight.extend_from_slice(CORS_PREFLIGHT_HEAD);
            preflight.extend_from_slice(origin.as_bytes());
            preflight.extend_from_slice(CORS_PREFLIGHT_MID);
            let _ = stream.write_all(&preflight).await;
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

        // Extract Origin header from the request (for credentials mode CORS).
        let origin = extract_origin(&buf);

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

                if let Err(e) = forward_response_with_cors(stream, &mut server, &origin).await {
                    debug!(error = %e, "http gate: response forward error");
                }
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
/// Extract the Origin header value from an HTTP header block.
fn extract_origin(buf: &[u8]) -> Option<String> {
    let mut pos = 0;
    loop {
        let line_end = buf[pos..].windows(2).position(|w| w == b"\r\n")?;
        let line = &buf[pos..pos + line_end];
        if line.len() > 7 && line[..7].eq_ignore_ascii_case(b"Origin:") {
            let val = String::from_utf8_lossy(&line[7..]).trim().to_string();
            return if val.is_empty() || val == "null" { None } else { Some(val) };
        }
        if line.is_empty() { break; }
        pos += line_end + 2;
    }
    None
}

/// Forward the HTTP response from `server` to `client`, injecting CORS
/// headers if the backend did not send them.
///
/// Reads exactly Content-Length body bytes so a keep-alive backend
/// (which does not close the connection after one response) does not
/// cause the gate to hang waiting for EOF.
async fn forward_response_with_cors<C, S>(
    client: &mut C,
    server: &mut S,
    origin: &Option<String>,
) -> std::io::Result<()>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut head = Vec::with_capacity(4096);
    let mut buf = [0u8; 8192];
    let eoh; // offset of "\r\n\r\n"

    loop {
        let n = server.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "response EOF before headers",
            ));
        }
        head.extend_from_slice(&buf[..n]);
        match head.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(p) => { eoh = p; break; }
            None => {
                if head.len() > 32768 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "response headers too large",
                    ));
                }
            }
        }
    }

    // Parse Content-Length so we only forward the exact body bytes.
    let content_length = parse_content_length(&head[..eoh]);

    let has_cors = head.windows(27).any(|w| {
        w.eq_ignore_ascii_case(b"Access-Control-Allow-Origin")
    });

    let body_part = &head[eoh + 4..];

    // Insert CORS header BEFORE the \r\n\r\n terminator (i.e. in the header block).
    let mut modified = Vec::with_capacity(head.len() + 80);
    modified.extend_from_slice(&head[..eoh]);
    if !has_cors {
        let cors_val = origin.as_deref().unwrap_or("*");
        modified.extend_from_slice(b"\r\nAccess-Control-Allow-Origin: ");
        modified.extend_from_slice(cors_val.as_bytes());
        if origin.is_some() {
            modified.extend_from_slice(b"\r\nAccess-Control-Allow-Credentials: true");
        }
    }
    modified.extend_from_slice(&head[eoh..]); // \r\n\r\n + any body bytes already read

    client.write_all(&modified).await?;

    // Forward the body: bytes already read in head + remaining Content-Length.
    let mut remaining_body = content_length.saturating_sub(body_part.len() as u64);
    if !body_part.is_empty() {
        client.write_all(body_part).await?;
    }
    while remaining_body > 0 {
        let want = (remaining_body.min(8192)) as usize;
        let n = server.read(&mut buf[..want]).await?;
        if n == 0 {
            break;
        }
        client.write_all(&buf[..n]).await?;
        remaining_body -= n as u64;
    }

    // No client→server copy: an idle GET must not block the gate.
    Ok(())
}

fn parse_content_length(headers: &[u8]) -> u64 {
    let mut pos = 0;
    while pos + 2 <= headers.len() {
        let line_end = match headers[pos..].windows(2).position(|w| w == b"\r\n") {
            Some(i) => i,
            None => break,
        };
        let line = &headers[pos..pos + line_end];
        if line.len() > 15 && line[..15].eq_ignore_ascii_case(b"content-length:") {
            let val: String = line[15..].iter().map(|&b| b as char).filter(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = val.parse::<u64>() {
                return n;
            }
        }
        pos += line_end + 2;
    }
    0
}

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
