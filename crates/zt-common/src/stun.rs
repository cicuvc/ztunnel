use std::io::Read;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpListener, TcpSocket};
use tokio::time::timeout;

use thiserror::Error;

const STUN_MAGIC: u32 = 0x2112_A442;
const BINDING_REQUEST_TYPE: u16 = 0x0001;
const XOR_MAPPED_ADDRESS_TYPE: u16 = 0x0020;
const STUN_HEADER_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XorMappedAddress {
    pub ip: std::net::Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Error)]
pub enum StunError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("STUN response too short ({0} bytes)")]
    TooShort(usize),
    #[error("STUN magic cookie mismatch")]
    BadMagic,
    #[error("XOR-MAPPED-ADDRESS not found")]
    NoXorMappedAddress,
    #[error("unsupported address family {0}")]
    UnsupportedFamily(u8),
    #[error("STUN operation timed out")]
    Timeout,
    #[error("transaction ID mismatch")]
    TxIdMismatch,
}

pub fn build_binding_request() -> (Vec<u8>, [u8; 12]) {
    let tx_id = rand_transaction_id();
    let mut buf = Vec::with_capacity(STUN_HEADER_LEN);
    buf.extend_from_slice(&BINDING_REQUEST_TYPE.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    buf.extend_from_slice(&tx_id);
    (buf, tx_id)
}

fn rand_transaction_id() -> [u8; 12] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut id = [0u8; 12];
    for i in 0..12 {
        let shift = (i as u32 * 8) % 64;
        id[i] = ((nanos >> shift) ^ (nanos.wrapping_mul(6364136223846793005 + i as u128) >> 33)) as u8;
    }
    id
}

pub fn parse_xor_mapped_address(data: &[u8]) -> Result<XorMappedAddress, StunError> {
    if data.len() < STUN_HEADER_LEN {
        return Err(StunError::TooShort(data.len()));
    }

    let _msg_type = u16::from_be_bytes([data[0], data[1]]);
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    if magic != STUN_MAGIC {
        return Err(StunError::BadMagic);
    }

    let body_end = STUN_HEADER_LEN + msg_len;
    if data.len() < body_end {
        return Err(StunError::TooShort(data.len()));
    }

    let mut pos = STUN_HEADER_LEN;
    while pos + 4 <= body_end {
        let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + attr_len > body_end {
            break;
        }

        if attr_type == XOR_MAPPED_ADDRESS_TYPE && attr_len >= 8 {
            let family = data[pos + 1];
            if family == 0x01 {
                let x_port = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                let x_ip = u32::from_be_bytes([
                    data[pos + 4],
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                ]);
                let port = x_port ^ (STUN_MAGIC >> 16) as u16;
                let ip_raw = x_ip ^ STUN_MAGIC;
                let ip = std::net::Ipv4Addr::new(
                    ((ip_raw >> 24) & 0xFF) as u8,
                    ((ip_raw >> 16) & 0xFF) as u8,
                    ((ip_raw >> 8) & 0xFF) as u8,
                    (ip_raw & 0xFF) as u8,
                );
                return Ok(XorMappedAddress { ip, port });
            } else {
                return Err(StunError::UnsupportedFamily(family));
            }
        }

        pos += (attr_len + 3) & !3;
    }

    Err(StunError::NoXorMappedAddress)
}

pub async fn discover_mapping(
    local_port: u16,
    stun_addr: SocketAddr,
    timeout_secs: u64,
) -> Result<(TcpListener, XorMappedAddress), StunError> {
    let sock = TcpSocket::new_v4()?;
    sock.set_reuseaddr(true)?;
    sock.bind(SocketAddr::from(([0, 0, 0, 0], local_port)))?;

    let mut stream = timeout(Duration::from_secs(timeout_secs), sock.connect(stun_addr))
        .await
        .map_err(|_| StunError::Timeout)??;

    let (request, tx_id) = build_binding_request();
    stream.write_all(&request).await?;

    let mut buf = Vec::with_capacity(4096);
    {
        let mut tmp = [0u8; 4096];
        let n = timeout(Duration::from_secs(timeout_secs), stream.read(&mut tmp))
            .await
            .map_err(|_| StunError::Timeout)??;
        buf.extend_from_slice(&tmp[..n]);
    }

    if buf.len() < STUN_HEADER_LEN {
        return Err(StunError::TooShort(buf.len()));
    }

    if buf[8..20] != tx_id {
        return Err(StunError::TxIdMismatch);
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let total_needed = STUN_HEADER_LEN + msg_len;
    while buf.len() < total_needed {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    drop(stream);

    let addr = parse_xor_mapped_address(&buf[..total_needed.min(buf.len())])?;

    let listen_sock = TcpSocket::new_v4()?;
    listen_sock.set_reuseaddr(true)?;
    listen_sock.bind(SocketAddr::from(([0, 0, 0, 0], local_port)))?;
    let listener = listen_sock.listen(1024)?;

    Ok((listener, addr))
}

use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;

#[cfg(test)]
mod tests {
    use super::*;

    fn build_stun_response(attr_bytes: &[u8]) -> Vec<u8> {
        let len = 20 + attr_bytes.len();
        let mut buf = Vec::with_capacity(len);
        buf.extend_from_slice(&0x0101u16.to_be_bytes());
        buf.extend_from_slice(&(attr_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        for i in 0..12u8 {
            buf.push(i);
        }
        buf.extend_from_slice(attr_bytes);
        buf
    }

    fn xor_port(port: u16) -> u16 {
        port ^ (STUN_MAGIC >> 16) as u16
    }

    fn xor_ip(ip: u32) -> u32 {
        ip ^ STUN_MAGIC
    }

    fn ip_to_u32(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d])
    }

    #[test]
    fn test_parse_xor_mapped_ipv4() {
        let data = build_stun_response(&[
            0x00, 0x20, 0x00, 0x08, 0x00, 0x01,
            (xor_port(12345) >> 8) as u8,
            (xor_port(12345) & 0xFF) as u8,
            (xor_ip(ip_to_u32(120, 37, 185, 53)) >> 24) as u8,
            (xor_ip(ip_to_u32(120, 37, 185, 53)) >> 16) as u8,
            (xor_ip(ip_to_u32(120, 37, 185, 53)) >> 8) as u8,
            xor_ip(ip_to_u32(120, 37, 185, 53)) as u8,
        ]);

        let result = parse_xor_mapped_address(&data).unwrap();
        assert_eq!(result.port, 12345);
        assert_eq!(result.ip.to_string(), "120.37.185.53");
    }

    #[test]
    fn test_parse_too_short() {
        let data = [0u8; 10];
        assert!(matches!(
            parse_xor_mapped_address(&data),
            Err(StunError::TooShort(_))
        ));
    }

    #[test]
    fn test_parse_bad_magic() {
        let mut data = [0u8; 20];
        data[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        assert!(matches!(
            parse_xor_mapped_address(&data),
            Err(StunError::BadMagic)
        ));
    }

    #[test]
    fn test_parse_no_xor_mapped() {
        let data = build_stun_response(&[]);
        assert!(matches!(
            parse_xor_mapped_address(&data),
            Err(StunError::NoXorMappedAddress)
        ));
    }

    #[test]
    fn test_parse_unknown_attribute_skipped() {
        let data = build_stun_response(&[
            0x99, 0x99, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef,
            0x00, 0x20, 0x00, 0x08, 0x00, 0x01,
            (xor_port(8080) >> 8) as u8,
            (xor_port(8080) & 0xFF) as u8,
            (xor_ip(ip_to_u32(10, 0, 0, 1)) >> 24) as u8,
            (xor_ip(ip_to_u32(10, 0, 0, 1)) >> 16) as u8,
            (xor_ip(ip_to_u32(10, 0, 0, 1)) >> 8) as u8,
            xor_ip(ip_to_u32(10, 0, 0, 1)) as u8,
        ]);

        let result = parse_xor_mapped_address(&data).unwrap();
        assert_eq!(result.port, 8080);
        assert_eq!(result.ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_build_request_roundtrip() {
        let (_req, tx_id) = build_binding_request();
        assert_eq!(tx_id.len(), 12);
        // Transaction ID should not be all zeros
        assert!(tx_id.iter().any(|&b| b != 0));
    }
}
