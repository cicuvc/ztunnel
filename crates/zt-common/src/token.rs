use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use std::str::FromStr;

type HmacSha256 = Hmac<Sha256>;

const TOKEN_CHARS: usize = 32;
const WINDOW_SECS: i64 = 30;
const WINDOW_TOLERANCE: i64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenPurpose {
    Register,
    Discover,
    Gate,
}

impl fmt::Display for TokenPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenPurpose::Register => write!(f, "register"),
            TokenPurpose::Discover => write!(f, "discover"),
            TokenPurpose::Gate => write!(f, "gate"),
        }
    }
}

impl FromStr for TokenPurpose {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "register" => Ok(TokenPurpose::Register),
            "discover" => Ok(TokenPurpose::Discover),
            "gate" => Ok(TokenPurpose::Gate),
            _ => Err(format!("unknown purpose: {s}")),
        }
    }
}

pub fn current_window() -> i64 {
    now_secs() / WINDOW_SECS
}

pub fn adjusted_window(offset_secs: i64) -> i64 {
    (now_secs() + offset_secs) / WINDOW_SECS
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn generate(secret: &[u8], purpose: TokenPurpose, window: i64) -> String {
    let msg = format!("{}:{}", purpose, window);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(msg.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    hex::encode(&code_bytes[..TOKEN_CHARS / 2])[..TOKEN_CHARS].to_string()
}

pub fn verify(secret: &[u8], purpose: TokenPurpose, token: &str, window: i64) -> bool {
    for offset in -WINDOW_TOLERANCE..=WINDOW_TOLERANCE {
        let candidate = generate(secret, purpose, window + offset);
        // constant-time comparison
        use subtle::ConstantTimeEq;
        let eq = token.as_bytes().ct_eq(candidate.as_bytes());
        if eq.into() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn test_golden_register() {
        let token = generate(TEST_SECRET, TokenPurpose::Register, 1000000);
        assert_eq!(token.len(), TOKEN_CHARS);
        assert_eq!(token, "6cb2fbc4a51a0132a2909d6110251362");
    }

    #[test]
    fn test_golden_discover() {
        let token = generate(TEST_SECRET, TokenPurpose::Discover, 1000000);
        assert_eq!(token.len(), TOKEN_CHARS);
        assert_eq!(token, "210a9b69b8ffce133e9d2d96c63262b0");
    }

    #[test]
    fn test_golden_gate() {
        let token = generate(TEST_SECRET, TokenPurpose::Gate, 1000000);
        assert_eq!(token.len(), TOKEN_CHARS);
        assert_eq!(token, "0a5b30e06bfa21db06f164a4c3535665");
    }

    #[test]
    fn test_verify_exact_window() {
        let token = generate(TEST_SECRET, TokenPurpose::Gate, 5000);
        assert!(verify(TEST_SECRET, TokenPurpose::Gate, &token, 5000));
    }

    #[test]
    fn test_verify_tolerance_plus_one() {
        let token = generate(TEST_SECRET, TokenPurpose::Gate, 4999);
        assert!(verify(TEST_SECRET, TokenPurpose::Gate, &token, 5000));
    }

    #[test]
    fn test_verify_tolerance_minus_one() {
        let token = generate(TEST_SECRET, TokenPurpose::Gate, 5001);
        assert!(verify(TEST_SECRET, TokenPurpose::Gate, &token, 5000));
    }

    #[test]
    fn test_verify_outside_tolerance() {
        let token = generate(TEST_SECRET, TokenPurpose::Gate, 4998);
        assert!(!verify(TEST_SECRET, TokenPurpose::Gate, &token, 5000));
    }

    #[test]
    fn test_purpose_mismatch() {
        let token = generate(TEST_SECRET, TokenPurpose::Register, 5000);
        assert!(!verify(TEST_SECRET, TokenPurpose::Discover, &token, 5000));
    }

    #[test]
    fn test_wrong_secret() {
        let token = generate(b"wrong-secret-32-bytes-long!!!", TokenPurpose::Gate, 5000);
        assert!(!verify(TEST_SECRET, TokenPurpose::Gate, &token, 5000));
    }

    #[test]
    fn test_token_length() {
        let token = generate(TEST_SECRET, TokenPurpose::Register, 0);
        assert_eq!(token.len(), 32);
    }

    #[test]
    fn test_current_window() {
        let w = current_window();
        assert!(w > 0);
    }

    #[test]
    fn test_adjusted_window_zero_offset() {
        assert_eq!(adjusted_window(0), current_window());
    }

    #[test]
    fn test_adjusted_window_positive_offset() {
        let now = now_secs();
        let expected = (now + 120) / 30;
        assert_eq!(adjusted_window(120), expected);
    }

    #[test]
    fn test_adjusted_window_negative_offset() {
        let now = now_secs();
        let expected = (now - 120) / 30;
        assert_eq!(adjusted_window(-120), expected);
    }
}
