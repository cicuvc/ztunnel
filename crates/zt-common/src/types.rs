use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndpointStatus {
    Active,
    Down,
}

fn default_service() -> String {
    "ssh".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointRecord {
    pub ip: String,
    pub port: u16,
    pub ts: i64,
    pub host_pubkey: String,
    pub status: EndpointStatus,
    #[serde(default)]
    pub nat_type_suspect: bool,
    #[serde(default = "default_service")]
    pub service: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let record = EndpointRecord {
            ip: "120.37.185.53".into(),
            port: 12345,
            ts: 1722000000,
            host_pubkey: "ssh-ed25519 AAAA...".into(),
            status: EndpointStatus::Active,
            nat_type_suspect: false,
            service: "ssh".into(),
        };

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: EndpointRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn test_down_status() {
        let record = EndpointRecord {
            ip: "10.0.0.1".into(),
            port: 2222,
            ts: 1000,
            host_pubkey: "".into(),
            status: EndpointStatus::Down,
            nat_type_suspect: true,
            service: "ssh".into(),
        };

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: EndpointRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
        assert!(json.contains("nat_type_suspect"));
    }

    #[test]
    fn test_missing_optional_field() {
        let json = r#"{"ip":"10.0.0.1","port":2222,"ts":1000,"host_pubkey":"","status":"active"}"#;
        let record: EndpointRecord = serde_json::from_str(json).unwrap();
        assert!(!record.nat_type_suspect);
        assert_eq!(record.service, "ssh");
    }
}
