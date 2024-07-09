use chrono::{offset::Utc, TimeZone};
use sha2::{Digest, Sha256};

pub fn human_option_str(x: Option<&String>) -> &str {
    if let Some(x) = x {
        x.as_str()
    } else {
        "-"
    }
}

pub fn now() -> i64 {
    let now = chrono::offset::Utc::now();
    now.timestamp()
}

pub fn format_datetime(timestamp: i64) -> String {
    let utc = Utc.timestamp_opt(timestamp, 0).unwrap();
    utc.format("%Y-%m-%d %H:%M UTC").to_string()
}

pub fn sha256(buf: &[u8]) -> String {
    let mut sha256 = Sha256::new();
    sha256.update(buf);
    hex::encode(sha256.finalize())
}
