//! Minimal UTC timestamp — RFC 3339 on the wire, epoch milliseconds inside.
//!
//! Why not chrono: see ADR-007. This is ~100 lines, fully deterministic,
//! serde-transparent as `"2026-09-21T20:08:35Z"`, and has zero OS linkage.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    epoch_ms: i64,
}

impl Timestamp {
    pub fn now() -> Self {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        Timestamp { epoch_ms: ms }
    }

    pub fn from_epoch_ms(ms: i64) -> Self {
        Timestamp { epoch_ms: ms }
    }

    pub fn epoch_ms(&self) -> i64 {
        self.epoch_ms
    }

    /// RFC 3339 / ISO 8601 UTC rendering, e.g. `2026-09-21T20:08:35Z`.
    pub fn to_rfc3339(&self) -> String {
        let secs = self.epoch_ms.div_euclid(1000);
        let days = secs.div_euclid(86_400);
        let day_secs = secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            y,
            m,
            d,
            day_secs / 3600,
            (day_secs % 3600) / 60,
            day_secs % 60
        )
    }
}

/// Howard Hinnant's civil_from_days: days since 1970-01-01 → (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Accept RFC 3339 strings; on any parse trouble fall back to epoch
        // fields if the caller used them. Strictness lives in verify tests.
        let s = String::deserialize(d)?;
        parse_rfc3339(&s).ok_or_else(|| serde::de::Error::custom("invalid RFC 3339 timestamp"))
    }
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` (seconds-precision UTC; offsets rejected).
pub fn parse_rfc3339(s: &str) -> Option<Timestamp> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[19] != b'Z' {
        return None;
    }
    let num = |i: usize, n: usize| -> Option<i64> { s.get(i..i + n).and_then(|t| t.parse().ok()) };
    let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (h, mi, sec) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // days_from_civil (Hinnant)
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy.rem_euclid(400);
    let mp = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(Timestamp::from_epoch_ms(
        ((days * 24 + h) * 3600 + mi * 60 + sec) * 1000,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_renders_correctly() {
        assert_eq!(
            Timestamp::from_epoch_ms(0).to_rfc3339(),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn rfc3339_roundtrip() {
        let ts = parse_rfc3339("2026-09-21T20:08:35Z").unwrap();
        assert_eq!(ts.to_rfc3339(), "2026-09-21T20:08:35Z");
        assert_eq!(ts.epoch_ms(), 1_790_021_315_000);
    }

    #[test]
    fn leap_day() {
        let ts = parse_rfc3339("2024-02-29T23:59:59Z").unwrap();
        assert_eq!(ts.to_rfc3339(), "2024-02-29T23:59:59Z");
    }

    #[test]
    fn serde_roundtrip() {
        let ts = Timestamp::from_epoch_ms(1_700_000_000_123);
        let json = serde_json::to_string(&ts).unwrap();
        let back: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(back.to_rfc3339(), ts.to_rfc3339());
    }
}
