//! Minimal UTC time handling: RFC 3339 with microseconds, and parsing the timestamp shapes the
//! collectors see (`2026-10-21T08:00:00.1234567Z`, `2026-10-21 18:00:00.123456+1000`).

use std::time::{SystemTime, UNIX_EPOCH};

/// Microseconds since the Unix epoch, now.
pub fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64)
}

/// `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
pub fn format_rfc3339_us(us: u64) -> String {
    let secs = us / 1_000_000;
    let micros = us % 1_000_000;
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Parse `YYYY-MM-DD[T ]HH:MM:SS[.fraction][Z|+HH:MM|+HHMM]` into microseconds since the epoch.
/// A missing offset is read as UTC. Returns `None` for anything else or a pre-1970 time.
pub fn parse_timestamp_us(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 19 || b.len() > 64 || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    if b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    let mut i = 19;
    let mut micros = 0i64;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            if i - start < 6 {
                micros = micros * 10 + i64::from(b[i] - b'0');
            }
            i += 1;
        }
        let digits = i - start;
        if digits == 0 {
            return None;
        }
        for _ in digits..6 {
            micros *= 10;
        }
    }

    let offset_s = match &b[i..] {
        [] | [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), rest @ ..] => {
            let digits: Vec<u8> = rest.iter().copied().filter(|&c| c != b':').collect();
            if digits.len() != 4 || !digits.iter().all(u8::is_ascii_digit) || rest.len() > 5 {
                return None;
            }
            let h = i64::from((digits[0] - b'0') * 10 + (digits[1] - b'0'));
            let m = i64::from((digits[2] - b'0') * 10 + (digits[3] - b'0'));
            if h > 23 || m > 59 {
                return None;
            }
            let off = h * 3600 + m * 60;
            if *sign == b'+' { off } else { -off }
        }
        _ => return None,
    };

    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second.min(59) - offset_s;
    if secs < 0 {
        return None;
    }
    Some(secs as u64 * 1_000_000 + micros as u64)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's days_from_civil / civil_from_days.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        if m <= 2 {
            yoe + era * 400 + 1
        } else {
            yoe + era * 400
        },
        m,
        d,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_792_569_600_123_456; // 2026-10-21T08:00:00.123456Z

    #[test]
    fn formats() {
        assert_eq!(format_rfc3339_us(T), "2026-10-21T08:00:00.123456Z");
        assert_eq!(format_rfc3339_us(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(
            format_rfc3339_us(951_782_400_000_000),
            "2000-02-29T00:00:00.000000Z"
        );
    }

    #[test]
    fn parses_collector_shapes() {
        assert_eq!(parse_timestamp_us("2026-10-21T08:00:00.123456Z"), Some(T));
        assert_eq!(parse_timestamp_us("2026-10-21T08:00:00.1234567Z"), Some(T));
        assert_eq!(
            parse_timestamp_us("2026-10-21 18:00:00.123456+1000"),
            Some(T)
        );
        assert_eq!(
            parse_timestamp_us("2026-10-21 18:00:00.123456+10:00"),
            Some(T)
        );
        assert_eq!(
            parse_timestamp_us("2026-10-21T03:30:00.123456-04:30"),
            Some(T)
        );
        assert_eq!(parse_timestamp_us("2026-10-21T08:00:00"), Some(T - 123_456));
        assert_eq!(
            parse_timestamp_us("2026-10-21T08:00:00.1Z"),
            Some(T - 23_456)
        );
    }

    #[test]
    fn rejects_hostile_input() {
        for s in [
            "",
            "2026-10-21",
            "2026-13-01T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-10-21T24:00:00Z",
            "2026-10-21T08:00:00.Z",
            "2026-10-21T08:00:00+25:00",
            "2026-10-21T08:00:00+1",
            "2026-10-21T08:00:00Zjunk",
            "+026-10-21T08:00:00Z",
            "1969-12-31T23:59:59Z",
            "2026-10-21T08:00:00.123456789012345678901234567890123456789012345678Z",
            "２０２６-10-21T08:00:00Z",
        ] {
            assert_eq!(parse_timestamp_us(s), None, "{s}");
        }
    }

    #[test]
    fn round_trips_many_days() {
        for day in (0..40_000u64).step_by(37) {
            let us = day * 86_400_000_000 + 12_345;
            assert_eq!(parse_timestamp_us(&format_rfc3339_us(us)), Some(us));
        }
    }
}
