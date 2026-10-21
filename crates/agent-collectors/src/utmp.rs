//! Binary login records: `struct utmp` as written to `/var/log/wtmp` and `/var/log/btmp`
//! (`format = "utmp"`), and `struct lastlog` from `/var/log/lastlog` (`format = "lastlog"`).
//!
//! The layouts are glibc's on 64-bit little-endian Linux. They differ by architecture:
//! x86_64 keeps 32-bit times for compatibility with 32-bit programs (utmp 384 bytes,
//! lastlog 292), aarch64 uses native 64-bit `long` and `time_t` (utmp 400 bytes, lastlog 296).
//! The agent reads the files of the host it runs on, so it uses [`Layout::NATIVE`]. Records
//! are decoded field by field from byte slices; nothing is trusted: strings are cut at the
//! first NUL and made valid UTF-8, unknown record types are skipped.
//!
//! ```text
//! utmp                      x86_64 (384)        aarch64 (400)
//!   ut_type                 0   i16             0   i16
//!   ut_pid                  4   i32             4   i32
//!   ut_line [32]            8                   8
//!   ut_id [4]               40                  40
//!   ut_user [32]            44                  44
//!   ut_host [256]           76                  76
//!   e_termination, e_exit   332 i16, 334 i16    332 i16, 334 i16
//!   ut_session              336 i32             336 i64
//!   tv_sec, tv_usec         340 i32, 344 i32    344 i64, 352 i64
//!   ut_addr_v6 [16]         348                 360
//! lastlog                   x86_64 (292)        aarch64 (296)
//!   ll_time                 0   i32             0   i64
//!   ll_line [32], ll_host [256] follow
//! ```

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde_json::{Map, Value};

use crate::time;

/// The glibc record layout of one architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// x86_64: 32-bit times (`__WORDSIZE_TIME64_COMPAT32`).
    X86_64,
    /// aarch64 (and other 64-bit targets without the compatibility layout).
    Aarch64,
}

impl Layout {
    /// The layout of the architecture the agent was built for.
    pub const NATIVE: Self = if cfg!(target_arch = "x86_64") {
        Self::X86_64
    } else {
        Self::Aarch64
    };

    /// `sizeof(struct utmp)`.
    pub fn utmp_size(self) -> usize {
        match self {
            Self::X86_64 => 384,
            Self::Aarch64 => 400,
        }
    }

    /// `sizeof(struct lastlog)`.
    pub fn lastlog_size(self) -> usize {
        match self {
            Self::X86_64 => 292,
            Self::Aarch64 => 296,
        }
    }
}

const TYPES: [&str; 10] = [
    "EMPTY",
    "RUN_LVL",
    "BOOT_TIME",
    "NEW_TIME",
    "OLD_TIME",
    "INIT_PROCESS",
    "LOGIN_PROCESS",
    "USER_PROCESS",
    "DEAD_PROCESS",
    "ACCOUNTING",
];

fn i16_at(b: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([b[at], b[at + 1]])
}

fn i32_at(b: &[u8], at: usize) -> i32 {
    i32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn i64_at(b: &[u8], at: usize) -> i64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&b[at..at + 8]);
    i64::from_le_bytes(bytes)
}

/// A fixed-size, NUL-padded C string.
fn c_str(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn put(fields: &mut Map<String, Value>, key: &str, value: String) {
    if !value.is_empty() {
        fields.insert(key.to_owned(), Value::String(value));
    }
}

/// `ut_addr_v6`: an IPv4 address in the first word (network order) or an IPv6 address.
fn address(b: &[u8]) -> Option<String> {
    if b.iter().all(|&x| x == 0) {
        return None;
    }
    if b[4..].iter().all(|&x| x == 0) {
        return Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string());
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&b[..16]);
    Some(Ipv6Addr::from(octets).to_string())
}

/// Seconds since the epoch as microseconds; `None` for 0, negative or beyond year 9999.
fn epoch_us(secs: i64, usecs: i64) -> Option<u64> {
    let secs = u64::try_from(secs)
        .ok()
        .filter(|s| (1..253_402_300_800).contains(s))?;
    let usecs = u64::try_from(usecs).unwrap_or(0).min(999_999);
    Some(secs * 1_000_000 + usecs)
}

/// Decode one utmp record from `log` (`wtmp`, `btmp`). Returns the record time and its
/// `fields`; `None` for an empty record, an unknown type or a slice of the wrong size.
pub fn decode_utmp(rec: &[u8], log: &str, layout: Layout) -> Option<(u64, Map<String, Value>)> {
    if rec.len() != layout.utmp_size() {
        return None;
    }
    let code = i16_at(rec, 0);
    let kind = usize::try_from(code).ok().and_then(|c| TYPES.get(c))?;
    if code == 0 {
        return None;
    }
    let (session, tv_sec, tv_usec, addr) = match layout {
        Layout::X86_64 => (
            i64::from(i32_at(rec, 336)),
            i64::from(i32_at(rec, 340)),
            i64::from(i32_at(rec, 344)),
            348,
        ),
        Layout::Aarch64 => (i64_at(rec, 336), i64_at(rec, 344), i64_at(rec, 352), 360),
    };
    let ts_us = epoch_us(tv_sec, tv_usec);
    let mut fields = Map::new();
    fields.insert("log".into(), Value::from(log));
    fields.insert("type".into(), Value::from(*kind));
    fields.insert("type_code".into(), Value::from(code));
    let pid = i32_at(rec, 4);
    if pid != 0 {
        fields.insert("pid".into(), Value::from(pid));
    }
    put(&mut fields, "line", c_str(&rec[8..40]));
    put(&mut fields, "id", c_str(&rec[40..44]));
    put(&mut fields, "user", c_str(&rec[44..76]));
    put(&mut fields, "host", c_str(&rec[76..332]));
    if let Some(addr) = address(&rec[addr..addr + 16]) {
        fields.insert("addr".into(), Value::from(addr));
    }
    let (termination, exit) = (i16_at(rec, 332), i16_at(rec, 334));
    if termination != 0 || exit != 0 {
        fields.insert("exit_termination".into(), Value::from(termination));
        fields.insert("exit_status".into(), Value::from(exit));
    }
    if session != 0 {
        fields.insert("session".into(), Value::from(session));
    }
    if let Some(ts) = ts_us {
        fields.insert("time".into(), Value::from(time::format_rfc3339_us(ts)));
    }
    Some((ts_us.unwrap_or_else(time::now_us), fields))
}

/// One user's last login from `/var/log/lastlog`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastLogin {
    pub uid: u32,
    pub time_us: u64,
    pub line: String,
    pub host: String,
}

/// Every user with a recorded last login, in uid order. The record index is the uid; records
/// that were never written (zero time, holes in the sparse file) are skipped.
pub fn decode_lastlog(data: &[u8], layout: Layout) -> Vec<LastLogin> {
    let (time_len, size) = match layout {
        Layout::X86_64 => (4, 292),
        Layout::Aarch64 => (8, 296),
    };
    data.chunks_exact(size)
        .enumerate()
        .filter_map(|(uid, rec)| {
            let secs = if time_len == 4 {
                i64::from(i32_at(rec, 0))
            } else {
                i64_at(rec, 0)
            };
            let time_us = epoch_us(secs, 0)?;
            Some(LastLogin {
                uid: u32::try_from(uid).ok()?,
                time_us,
                line: c_str(&rec[time_len..time_len + 32]),
                host: c_str(&rec[time_len + 32..time_len + 288]),
            })
        })
        .collect()
}

/// `/etc/passwd` as uid to user name (first name wins for a shared uid).
pub fn passwd_names(text: &str) -> HashMap<u32, String> {
    let mut names = HashMap::new();
    for line in text.lines() {
        let mut parts = line.split(':');
        let (Some(name), Some(_), Some(uid)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if let Ok(uid) = uid.parse::<u32>()
            && !name.is_empty()
            && !name.starts_with(['#', '+', '-'])
        {
            names
                .entry(uid)
                .or_insert_with(|| name.chars().take(64).collect());
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const WTMP_X86_64: &[u8] = include_bytes!("../../../presets/linux/fixtures/wtmp");
    const WTMP_AARCH64: &[u8] = include_bytes!("../../../presets/linux/fixtures/wtmp-aarch64");
    const LASTLOG_X86_64: &[u8] = include_bytes!("../../../presets/linux/fixtures/lastlog");
    const LASTLOG_AARCH64: &[u8] =
        include_bytes!("../../../presets/linux/fixtures/lastlog-aarch64");

    fn decode_all(data: &[u8], layout: Layout) -> Vec<Value> {
        assert_eq!(data.len() % layout.utmp_size(), 0);
        data.chunks(layout.utmp_size())
            .filter_map(|r| decode_utmp(r, "wtmp", layout))
            .map(|(_, f)| Value::Object(f))
            .collect()
    }

    /// The fixtures were written by util-linux `utmpdump -r` on Ubuntu 24.04 for each
    /// architecture (see `wtmp.utmpdump`): both decode to the same records.
    #[test]
    fn decodes_glibc_fixtures_for_both_architectures() {
        let x86 = decode_all(WTMP_X86_64, Layout::X86_64);
        let arm = decode_all(WTMP_AARCH64, Layout::Aarch64);
        assert_eq!(x86, arm);
        assert_eq!(x86.len(), 7);
        assert_eq!(
            x86[2],
            json!({"log": "wtmp", "type": "USER_PROCESS", "type_code": 7, "pid": 2101,
                   "line": "pts/0", "id": "ts/0", "user": "alice", "host": "192.0.2.10",
                   "addr": "192.0.2.10", "time": "2026-10-21T08:00:01.104512Z"})
        );
        assert_eq!(x86[3]["addr"], "2001:db8::25");
        assert_eq!(x86[0]["type"], "BOOT_TIME");
        assert_eq!(x86[4]["type"], "DEAD_PROCESS");
        // The wrong layout does not produce garbage records with the right size check.
        assert!(decode_utmp(&WTMP_X86_64[..384], "wtmp", Layout::Aarch64).is_none());
    }

    #[test]
    fn decodes_lastlog_fixtures_for_both_architectures() {
        let x86 = decode_lastlog(LASTLOG_X86_64, Layout::X86_64);
        assert_eq!(x86, decode_lastlog(LASTLOG_AARCH64, Layout::Aarch64));
        let uids: Vec<u32> = x86.iter().map(|l| l.uid).collect();
        assert_eq!(uids, [0, 1000, 1002]);
        assert_eq!(
            x86[1],
            LastLogin {
                uid: 1000,
                time_us: 1_792_569_601_000_000,
                line: "pts/0".into(),
                host: "192.0.2.10".into()
            }
        );
        // A trailing partial record is ignored.
        let mut data = LASTLOG_X86_64.to_vec();
        data.extend_from_slice(&[1, 2, 3]);
        assert_eq!(decode_lastlog(&data, Layout::X86_64).len(), 3);
    }

    #[test]
    fn hostile_records() {
        for layout in [Layout::X86_64, Layout::Aarch64] {
            let size = layout.utmp_size();
            // Empty, unknown types, wrong sizes.
            assert!(decode_utmp(&vec![0u8; size], "wtmp", layout).is_none());
            let mut rec = vec![0xffu8; size];
            assert!(decode_utmp(&rec, "wtmp", layout).is_none());
            rec[0..2].copy_from_slice(&42i16.to_le_bytes());
            assert!(decode_utmp(&rec, "wtmp", layout).is_none());
            assert!(decode_utmp(&[7u8; 100], "wtmp", layout).is_none());
            // Strings without a NUL and invalid UTF-8 are cut to their field; a negative
            // time is not a time.
            rec[0..2].copy_from_slice(&6i16.to_le_bytes());
            let (ts, fields) = decode_utmp(&rec, "btmp", layout).expect("record");
            assert_eq!(fields["user"].as_str().map(|s| s.chars().count()), Some(32));
            assert!(ts > 0);
            assert!(!fields.contains_key("time"));
            // A time far in the future is not a time either.
            let mut rec = vec![0u8; size];
            rec[0..2].copy_from_slice(&7i16.to_le_bytes());
            if layout == Layout::Aarch64 {
                rec[344..352].copy_from_slice(&i64::MAX.to_le_bytes());
            }
            let (_, fields) = decode_utmp(&rec, "wtmp", layout).expect("record");
            assert!(!fields.contains_key("time"));
        }
        assert!(decode_lastlog(&[0xffu8; 296 * 4], Layout::Aarch64).is_empty());
    }

    #[test]
    fn passwd() {
        let names = passwd_names(
            "root:x:0:0:root:/root:/bin/bash\n# comment\nalice:x:1000:1000::/home/alice:/bin/sh\nbad\n+nis::::\ndup:x:0:0::/:\n",
        );
        assert_eq!(names.get(&0).map(String::as_str), Some("root"));
        assert_eq!(names.get(&1000).map(String::as_str), Some("alice"));
        assert_eq!(names.len(), 2);
    }
}
