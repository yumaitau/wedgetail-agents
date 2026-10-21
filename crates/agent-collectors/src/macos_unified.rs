//! macOS unified log, read through `log stream --style ndjson`.
//!
//! `log stream` cannot start in the past, so the checkpoint is the newest event time sent plus
//! hashes of the events in a short window before it. On restart the collector starts the
//! stream first, then catches up with `log show --start <checkpoint - overlap>`, and drops
//! events whose hash it has already seen. The catch-up is capped at [`MAX_CATCH_UP_US`].
//!
//! Parsing and de-duplication are portable and tested everywhere; the collector is macOS only.

use std::collections::HashMap;

use serde_json::{Map, Value};

use agent_config::LogLevel;

use crate::{Checkpoint, MAX_LINE_BYTES, time};

/// Window before the newest event in which hashes are kept for de-duplication.
pub const OVERLAP_US: u64 = 2_000_000;
/// Longest outage the catch-up read covers.
pub const MAX_CATCH_UP_US: u64 = 24 * 3600 * 1_000_000;
/// Cap on remembered hashes, so a burst during catch-up cannot grow memory without bound.
const MAX_SEEN: usize = 50_000;
/// Cap on hashes saved in a checkpoint.
const MAX_CHECKPOINT_SEEN: usize = 2_000;

/// One parsed unified log entry.
#[derive(Debug, PartialEq)]
pub struct UnifiedEntry {
    pub ts_us: u64,
    /// Stable identity for de-duplication between `log show` and `log stream`.
    pub hash: u64,
    pub fields: Map<String, Value>,
}

/// Parse one ndjson line. Header text and the trailing `{"count":..,"finished":1}` summary
/// return `None`.
pub fn parse_line(line: &[u8]) -> Option<UnifiedEntry> {
    if line.first() != Some(&b'{') {
        return None;
    }
    let Value::Object(obj) = serde_json::from_slice(line).ok()? else {
        return None;
    };
    let timestamp = obj.get("timestamp")?.as_str()?;
    let ts_us = time::parse_timestamp_us(timestamp)?;
    obj.get("eventType")?.as_str()?;

    let mut hasher = Fnv::default();
    // Not `timestamp`: `log show` and `log stream` report the same event a few milliseconds
    // apart. `machTimestamp` is identical in both.
    for key in [
        "machTimestamp",
        "threadID",
        "traceID",
        "processID",
        "eventMessage",
    ] {
        hasher.write(key.as_bytes());
        hasher.write(
            obj.get(key)
                .map(Value::to_string)
                .unwrap_or_default()
                .as_bytes(),
        );
    }

    let text = |key: &str| {
        obj.get(key)
            .and_then(Value::as_str)
            .map(|s| Value::String(cut(s)))
    };
    let basename = |key: &str| {
        obj.get(key)
            .and_then(Value::as_str)
            .map(|p| Value::String(cut(p.rsplit('/').next().unwrap_or(p))))
    };
    let mut fields = Map::new();
    let mut put = |key: &str, value: Option<Value>| {
        if let Some(v) = value {
            fields.insert(key.to_owned(), v);
        }
    };
    put("subsystem", text("subsystem"));
    put("category", text("category"));
    put("process", basename("processImagePath"));
    put("processImagePath", text("processImagePath"));
    put("sender", basename("senderImagePath"));
    put("eventMessage", text("eventMessage"));
    put("messageType", text("messageType"));
    put("eventType", text("eventType"));
    put("userID", obj.get("userID").filter(|v| v.is_u64()).cloned());
    put("timestamp", text("timestamp"));
    Some(UnifiedEntry {
        ts_us,
        hash: hasher.0,
        fields,
    })
}

fn cut(s: &str) -> String {
    let mut end = s.len().min(MAX_LINE_BYTES);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

/// FNV-1a: stable across processes, unlike the standard library's randomised hasher.
struct Fnv(u64);

impl Default for Fnv {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Fnv {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
        // Field separator so ("ab","c") and ("a","bc") differ.
        self.0 ^= 0xff;
        self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
    }
}

/// Tracks what has been sent so overlapping reads do not send an event twice.
#[derive(Debug, Default)]
pub struct Dedupe {
    /// Newest event time accepted.
    pub watermark_us: u64,
    /// Events older than this are dropped while catching up (they were sent before).
    resume_from_us: u64,
    seen: HashMap<u64, u64>,
    /// While a catch-up read is in progress, nothing is pruned.
    pub catching_up: bool,
}

impl Dedupe {
    pub fn from_checkpoint(checkpoint: Option<&Checkpoint>) -> Self {
        let mut d = Self::default();
        if let Some(Checkpoint::MacosUnified { ts, seen }) = checkpoint
            && let Some(ts_us) = time::parse_timestamp_us(ts)
        {
            d.watermark_us = ts_us;
            d.resume_from_us = ts_us.saturating_sub(OVERLAP_US);
            for h in seen.iter().take(MAX_CHECKPOINT_SEEN) {
                if let Ok(h) = u64::from_str_radix(h, 16) {
                    d.seen.insert(h, ts_us);
                }
            }
        }
        d
    }

    /// Where a catch-up read should start, or `None` if there is nothing to catch up (no
    /// checkpoint, or it is older than [`MAX_CATCH_UP_US`]).
    pub fn catch_up_from(&self, now_us: u64) -> Option<u64> {
        (self.watermark_us > 0 && now_us.saturating_sub(self.watermark_us) <= MAX_CATCH_UP_US)
            .then_some(self.resume_from_us)
    }

    /// Whether to send this entry.
    pub fn accept(&mut self, entry: &UnifiedEntry, from_catch_up: bool) -> bool {
        if self.seen.contains_key(&entry.hash) {
            return false;
        }
        if from_catch_up && entry.ts_us < self.resume_from_us {
            return false;
        }
        if self.seen.len() < MAX_SEEN {
            self.seen.insert(entry.hash, entry.ts_us);
        }
        self.watermark_us = self.watermark_us.max(entry.ts_us);
        if !self.catching_up {
            self.prune();
        }
        true
    }

    fn prune(&mut self) {
        let floor = self.watermark_us.saturating_sub(OVERLAP_US);
        if self.seen.values().any(|&ts| ts < floor) {
            self.seen.retain(|_, ts| *ts >= floor);
        }
    }

    pub fn finish_catch_up(&mut self) {
        self.catching_up = false;
        self.prune();
    }

    pub fn checkpoint(&self) -> Checkpoint {
        let floor = self.watermark_us.saturating_sub(OVERLAP_US);
        let seen = self
            .seen
            .iter()
            .filter(|(_, ts)| **ts >= floor)
            .take(MAX_CHECKPOINT_SEEN)
            .map(|(h, _)| format!("{h:x}"))
            .collect();
        Checkpoint::MacosUnified {
            ts: time::format_rfc3339_us(self.watermark_us),
            seen,
        }
    }
}

/// `log show --start` takes local-style `YYYY-MM-DD HH:MM:SS+0000`.
/// `log show` flags that include messages down to `level` (`log stream` takes `--level`).
pub fn show_level_flags(level: LogLevel) -> &'static [&'static str] {
    match level {
        LogLevel::Default => &[],
        LogLevel::Info => &["--info"],
        LogLevel::Debug => &["--info", "--debug"],
    }
}

pub fn log_show_start(us: u64) -> String {
    let s = time::format_rfc3339_us(us);
    format!("{} {}+0000", &s[..10], &s[11..19])
}

#[cfg(target_os = "macos")]
pub use collector::UnifiedLog;

#[cfg(target_os = "macos")]
mod collector {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use agent_config::LogLevel;

    use super::{Dedupe, log_show_start, parse_line, show_level_flags};
    use crate::subprocess::LineProcess;
    use crate::{Batch, Checkpoint, Collector, CollectorError, EventTemplate, time};

    const LOG: &str = "/usr/bin/log";

    #[derive(Debug)]
    pub struct UnifiedLog {
        template: EventTemplate,
        predicate: Option<String>,
        level: LogLevel,
        pub(crate) dedupe: Dedupe,
        stream: Option<LineProcess>,
        catch_up: Option<LineProcess>,
    }

    impl UnifiedLog {
        pub fn new(template: EventTemplate, predicate: Option<String>, level: LogLevel) -> Self {
            Self {
                template,
                predicate,
                level,
                dedupe: Dedupe::default(),
                stream: None,
                catch_up: None,
            }
        }

        fn command(&self, args: &[&str]) -> Command {
            let mut command = Command::new(LOG);
            command.args(args).args(["--style", "ndjson"]);
            if let Some(p) = &self.predicate {
                command.arg("--predicate").arg(p);
            }
            command
        }
    }

    impl Collector for UnifiedLog {
        fn rule_id(&self) -> &str {
            &self.template.rule_id
        }

        fn start(&mut self, checkpoint: Option<Checkpoint>) -> Result<(), CollectorError> {
            self.stream = None;
            self.catch_up = None;
            if checkpoint.is_some() {
                self.dedupe = Dedupe::from_checkpoint(checkpoint.as_ref());
            }
            // Stream first so nothing falls between the end of the catch-up and the stream.
            self.stream = Some(LineProcess::spawn(self.command(&[
                "stream",
                "--level",
                self.level.name(),
            ]))?);
            if let Some(from) = self.dedupe.catch_up_from(time::now_us()) {
                let start = log_show_start(from);
                let mut args = vec!["show"];
                args.extend(show_level_flags(self.level));
                args.extend(["--start", &start]);
                self.catch_up = Some(LineProcess::spawn(self.command(&args))?);
                self.dedupe.catching_up = true;
            }
            Ok(())
        }

        fn poll(&mut self, max_events: usize, wait: Duration) -> Result<Batch, CollectorError> {
            let deadline = Instant::now() + wait;
            let mut events = Vec::new();
            while events.len() < max_events {
                let (line, from_catch_up) = if let Some(show) = &mut self.catch_up {
                    match show.recv(deadline.saturating_duration_since(Instant::now())) {
                        Ok(Some(line)) => (line, true),
                        Ok(None) => break,
                        // `log show` has finished: carry on with the stream.
                        Err(_) => {
                            self.catch_up = None;
                            continue;
                        }
                    }
                } else {
                    let stream = self
                        .stream
                        .as_mut()
                        .ok_or_else(|| CollectorError("log stream is not running".into()))?;
                    let line = if events.is_empty() {
                        stream.recv(deadline.saturating_duration_since(Instant::now()))?
                    } else {
                        stream.try_recv()?
                    };
                    match line {
                        Some(line) => (line, false),
                        None => {
                            if self.dedupe.catching_up {
                                // Stream backlog from the catch-up period is drained.
                                self.dedupe.finish_catch_up();
                            }
                            break;
                        }
                    }
                };
                let Some(entry) = parse_line(&line) else {
                    continue;
                };
                if self.dedupe.accept(&entry, from_catch_up) {
                    events.push(self.template.event(entry.ts_us, None, entry.fields));
                }
            }
            let checkpoint = (!events.is_empty()).then(|| self.dedupe.checkpoint());
            Ok(Batch { events, checkpoint })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_flags() {
        assert!(show_level_flags(LogLevel::Default).is_empty());
        assert_eq!(show_level_flags(LogLevel::Info), ["--info"]);
        assert_eq!(show_level_flags(LogLevel::Debug), ["--info", "--debug"]);
    }

    const LINE: &str = r#"{"timezoneName":"","messageType":"Default","eventType":"logEvent","source":null,"formatString":"%s","userID":0,"activityIdentifier":0,"subsystem":"com.apple.Authorization","category":"authd","threadID":5434,"bootUUID":"","processImagePath":"\/System\/Library\/Frameworks\/Security.framework\/Versions\/A\/MachServices\/authd.xpc\/Contents\/MacOS\/authd","senderImagePath":"\/System\/Library\/Frameworks\/Security.framework\/Versions\/A\/Security","timestamp":"2026-10-21 19:00:00.123456+1100","machTimestamp":113743864720729,"eventMessage":"Succeeded authorizing right 'system.login.console'","traceID":1092473043961512196,"processID":623,"parentActivityIdentifier":0}"#;

    #[test]
    fn parses_contract_fields() {
        let entry = parse_line(LINE.as_bytes()).expect("entry");
        assert_eq!(entry.ts_us, 1_792_569_600_123_456);
        assert_eq!(entry.fields["process"], "authd");
        assert_eq!(entry.fields["sender"], "Security");
        assert_eq!(entry.fields["subsystem"], "com.apple.Authorization");
        assert_eq!(
            entry.fields["eventMessage"],
            "Succeeded authorizing right 'system.login.console'"
        );
        assert_eq!(entry.fields["userID"], 0);
        assert!(!entry.fields.contains_key("formatString"));
        // The same event from `log show` (bootUUID filled in, timestamp a few ms later, as
        // observed on macOS 26) hashes the same.
        let shown = LINE
            .replace(r#""bootUUID":"""#, r#""bootUUID":"2EA8D92E""#)
            .replace("00.123456+1100", "00.132618+1100");
        assert_ne!(shown, LINE);
        assert_eq!(
            parse_line(shown.as_bytes()).expect("entry").hash,
            entry.hash
        );
    }

    #[test]
    fn skips_headers_summaries_and_garbage() {
        for line in [
            &br#"Filtering the log data using "process == "x"""#[..],
            br#"{"count":24137,"finished":1}"#,
            b"{",
            br#"{"timestamp":"yesterday","eventType":"logEvent"}"#,
            br#"{"timestamp":"2026-10-21 19:00:00+1100"}"#,
            br#"{"timestamp":7,"eventType":"logEvent"}"#,
            b"",
        ] {
            assert_eq!(parse_line(line), None, "{}", String::from_utf8_lossy(line));
        }
        let huge = format!(
            r#"{{"timestamp":"2026-10-21 19:00:00+1100","eventType":"logEvent","eventMessage":"{}","userID":-1}}"#,
            "x".repeat(MAX_LINE_BYTES * 2)
        );
        let entry = parse_line(huge.as_bytes()).expect("entry");
        assert_eq!(
            entry.fields["eventMessage"].as_str().map(str::len),
            Some(MAX_LINE_BYTES)
        );
        assert!(!entry.fields.contains_key("userID"));
    }

    fn entry(ts_us: u64, hash: u64) -> UnifiedEntry {
        UnifiedEntry {
            ts_us,
            hash,
            fields: Map::new(),
        }
    }

    #[test]
    fn catch_up_overlap_is_deduplicated_across_restart() {
        let base = 1_792_569_600_000_000;
        // First run sends three events, then the agent stops.
        let mut d = Dedupe::default();
        assert!(d.accept(&entry(base, 1), false));
        assert!(d.accept(&entry(base + 1_000_000, 2), false));
        assert!(d.accept(&entry(base + 1_500_000, 3), false));
        assert!(!d.accept(&entry(base + 1_500_000, 3), false));
        let cp = d.checkpoint();

        // Restart: catch up from (newest - overlap).
        let mut d = Dedupe::from_checkpoint(Some(&cp));
        assert_eq!(
            d.catch_up_from(base + 60_000_000),
            Some(base + 1_500_000 - OVERLAP_US)
        );
        assert_eq!(d.catch_up_from(base + MAX_CATCH_UP_US + 2_000_000), None);
        d.catching_up = true;
        // `log show` repeats the overlap window, then has new events.
        assert!(!d.accept(&entry(base, 1), true));
        assert!(!d.accept(&entry(base + 1_000_000, 2), true));
        assert!(!d.accept(&entry(base + 1_500_000, 3), true));
        assert!(d.accept(&entry(base + 9_000_000, 4), true));
        assert!(d.accept(&entry(base + 20_000_000, 5), true));
        // The stream, started before the catch-up, repeats event 4 and 5 long after the
        // overlap window: still caught because nothing is pruned while catching up.
        assert!(!d.accept(&entry(base + 9_000_000, 4), false));
        assert!(!d.accept(&entry(base + 20_000_000, 5), false));
        d.finish_catch_up();
        assert!(d.accept(&entry(base + 21_000_000, 6), false));
        assert!(
            d.seen.len() <= 2,
            "pruned to the overlap window: {:?}",
            d.seen
        );
    }

    #[test]
    fn checkpoint_with_bad_hashes_is_tolerated() {
        let cp = Checkpoint::MacosUnified {
            ts: "2026-10-21T08:00:00.000000Z".into(),
            seen: vec!["zz".into(), "ff".into()],
        };
        let d = Dedupe::from_checkpoint(Some(&cp));
        assert_eq!(d.seen.len(), 1);
        let cp = Checkpoint::MacosUnified {
            ts: "garbage".into(),
            seen: vec![],
        };
        assert_eq!(Dedupe::from_checkpoint(Some(&cp)).catch_up_from(1), None);
    }

    #[test]
    fn show_start_format() {
        assert_eq!(
            log_show_start(1_792_569_600_123_456),
            "2026-10-21 08:00:00+0000"
        );
    }
}

/// Runs the real `log stream`. Needs an admin user (as on GitHub's macOS runners).
#[cfg(all(test, target_os = "macos"))]
mod os_tests {
    use std::collections::BTreeMap;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use agent_config::LogLevel;

    use super::UnifiedLog;
    use crate::{Collector, EventTemplate};

    fn collect_until(c: &mut UnifiedLog, token: &str, want: usize, secs: u64) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut got = Vec::new();
        while Instant::now() < deadline && got.len() < want {
            let batch = c.poll(100, Duration::from_millis(500)).expect("poll");
            got.extend(
                batch
                    .events
                    .iter()
                    .filter_map(|e| e.fields.get("eventMessage")?.as_str().map(str::to_owned))
                    // `log` itself logs its command line, which contains the token too.
                    .filter(|m| m.starts_with(token)),
            );
        }
        got
    }

    #[test]
    fn streams_and_catches_up_after_restart() {
        let token = format!("wt-test-{}-{}", std::process::id(), crate::time::now_us());
        let template = EventTemplate::new("t", "macos.unified", None, &BTreeMap::new());
        let predicate = format!("eventMessage CONTAINS \"{token}\"");
        let mut c = UnifiedLog::new(template.clone(), Some(predicate.clone()), LogLevel::Info);
        c.start(None).expect("start");
        std::thread::sleep(Duration::from_secs(2));
        let logger = |m: &str| {
            Command::new("/usr/bin/logger")
                .arg(m)
                .status()
                .expect("logger")
        };
        logger(&format!("{token} one"));
        let got = collect_until(&mut c, &token, 1, 20);
        assert_eq!(got, [format!("{token} one")]);
        let checkpoint = c.dedupe.checkpoint();
        drop(c);

        // Logged while stopped: found by the catch-up read, and "one" is not repeated.
        logger(&format!("{token} two"));
        std::thread::sleep(Duration::from_secs(1));
        let mut c = UnifiedLog::new(template, Some(predicate), LogLevel::Info);
        c.start(Some(checkpoint)).expect("restart");
        let got = collect_until(&mut c, &token, 1, 20);
        let more = collect_until(&mut c, &token, 1, 3);
        assert_eq!(got, [format!("{token} two")], "then {more:?}");
        assert!(more.is_empty(), "duplicates: {more:?}");
    }
}
