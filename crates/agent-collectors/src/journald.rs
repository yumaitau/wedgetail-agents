//! systemd journal, read through `journalctl -o json --follow`.
//!
//! The checkpoint is the journal cursor of the last event; a restart passes it to
//! `--after-cursor`. Parsing is portable so it is tested on every OS; the collector itself is
//! Linux only.

use serde_json::{Map, Value};

use crate::MAX_LINE_BYTES;

/// Journal fields kept in `fields` (the wire contract's subset).
pub const FIELDS: &[&str] = &[
    "MESSAGE",
    "_SYSTEMD_UNIT",
    "SYSLOG_IDENTIFIER",
    "_PID",
    "_UID",
    "PRIORITY",
    "SYSLOG_FACILITY",
    "_TRANSPORT",
    "_COMM",
    "_EXE",
];

/// One journal entry after parsing.
#[derive(Debug, PartialEq)]
pub struct JournalEntry {
    pub cursor: String,
    pub ts_us: u64,
    pub fields: Map<String, Value>,
}

/// Parse one `journalctl -o json` line. Returns `None` for anything that is not an entry with
/// a cursor and realtime timestamp.
pub fn parse_line(line: &[u8]) -> Option<JournalEntry> {
    let Value::Object(mut obj) = serde_json::from_slice(line).ok()? else {
        return None;
    };
    let cursor = match obj.remove("__CURSOR")? {
        Value::String(c) if !c.is_empty() && c.len() <= 1024 => c,
        _ => return None,
    };
    let ts_us = match obj.get("__REALTIME_TIMESTAMP")? {
        Value::String(s) => s.parse().ok()?,
        _ => return None,
    };
    let mut fields = Map::new();
    for &name in FIELDS {
        if let Some(value) = obj.remove(name).and_then(field_value) {
            fields.insert(name.to_owned(), value);
        }
    }
    Some(JournalEntry {
        cursor,
        ts_us,
        fields,
    })
}

/// Journal values are strings, byte arrays (non-UTF-8 data) or arrays of those when a field
/// repeats. Anything is cut to [`MAX_LINE_BYTES`].
fn field_value(value: Value) -> Option<Value> {
    match value {
        Value::String(s) => Some(Value::String(cut(s))),
        Value::Array(items) if items.iter().all(|v| v.as_u64().is_some_and(|n| n <= 255)) => {
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(Value::as_u64)
                .map(|n| n as u8)
                .collect();
            Some(Value::String(cut(
                String::from_utf8_lossy(&bytes).into_owned()
            )))
        }
        Value::Array(items) => {
            let values: Vec<Value> = items.into_iter().take(16).filter_map(field_value).collect();
            (!values.is_empty()).then_some(Value::Array(values))
        }
        _ => None,
    }
}

fn cut(mut s: String) -> String {
    if s.len() > MAX_LINE_BYTES {
        let mut end = MAX_LINE_BYTES;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

/// `journalctl` arguments for a start position and match list.
pub fn journalctl_args(cursor: Option<&str>, matches: &[String]) -> Vec<String> {
    let mut args = vec![
        "--output=json".to_owned(),
        "--follow".to_owned(),
        "--no-pager".to_owned(),
        "--quiet".to_owned(),
        format!("--output-fields={}", FIELDS.join(",")),
    ];
    match cursor {
        Some(c) => args.push(format!("--after-cursor={c}")),
        None => args.push("--lines=0".to_owned()),
    }
    // Validated as FIELD=value by agent-config, so none can be read as an option.
    args.extend(matches.iter().cloned());
    args
}

#[cfg(target_os = "linux")]
pub use collector::Journald;

#[cfg(target_os = "linux")]
mod collector {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::{journalctl_args, parse_line};
    use crate::subprocess::LineProcess;
    use crate::{Batch, Checkpoint, Collector, CollectorError, EventTemplate};

    const JOURNALCTL: &str = "/usr/bin/journalctl";

    #[derive(Debug)]
    pub struct Journald {
        template: EventTemplate,
        matches: Vec<String>,
        cursor: Option<String>,
        process: Option<LineProcess>,
    }

    impl Journald {
        pub fn new(template: EventTemplate, matches: Vec<String>) -> Self {
            Self {
                template,
                matches,
                cursor: None,
                process: None,
            }
        }
    }

    impl Collector for Journald {
        fn rule_id(&self) -> &str {
            &self.template.rule_id
        }

        fn start(&mut self, checkpoint: Option<Checkpoint>) -> Result<(), CollectorError> {
            if let Some(Checkpoint::Journald { cursor }) = checkpoint {
                self.cursor = Some(cursor);
            }
            self.process = None;
            let mut command = Command::new(JOURNALCTL);
            command.args(journalctl_args(self.cursor.as_deref(), &self.matches));
            self.process = Some(LineProcess::spawn(command)?);
            Ok(())
        }

        fn poll(&mut self, max_events: usize, wait: Duration) -> Result<Batch, CollectorError> {
            let process = self
                .process
                .as_mut()
                .ok_or_else(|| CollectorError("journalctl is not running".into()))?;
            let deadline = Instant::now() + wait;
            let mut events = Vec::new();
            while events.len() < max_events {
                let line = if events.is_empty() {
                    process.recv(deadline.saturating_duration_since(Instant::now()))?
                } else {
                    process.try_recv()?
                };
                let Some(line) = line else { break };
                let Some(entry) = parse_line(&line) else {
                    log::debug!(
                        "{}: skipped an unparsable journal line",
                        self.template.rule_id
                    );
                    continue;
                };
                self.cursor = Some(entry.cursor);
                events.push(self.template.event(entry.ts_us, None, entry.fields));
            }
            let checkpoint = if events.is_empty() {
                None
            } else {
                self.cursor
                    .clone()
                    .map(|cursor| Checkpoint::Journald { cursor })
            };
            Ok(Batch { events, checkpoint })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_entry_and_keeps_contract_fields() {
        let line = br#"{"__CURSOR":"s=abc;i=1f","__REALTIME_TIMESTAMP":"1792569600123456","__MONOTONIC_TIMESTAMP":"1","_BOOT_ID":"x","MESSAGE":"Accepted publickey for alice from 192.0.2.10","_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd","_PID":"812","_UID":"0","PRIORITY":"6","_TRANSPORT":"syslog","_COMM":"sshd","_EXE":"/usr/sbin/sshd","_HOSTNAME":"web-01"}"#;
        let entry = parse_line(line).expect("entry");
        assert_eq!(entry.cursor, "s=abc;i=1f");
        assert_eq!(entry.ts_us, 1_792_569_600_123_456);
        assert_eq!(
            entry.fields["MESSAGE"],
            "Accepted publickey for alice from 192.0.2.10"
        );
        assert_eq!(entry.fields["_SYSTEMD_UNIT"], "ssh.service");
        assert!(!entry.fields.contains_key("_HOSTNAME"));
        assert!(!entry.fields.contains_key("_BOOT_ID"));
    }

    #[test]
    fn binary_and_repeated_fields() {
        let line = br#"{"__CURSOR":"c","__REALTIME_TIMESTAMP":"1","MESSAGE":[104,105,255],"_COMM":["a","b"]}"#;
        let entry = parse_line(line).expect("entry");
        assert_eq!(entry.fields["MESSAGE"], "hi\u{fffd}");
        assert_eq!(entry.fields["_COMM"], serde_json::json!(["a", "b"]));
    }

    #[test]
    fn hostile_lines_are_skipped_or_bounded() {
        for line in [
            &b""[..],
            b"not json",
            b"[]",
            b"{}",
            br#"{"__CURSOR":"c"}"#,
            br#"{"__CURSOR":"c","__REALTIME_TIMESTAMP":"-1"}"#,
            br#"{"__CURSOR":"c","__REALTIME_TIMESTAMP":1}"#,
            br#"{"__CURSOR":1,"__REALTIME_TIMESTAMP":"1"}"#,
            br#"{"__CURSOR":"","__REALTIME_TIMESTAMP":"1"}"#,
        ] {
            assert_eq!(parse_line(line), None, "{}", String::from_utf8_lossy(line));
        }

        let big = format!(
            r#"{{"__CURSOR":"c","__REALTIME_TIMESTAMP":"1","MESSAGE":"{}","PRIORITY":{{"x":1}},"_PID":[1,2,300]}}"#,
            "é".repeat(MAX_LINE_BYTES)
        );
        let entry = parse_line(big.as_bytes()).expect("entry");
        let msg = entry.fields["MESSAGE"].as_str().expect("str");
        assert!(msg.len() <= MAX_LINE_BYTES);
        assert!(!entry.fields.contains_key("PRIORITY"));
        assert!(!entry.fields.contains_key("_PID"));
    }

    #[test]
    fn args_resume_after_cursor() {
        let args = journalctl_args(Some("s=1;i=2"), &["_SYSTEMD_UNIT=ssh.service".to_owned()]);
        assert!(args.contains(&"--after-cursor=s=1;i=2".to_owned()));
        assert!(!args.contains(&"--lines=0".to_owned()));
        assert_eq!(
            args.last().map(String::as_str),
            Some("_SYSTEMD_UNIT=ssh.service")
        );
        let args = journalctl_args(None, &[]);
        assert!(args.contains(&"--lines=0".to_owned()));
        assert!(args.contains(&"--output=json".to_owned()));
    }
}

/// Runs the real `journalctl`; skipped where the journal is not readable.
#[cfg(all(test, target_os = "linux"))]
mod os_tests {
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use super::Journald;
    use crate::{Checkpoint, Collector, EventTemplate};

    fn journal_readable() -> bool {
        Command::new("/usr/bin/journalctl")
            .args(["--lines=1", "--quiet"])
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    fn send(identifier: &str, message: &str) {
        let mut child = Command::new("systemd-cat")
            .args(["-t", identifier])
            .stdin(Stdio::piped())
            .spawn()
            .expect("systemd-cat");
        if let Some(stdin) = child.stdin.as_mut() {
            writeln!(stdin, "{message}").expect("write");
        }
        child.wait().expect("wait");
    }

    fn collect(c: &mut Journald, want: usize, secs: u64) -> (Vec<String>, Option<Checkpoint>) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let (mut got, mut cp) = (Vec::new(), None);
        while Instant::now() < deadline && got.len() < want {
            let batch = c.poll(100, Duration::from_millis(500)).expect("poll");
            got.extend(
                batch
                    .events
                    .iter()
                    .filter_map(|e| e.fields.get("MESSAGE")?.as_str().map(str::to_owned)),
            );
            cp = batch.checkpoint.or(cp);
        }
        (got, cp)
    }

    #[test]
    fn follows_and_resumes_after_cursor() {
        if !journal_readable() {
            eprintln!("journal not readable here; skipping");
            return;
        }
        let ident = format!("wt-test-{}", std::process::id());
        let template = EventTemplate::new("j", "journald", None, &BTreeMap::new());
        let matches = vec![format!("SYSLOG_IDENTIFIER={ident}")];
        let mut c = Journald::new(template.clone(), matches.clone());
        c.start(None).expect("start");
        std::thread::sleep(Duration::from_secs(1));
        send(&ident, "one");
        let (got, cp) = collect(&mut c, 1, 20);
        assert_eq!(got, ["one"]);
        drop(c);

        send(&ident, "two");
        let mut c = Journald::new(template, matches);
        c.start(cp).expect("restart");
        let (got, _) = collect(&mut c, 2, 5);
        assert_eq!(got, ["two"]);
    }
}
