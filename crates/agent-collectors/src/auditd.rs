//! The Linux audit log (`format = "auditd"`): parse records and merge the records of one
//! event into one [`Event`].
//!
//! Every record names its event as `msg=audit(<seconds>.<millis>:<serial>)`. A system call
//! event is several records (SYSCALL, EXECVE, PATH, CWD, PROCTITLE, ...) ended by an `EOE`
//! record; user-space events (USER_LOGIN, USER_CMD, CRED_*, ADD_USER, ...) are one record with
//! a quoted `msg='...'` part. Records are grouped by that stamp, and a group is finished by
//! its `EOE`, by being a single-record event, or after [`FLUSH_AFTER`] without a new record.
//! Groups are bounded in records and bytes, and at most [`MAX_PENDING`] are open at once (the
//! oldest is finished early beyond that).
//!
//! Each record becomes `{"type": "SYSCALL", "<key>": "<value>", ...}`. Values are strings, as
//! written; fields auditd hex-encodes when they hold spaces or control characters (PROCTITLE
//! `proctitle`, EXECVE `a0`, `a1`, ..., `cmd`, `comm`, `exe`, `name`, `cwd`, ...) are decoded,
//! and PROCTITLE's NUL-separated arguments are joined with spaces. A user-space record's
//! `msg='op=login acct="alice" res=failed'` is flattened into the record. With
//! `log_format = ENRICHED` the interpreted fields after the `0x1d` separator (`UID="root"`,
//! `SYSCALL=execve`, ...) are added in upper case, as auditd writes them.

use std::time::{Duration, Instant};

use serde_json::{Map, Value};

/// How long an incomplete event waits for more records.
pub const FLUSH_AFTER: Duration = Duration::from_secs(2);
/// Most records in one event; the rest are dropped and the event marked truncated.
pub const MAX_RECORDS: usize = 128;
/// Most events being assembled at once.
pub const MAX_PENDING: usize = 256;
/// Most fields kept from one record.
const MAX_FIELDS: usize = 256;

/// Fields auditd writes hex-encoded (unquoted) when the value needs it.
const ENCODED: &[&str] = &[
    "acct",
    "cmd",
    "comm",
    "cwd",
    "data",
    "dir",
    "exe",
    "file",
    "grp",
    "key",
    "name",
    "new_group",
    "ocomm",
    "old_group",
    "path",
    "proctitle",
    "root_dir",
    "vm",
    "watch",
];

/// One finished audit event.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub ts_us: u64,
    /// `{"serial": n, "node"?: "...", "records": [{"type": ..., ...}, ...]}`.
    pub fields: Map<String, Value>,
    /// Records or bytes were dropped to stay within the bounds.
    pub truncated: bool,
}

/// One parsed record line.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// `<seconds>.<millis>:<serial>`, the event's identity.
    pub stamp: String,
    pub ts_us: u64,
    pub serial: u64,
    pub node: Option<String>,
    pub kind: String,
    /// The record as it is sent: `type` plus every field.
    pub fields: Map<String, Value>,
    /// Had a `msg='...'` part: a user-space event, always a single record.
    pub user_space: bool,
}

/// Parse one audit log line. `None` for anything that is not a record.
pub fn parse_record(line: &str) -> Option<Record> {
    let (raw, enriched) = match line.split_once('\u{1d}') {
        Some((raw, enriched)) => (raw, Some(enriched)),
        None => (line, None),
    };
    let at = raw.find("msg=audit(")?;
    let (head, rest) = raw.split_at(at);
    let rest = &rest["msg=audit(".len()..];
    let (stamp, body) = rest.split_once("):")?;
    let (time, serial) = stamp.split_once(':')?;
    let serial: u64 = serial.parse().ok()?;
    let ts_us = parse_time(time)?;

    let mut node = None;
    let mut kind = None;
    for (key, value) in tokens(head).filter_map(|t| match t {
        Token::Pair(k, v, _) => Some((k, v)),
        Token::Word(_) => None,
    }) {
        match key {
            "node" => node = Some(value.to_owned()),
            "type" => kind = Some(value.to_owned()),
            _ => {}
        }
    }
    let kind = kind.filter(|k| !k.is_empty() && k.len() <= 64)?;

    let mut fields = Map::new();
    fields.insert("type".into(), Value::from(kind.as_str()));
    let user_space = add_fields(&kind, body, &mut fields, true);
    if let Some(enriched) = enriched {
        add_fields(&kind, enriched, &mut fields, false);
    }
    Some(Record {
        stamp: stamp.to_owned(),
        ts_us,
        serial,
        node,
        kind,
        fields,
        user_space,
    })
}

/// `1729497600.123` as microseconds.
fn parse_time(s: &str) -> Option<u64> {
    let (secs, frac) = s.split_once('.').unwrap_or((s, ""));
    if secs.is_empty() || secs.len() > 12 || frac.len() > 9 {
        return None;
    }
    let secs: u64 = secs.parse().ok()?;
    let mut micros = 0u64;
    for (i, b) in frac.bytes().enumerate() {
        if !b.is_ascii_digit() {
            return None;
        }
        if i < 6 {
            micros = micros * 10 + u64::from(b - b'0');
        }
    }
    for _ in frac.len().min(6)..6 {
        micros *= 10;
    }
    secs.checked_mul(1_000_000)?.checked_add(micros)
}

#[derive(Debug, PartialEq)]
enum Token<'a> {
    /// `key=value`; the flag is the quote the value was in (`"`, `'` or none).
    Pair(&'a str, &'a str, Option<char>),
    /// A word without `=` (`avc:`, `denied`, `{`, `read`, `}`, `for`).
    Word(&'a str),
}

/// Split `key=value key2="quoted value" key3='nested msg'` into tokens. Quotes do not
/// escape: auditd hex-encodes any value that would need it.
fn tokens(s: &str) -> impl Iterator<Item = Token<'_>> {
    let mut rest = s;
    std::iter::from_fn(move || {
        rest = rest.trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            return None;
        }
        let word_end = rest.find([' ', '\t']).unwrap_or(rest.len());
        let eq = rest[..word_end].find('=');
        let Some(eq) = eq.filter(|&i| i > 0) else {
            let (word, r) = rest.split_at(word_end);
            rest = r;
            return Some(Token::Word(word));
        };
        let key = &rest[..eq];
        let after = &rest[eq + 1..];
        let quote = after.chars().next().filter(|c| *c == '"' || *c == '\'');
        let (value, r) = match quote {
            Some(q) => {
                let inner = &after[1..];
                match inner.find(q) {
                    Some(end) => (&inner[..end], &inner[end + 1..]),
                    // Unterminated: take the rest.
                    None => (inner, ""),
                }
            }
            None => {
                let end = after.find([' ', '\t']).unwrap_or(after.len());
                (&after[..end], &after[end..])
            }
        };
        rest = r;
        Some(Token::Pair(key, value, quote))
    })
}

/// Add the fields of `text` to `fields`, keeping fields already present. Returns whether a
/// nested `msg='...'` was found.
fn add_fields(kind: &str, text: &str, fields: &mut Map<String, Value>, nested: bool) -> bool {
    let mut words = Vec::new();
    let mut user_space = false;
    for token in tokens(text) {
        match token {
            Token::Word(w) => {
                if words.len() < 32 {
                    words.push(w);
                }
            }
            Token::Pair("msg", value, Some('\'')) if nested => {
                user_space = true;
                let before = fields.len();
                add_fields(kind, value, fields, false);
                if fields.len() == before {
                    insert(fields, "msg", value.to_owned());
                }
            }
            Token::Pair(key, value, quote) => {
                let value = if quote.is_none() && is_encoded(kind, key) {
                    decode_hex(kind, value).unwrap_or_else(|| value.to_owned())
                } else {
                    value.to_owned()
                };
                insert(fields, key, value);
            }
        }
    }
    // SELinux AVC: `avc:  denied  { read write } for ...`.
    if let Some(open) = words.iter().position(|w| *w == "{") {
        if let Some(close) = words[open..].iter().position(|w| *w == "}") {
            insert(fields, "seperms", words[open + 1..open + close].join(","));
        }
        if open > 0 {
            insert(fields, "seresult", words[open - 1].to_owned());
        }
    }
    user_space
}

fn insert(fields: &mut Map<String, Value>, key: &str, value: String) {
    if fields.len() < MAX_FIELDS && !fields.contains_key(key) && key.len() <= 64 {
        fields.insert(key.to_owned(), Value::String(value));
    }
}

fn is_encoded(kind: &str, key: &str) -> bool {
    if ENCODED.contains(&key) {
        return true;
    }
    // EXECVE arguments: a0, a1, ... and the chunks of long ones, a1[0], a1[1], ...
    kind == "EXECVE"
        && key
            .strip_prefix('a')
            .map(|n| n.split_once('[').map_or(n, |(n, _)| n))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Decode an unquoted hex value; `None` if it is not hex (`(null)`, `?`, a number).
fn decode_hex(kind: &str, value: &str) -> Option<String> {
    let b = value.as_bytes();
    if b.len() < 2 || !b.len().is_multiple_of(2) || !b.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut bytes: Vec<u8> = b
        .chunks(2)
        .map(|pair| (hex_digit(pair[0]) << 4) | hex_digit(pair[1]))
        .collect();
    if kind == "PROCTITLE" {
        // Arguments are NUL-separated.
        while bytes.last() == Some(&0) {
            bytes.pop();
        }
        for b in &mut bytes {
            if *b == 0 {
                *b = b' ';
            }
        }
    }
    // Several keys on one rule are joined with 0x01.
    for b in &mut bytes {
        if *b == 0x01 {
            *b = b',';
        }
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn hex_digit(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => b - b'A' + 10,
    }
}

#[derive(Debug)]
struct Group {
    stamp: String,
    ts_us: u64,
    serial: u64,
    node: Option<String>,
    records: Vec<Value>,
    bytes: usize,
    truncated: bool,
    /// File offset of the group's first record line.
    start: u64,
    last: Instant,
}

impl Group {
    fn finish(self) -> Event {
        let mut fields = Map::new();
        fields.insert("serial".into(), Value::from(self.serial));
        if let Some(node) = self.node {
            fields.insert("node".into(), Value::from(node));
        }
        fields.insert("records".into(), Value::Array(self.records));
        Event {
            ts_us: self.ts_us,
            fields,
            truncated: self.truncated,
        }
    }
}

/// Assembles the records of one audit log file into events.
#[derive(Debug)]
pub struct Assembler {
    max_bytes: usize,
    pending: Vec<Group>,
}

impl Assembler {
    /// `max_bytes` caps the raw record bytes kept per event (the rule's `max_line_bytes`).
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            pending: Vec::new(),
        }
    }

    /// File offset of the oldest unfinished event's first record.
    pub fn pending_start(&self) -> Option<u64> {
        self.pending.iter().map(|g| g.start).min()
    }

    /// Feed one line that starts at file offset `start`. Finished events go to `out`.
    pub fn push(
        &mut self,
        line: &[u8],
        truncated: bool,
        start: u64,
        now: Instant,
        out: &mut Vec<Event>,
    ) {
        let text = String::from_utf8_lossy(line);
        let Some(record) = parse_record(&text) else {
            if !line.is_empty() {
                log::debug!("skipped a line that is not an audit record");
            }
            return;
        };
        let idx = match self.pending.iter().position(|g| g.stamp == record.stamp) {
            Some(i) => i,
            // The end of an event already sent (read again after a restart).
            None if record.kind == "EOE" => return,
            None => {
                if self.pending.len() >= MAX_PENDING {
                    out.push(self.pending.remove(0).finish());
                }
                self.pending.push(Group {
                    stamp: record.stamp.clone(),
                    ts_us: record.ts_us,
                    serial: record.serial,
                    node: record.node.clone(),
                    records: Vec::new(),
                    bytes: 0,
                    truncated: false,
                    start,
                    last: now,
                });
                self.pending.len() - 1
            }
        };
        let group = &mut self.pending[idx];
        group.last = now;
        group.truncated |= truncated;
        if record.kind == "EOE" {
            out.push(self.pending.remove(idx).finish());
            return;
        }
        if group.records.len() >= MAX_RECORDS || group.bytes + line.len() > self.max_bytes {
            group.truncated = true;
        } else {
            group.bytes += line.len();
            group.records.push(Value::Object(record.fields));
        }
        let single =
            record.user_space || record.kind.starts_with("DAEMON_") || record.kind == "ANOM_ABEND";
        if single && group.records.len() == 1 {
            out.push(self.pending.remove(idx).finish());
        }
    }

    /// Finish events that have had no record for [`FLUSH_AFTER`].
    pub fn flush_idle(&mut self, now: Instant, out: &mut Vec<Event>) {
        let mut i = 0;
        while i < self.pending.len() {
            if now.saturating_duration_since(self.pending[i].last) >= FLUSH_AFTER {
                out.push(self.pending.remove(i).finish());
            } else {
                i += 1;
            }
        }
    }

    /// Finish every pending event (the file was rotated away or truncated).
    pub fn flush_all(&mut self, out: &mut Vec<Event>) {
        out.extend(self.pending.drain(..).map(Group::finish));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SYSCALL: &str = r#"type=SYSCALL msg=audit(1792569600.123:4567): arch=c000003e syscall=59 success=yes exit=0 a0=55d1c4a2b8f0 a1=55d1c4a2b950 a2=55d1c4a2b960 a3=8 items=2 ppid=1210 pid=1234 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="cat" exe="/usr/bin/cat" subj=unconfined key="exec""#;

    fn assemble(lines: &[&str]) -> (Vec<Event>, Assembler) {
        let mut a = Assembler::new(64 * 1024);
        let mut out = Vec::new();
        let now = Instant::now();
        let mut offset = 0u64;
        for line in lines {
            a.push(line.as_bytes(), false, offset, now, &mut out);
            offset += line.len() as u64 + 1;
        }
        (out, a)
    }

    #[test]
    fn parses_a_syscall_record() {
        let r = parse_record(SYSCALL).expect("record");
        assert_eq!(r.stamp, "1792569600.123:4567");
        assert_eq!(r.ts_us, 1_792_569_600_123_000);
        assert_eq!(r.serial, 4567);
        assert_eq!(r.kind, "SYSCALL");
        assert_eq!(r.fields["syscall"], "59");
        // SYSCALL a0..a3 are numbers, not encoded strings.
        assert_eq!(r.fields["a0"], "55d1c4a2b8f0");
        assert_eq!(r.fields["comm"], "cat");
        assert_eq!(r.fields["key"], "exec");
        assert!(!r.user_space);
    }

    #[test]
    fn decodes_hex_fields() {
        let r = parse_record(
            "type=PROCTITLE msg=audit(1792569600.123:4567): proctitle=636174002F6574632F736861646F77",
        )
        .expect("record");
        assert_eq!(r.fields["proctitle"], "cat /etc/shadow");
        let r = parse_record(
            r#"type=EXECVE msg=audit(1792569600.123:4567): argc=3 a0="bash" a1="-c" a2=6563686F202268692074686572652220263E2F6465762F6E756C6C"#,
        )
        .expect("record");
        assert_eq!(r.fields["a0"], "bash");
        assert_eq!(r.fields["a2"], "echo \"hi there\" &>/dev/null");
        let r = parse_record(
            "type=EXECVE msg=audit(1.0:1): argc=2 a0=\"x\" a1_len=8 a1[0]=41424344 a1[1]=45464748",
        )
        .expect("record");
        assert_eq!(r.fields["a1[0]"], "ABCD");
        assert_eq!(r.fields["a1_len"], "8");
        // (null) and odd-length values stay as written.
        let r = parse_record("type=PATH msg=audit(1.0:1): item=0 name=(null) inode=12 cwd=ABC")
            .expect("record");
        assert_eq!(r.fields["name"], "(null)");
        assert_eq!(r.fields["cwd"], "ABC");
        // Several keys.
        let r = parse_record("type=SYSCALL msg=audit(1.0:1): key=6964656E7469747901657463")
            .expect("record");
        assert_eq!(r.fields["key"], "identity,etc");
    }

    #[test]
    fn flattens_user_space_messages_and_enriched_fields() {
        let line = "type=USER_LOGIN msg=audit(1792569600.500:4570): pid=2001 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=login acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=? addr=203.0.113.50 terminal=sshd res=failed'\u{1d}UID=\"root\" AUID=\"unset\"";
        let r = parse_record(line).expect("record");
        assert!(r.user_space);
        assert_eq!(r.fields["op"], "login");
        assert_eq!(r.fields["acct"], "root");
        assert_eq!(r.fields["addr"], "203.0.113.50");
        assert_eq!(r.fields["res"], "failed");
        assert_eq!(r.fields["pid"], "2001");
        assert_eq!(r.fields["UID"], "root");
        assert!(!r.fields.contains_key("msg"));
        // A non key/value msg is kept as text.
        let r = parse_record("type=USER msg=audit(1.0:2): pid=1 msg='hello world'").expect("r");
        assert_eq!(r.fields["msg"], "hello world");
        // USER_CMD cmd is hex.
        let r = parse_record("type=USER_CMD msg=audit(1.0:3): pid=1 msg='cwd=\"/root\" cmd=6C73202D6C61 terminal=pts/0 res=success'").expect("r");
        assert_eq!(r.fields["cmd"], "ls -la");
    }

    #[test]
    fn avc_permissions() {
        let r = parse_record(r#"type=AVC msg=audit(1792569600.700:4580): avc:  denied  { read write } for  pid=812 comm="httpd" name="shadow" dev="dm-0" ino=1234 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0"#).expect("r");
        assert_eq!(r.fields["seresult"], "denied");
        assert_eq!(r.fields["seperms"], "read,write");
        assert_eq!(r.fields["tclass"], "file");
    }

    #[test]
    fn node_prefix() {
        let r = parse_record("node=web-01 type=EOE msg=audit(1.5:9): ").expect("r");
        assert_eq!(r.node.as_deref(), Some("web-01"));
        assert_eq!(r.kind, "EOE");
    }

    #[test]
    fn hostile_lines_are_refused_or_bounded() {
        for bad in [
            "",
            "garbage",
            "type=SYSCALL msg=audit(",
            "type=SYSCALL msg=audit(abc:1): x=1",
            "type=SYSCALL msg=audit(1.0:x): x=1",
            "msg=audit(1.0:1): no type",
            "type=SYSCALL msg=audit(99999999999999999999.0:1): x=1",
        ] {
            assert!(parse_record(bad).is_none(), "{bad:?}");
        }
        // Unterminated quotes and many fields.
        let r = parse_record("type=X msg=audit(1.0:1): a=\"open msg='also").expect("r");
        assert_eq!(r.fields["a"], "open msg='also");
        let many: String = (0..1000).map(|i| format!(" k{i}=v")).collect();
        let r = parse_record(&format!("type=X msg=audit(1.0:1):{many}")).expect("r");
        assert!(r.fields.len() <= MAX_FIELDS);
    }

    #[test]
    fn merges_records_by_serial_until_eoe() {
        let (events, a) = assemble(&[
            SYSCALL,
            r#"type=EXECVE msg=audit(1792569600.123:4567): argc=2 a0="cat" a1="/etc/shadow""#,
            r#"type=CWD msg=audit(1792569600.123:4567): cwd="/root""#,
            "type=PROCTITLE msg=audit(1792569600.123:4567): proctitle=636174002F6574632F736861646F77",
        ]);
        assert!(events.is_empty());
        assert_eq!(a.pending_start(), Some(0));
        let mut a = a;
        let mut events = events;
        a.push(
            b"type=EOE msg=audit(1792569600.123:4567): ",
            false,
            999,
            Instant::now(),
            &mut events,
        );
        assert_eq!(events.len(), 1);
        assert_eq!(a.pending_start(), None);
        let ev = &events[0];
        assert_eq!(ev.ts_us, 1_792_569_600_123_000);
        let fields = Value::Object(ev.fields.clone());
        assert_eq!(fields["serial"], 4567);
        let types: Vec<&str> = fields["records"]
            .as_array()
            .expect("records")
            .iter()
            .map(|r| r["type"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(types, ["SYSCALL", "EXECVE", "CWD", "PROCTITLE"]);
        assert_eq!(fields["records"][3]["proctitle"], "cat /etc/shadow");
    }

    #[test]
    fn interleaved_events_and_single_records() {
        let (events, a) = assemble(&[
            "type=SYSCALL msg=audit(10.000:1): syscall=59",
            "type=USER_AUTH msg=audit(10.001:2): pid=5 msg='op=PAM:authentication acct=\"alice\" res=success'",
            "type=PATH msg=audit(10.000:1): item=0 name=\"/bin/ls\"",
            "type=EOE msg=audit(10.000:1): ",
        ]);
        let serials: Vec<u64> = events
            .iter()
            .map(|e| e.fields["serial"].as_u64().unwrap_or_default())
            .collect();
        assert_eq!(serials, [2, 1]);
        assert_eq!(
            events[1].fields["records"],
            json!([{"type": "SYSCALL", "syscall": "59"}, {"type": "PATH", "item": "0", "name": "/bin/ls"}])
        );
        assert_eq!(a.pending_start(), None);
    }

    #[test]
    fn incomplete_groups_flush_after_a_timeout() {
        let mut a = Assembler::new(64 * 1024);
        let mut out = Vec::new();
        let t0 = Instant::now();
        a.push(
            b"type=SYSCALL msg=audit(10.000:1): syscall=2",
            false,
            0,
            t0,
            &mut out,
        );
        a.push(
            b"type=SYSCALL msg=audit(10.500:2): syscall=2",
            false,
            50,
            t0 + Duration::from_secs(1),
            &mut out,
        );
        a.flush_idle(t0 + Duration::from_millis(1500), &mut out);
        assert!(out.is_empty());
        a.flush_idle(t0 + Duration::from_millis(2100), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(a.pending_start(), Some(50));
        a.flush_all(&mut out);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn groups_are_bounded() {
        let mut a = Assembler::new(1024);
        let mut out = Vec::new();
        let now = Instant::now();
        for _ in 0..200 {
            a.push(
                b"type=PATH msg=audit(10.000:1): item=0 name=\"/x\"",
                false,
                0,
                now,
                &mut out,
            );
        }
        a.flush_all(&mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].truncated);
        assert!(out[0].fields["records"].as_array().expect("records").len() < 30);

        let mut a = Assembler::new(1 << 20);
        for _ in 0..(MAX_RECORDS + 10) {
            a.push(
                b"type=PATH msg=audit(10.000:1): item=0",
                false,
                0,
                now,
                &mut out,
            );
        }
        a.flush_all(&mut out);
        assert_eq!(
            out[1].fields["records"].as_array().expect("records").len(),
            MAX_RECORDS
        );

        // Too many open events: the oldest is finished early.
        let mut a = Assembler::new(1 << 20);
        let mut out = Vec::new();
        for serial in 0..(MAX_PENDING + 5) {
            let line = format!("type=SYSCALL msg=audit(10.000:{serial}): syscall=1");
            a.push(line.as_bytes(), false, serial as u64, now, &mut out);
        }
        assert_eq!(out.len(), 5);
        assert_eq!(out[0].fields["serial"], 0);
        assert_eq!(a.pending_start(), Some(5));
    }
}
