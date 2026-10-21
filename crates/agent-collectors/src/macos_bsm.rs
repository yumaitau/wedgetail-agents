//! macOS OpenBSM audit trail, read from `/var/audit` and converted with `praudit`.
//!
//! auditd writes binary BSM records to `/var/audit/<start>.not_terminated` and points the
//! `/var/audit/current` symlink at it; on rotation the file is renamed `<start>.<end>` and a
//! new one is started. The collector reads complete records from the trail file itself (each
//! record starts with a header token holding its length and ends with a trailer token
//! repeating it), so the checkpoint is a byte offset like a file rule's. Each chunk of records
//! is piped through `/usr/sbin/praudit -x -r` (XML, numeric form: times in epoch seconds,
//! numeric ids and errors, so nothing depends on the time zone or the user database) and the
//! XML is turned into `fields`. Event names and classes come from `/etc/security/audit_event`.
//!
//! Framing, the event table and the XML conversion are portable and tested everywhere; the
//! collector is macOS only.

use std::collections::HashMap;

use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use serde_json::{Map, Value};

use crate::MAX_LINE_BYTES;

/// Largest record accepted. The kernel's limit is far lower; anything bigger is corrupt.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
/// Most string bytes kept per record (token values and arguments). The rest is dropped and
/// the event is marked `attrs.truncated`, so a huge command line cannot push the event over
/// the agent's event size limit and get it dropped whole.
const MAX_RECORD_STRING_BYTES: usize = 128 * 1024;
/// Most tokens and most `exec_args`/`exec_env` entries kept per record.
const MAX_TOKENS: usize = 256;
const MAX_ARGS: usize = 1024;

const HEADER_TOKENS: [u8; 4] = [0x14, 0x15, 0x74, 0x79];
const TRAILER_TOKEN: u8 = 0x13;
const TRAILER_MAGIC: [u8; 2] = [0xb1, 0x05];
/// Header id + length + version + event + modifier + time, plus the 7-byte trailer.
const MIN_RECORD_BYTES: usize = 18 + 7;

/// Tokens that may appear more than once in a record; always sent as arrays.
const REPEATED: &[&str] = &["text", "path", "attribute", "argument", "arbitrary"];

/// Complete records found at the start of a buffer.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Frames {
    /// The complete records, back to back, ready for `praudit`.
    pub data: Vec<u8>,
    pub records: usize,
    /// Bytes of the buffer used up: records plus skipped bytes. The offset advances by this.
    pub consumed: usize,
    /// Bytes skipped because they were not a valid record.
    pub skipped: usize,
}

/// Split up to `max_records` complete records off the start of `buf`. Bytes that are not a
/// valid record are skipped until the next valid header. A record that is valid so far but
/// not complete yet ends the scan; it is read again on the next call.
pub fn frame_records(buf: &[u8], max_records: usize) -> Frames {
    let mut f = Frames::default();
    let mut pos = 0;
    while pos < buf.len() && f.records < max_records {
        match record_len(&buf[pos..]) {
            Some(Ok(len)) => {
                f.data.extend_from_slice(&buf[pos..pos + len]);
                f.records += 1;
                pos += len;
            }
            Some(Err(())) => {
                pos += 1;
                f.skipped += 1;
            }
            None => break,
        }
    }
    f.consumed = pos;
    f
}

/// `Some(Ok(len))` for a complete record, `None` when `buf` may be the start of one that is
/// still being written, `Some(Err(()))` when it is not a record.
fn record_len(buf: &[u8]) -> Option<Result<usize, ()>> {
    if !HEADER_TOKENS.contains(&buf[0]) {
        return Some(Err(()));
    }
    let len_bytes = buf.get(1..5)?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
    let len = len as usize;
    if !(MIN_RECORD_BYTES..=MAX_RECORD_BYTES).contains(&len) {
        return Some(Err(()));
    }
    let record = buf.get(..len)?;
    let trailer = &record[len - 7..];
    let valid = trailer[0] == TRAILER_TOKEN
        && trailer[1..3] == TRAILER_MAGIC
        && trailer[3..7] == record[1..5];
    Some(if valid { Ok(len) } else { Err(()) })
}

/// Event numbers to names and classes, from `/etc/security/audit_event`
/// (`45028:AUE_sudo:sudo(1):aa`).
#[derive(Debug, Default)]
pub struct EventTable(HashMap<u32, (String, Vec<String>)>);

impl EventTable {
    pub fn parse(text: &str) -> Self {
        let mut map = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split(':');
            let (Some(num), Some(name), Some(_desc), Some(classes)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let Ok(num) = num.parse::<u32>() else {
                continue;
            };
            let classes = classes
                .split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(str::to_owned)
                .collect();
            map.insert(num, (name.to_owned(), classes));
        }
        Self(map)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One converted audit record.
#[derive(Debug, PartialEq)]
pub struct BsmRecord {
    pub ts_us: u64,
    pub fields: Map<String, Value>,
    /// Some strings were dropped to stay within the per-record budget.
    pub truncated: bool,
}

/// What [`parse_praudit`] found.
#[derive(Debug, Default)]
pub struct Parsed {
    pub records: Vec<BsmRecord>,
    /// Records outside the wanted classes.
    pub filtered: usize,
    /// Records that could not be converted (no valid time, malformed XML).
    pub errors: usize,
}

#[derive(Debug, Default)]
struct Token {
    name: String,
    attrs: Vec<(String, String)>,
    text: String,
    /// `<arg>`/`<env>` children of `exec_args`/`exec_env`.
    items: Vec<String>,
}

#[derive(Debug, Default)]
struct Record {
    attrs: Vec<(String, String)>,
    tokens: Vec<Token>,
    budget: usize,
    truncated: bool,
}

impl Record {
    /// Take up to the remaining budget of `s`.
    fn keep(&mut self, s: &str) -> Option<String> {
        if self.budget == 0 {
            self.truncated |= !s.is_empty();
            return None;
        }
        let limit = self.budget.min(MAX_LINE_BYTES);
        let kept = cut(s, limit);
        if kept.len() < s.len() {
            self.truncated = true;
        }
        self.budget -= kept.len();
        Some(kept)
    }
}

/// Convert `praudit -x -r` output. Records whose event is in none of `classes` are counted as
/// filtered (every record is kept when `classes` is empty).
pub fn parse_praudit(xml: &str, table: &EventTable, classes: &[String]) -> Parsed {
    let mut out = Parsed::default();
    let mut reader = quick_xml::Reader::from_str(xml);
    // Depth 0: document, 1: <audit>, 2: <record>, 3: token, 4: arg/env.
    let mut depth = 0usize;
    let mut record: Option<Record> = None;
    loop {
        let event = match reader.read_event() {
            Ok(e) => e,
            Err(_) => {
                // praudit stops at a record it cannot decode, leaving it unclosed.
                record.get_or_insert_default();
                break;
            }
        };
        match event {
            Event::Start(e) => {
                depth += 1;
                open(&mut record, depth, &e);
            }
            Event::Empty(e) => {
                open(&mut record, depth + 1, &e);
                if depth + 1 == 2 {
                    finish(&mut record, table, classes, &mut out);
                }
            }
            Event::End(_) => {
                if depth == 2 {
                    finish(&mut record, table, classes, &mut out);
                }
                depth = depth.saturating_sub(1);
            }
            Event::Text(t) => text(&mut record, depth, &t.xml_content(XmlVersion::Implicit1_0)),
            Event::CData(t) => text(&mut record, depth, &t.xml_content(XmlVersion::Implicit1_0)),
            Event::GeneralRef(r) => {
                let resolved = match r.resolve_char_ref() {
                    Ok(Some(c)) => c.to_string(),
                    _ => resolve_predefined_entity(&r).unwrap_or_default().to_owned(),
                };
                text(&mut record, depth, &resolved);
            }
            Event::DocType(_) => {
                record.get_or_insert_default();
                break;
            }
            Event::Eof => break,
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) => {}
        }
    }
    if record.is_some() {
        out.errors += 1;
    }
    out
}

fn attrs(e: &BytesStart<'_>) -> Vec<(String, String)> {
    e.attributes()
        .filter_map(Result::ok)
        .filter_map(|a| {
            let key = a.key.as_ref().replace('-', "_");
            let value = a.normalized_value(XmlVersion::Implicit1_0).ok()?;
            Some((key, value.into_owned()))
        })
        .collect()
}

fn open(record: &mut Option<Record>, depth: usize, e: &BytesStart<'_>) {
    let name = e.local_name();
    let name: &str = name.as_ref();
    match depth {
        2 if name == "record" => {
            *record = Some(Record {
                attrs: attrs(e),
                budget: MAX_RECORD_STRING_BYTES,
                ..Record::default()
            });
        }
        3 => {
            if let Some(r) = record {
                if r.tokens.len() >= MAX_TOKENS {
                    r.truncated = true;
                    return;
                }
                let mut token = Token {
                    name: name.replace('-', "_"),
                    ..Token::default()
                };
                for (k, v) in attrs(e) {
                    if let Some(v) = r.keep(&v) {
                        token.attrs.push((k, v));
                    }
                }
                r.tokens.push(token);
            }
        }
        // `<arg>`/`<env>`: the text that follows is one item.
        4 => {
            if let Some(r) = record
                && let Some(token) = r.tokens.last_mut()
            {
                if token.items.len() >= MAX_ARGS {
                    r.truncated = true;
                } else {
                    token.items.push(String::new());
                }
            }
        }
        _ => {}
    }
}

fn text(record: &mut Option<Record>, depth: usize, s: &str) {
    let Some(r) = record else { return };
    if !(3..=4).contains(&depth) || r.tokens.is_empty() {
        return;
    }
    let Some(kept) = r.keep(s) else { return };
    let Some(token) = r.tokens.last_mut() else {
        return;
    };
    if depth == 3 {
        token.text.push_str(&kept);
    } else if let Some(item) = token.items.last_mut() {
        item.push_str(&kept);
    }
}

fn finish(record: &mut Option<Record>, table: &EventTable, classes: &[String], out: &mut Parsed) {
    let Some(r) = record.take() else { return };
    let attr = |k: &str| {
        r.attrs
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.trim())
    };
    let secs = attr("time").and_then(|t| t.parse::<u64>().ok());
    let msec = attr("msec")
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(0);
    let (Some(secs), Some(event_id)) = (secs, attr("event").and_then(|e| e.parse::<u32>().ok()))
    else {
        out.errors += 1;
        return;
    };
    let (name, event_classes) = match table.0.get(&event_id) {
        Some((name, c)) => (name.clone(), c.clone()),
        None => (event_id.to_string(), Vec::new()),
    };
    if !classes.is_empty() && !event_classes.iter().any(|c| classes.contains(c)) {
        out.filtered += 1;
        return;
    }

    let mut fields = Map::new();
    fields.insert("event".into(), Value::String(name));
    fields.insert("event_id".into(), Value::from(event_id));
    fields.insert(
        "classes".into(),
        Value::Array(event_classes.into_iter().map(Value::String).collect()),
    );
    if let Some(m) = attr("modifier").and_then(|m| m.parse::<u64>().ok()) {
        fields.insert("modifier".into(), Value::from(m));
    }
    for token in r.tokens {
        let value = if matches!(token.name.as_str(), "exec_args" | "exec_env") {
            Value::Array(token.items.into_iter().map(Value::String).collect())
        } else if token.attrs.is_empty() {
            Value::String(token.text)
        } else {
            let mut obj: Map<String, Value> = token
                .attrs
                .into_iter()
                .map(|(k, v)| (k, Value::String(v)))
                .collect();
            if !token.text.trim().is_empty() {
                obj.insert("value".into(), Value::String(token.text));
            }
            Value::Object(obj)
        };
        if REPEATED.contains(&token.name.as_str()) {
            match fields
                .entry(token.name)
                .or_insert_with(|| Value::Array(Vec::new()))
            {
                Value::Array(items) => items.push(value),
                other => *other = Value::Array(vec![other.take(), value]),
            }
            continue;
        }
        match fields.get_mut(&token.name) {
            Some(Value::Array(items)) => items.push(value),
            Some(existing) => {
                let first = existing.take();
                *existing = Value::Array(vec![first, value]);
            }
            None => {
                fields.insert(token.name, value);
            }
        }
    }
    out.records.push(BsmRecord {
        ts_us: secs.saturating_mul(1_000_000) + msec.min(999) * 1000,
        fields,
        truncated: r.truncated,
    });
}

fn cut(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

#[cfg(target_os = "macos")]
pub use collector::BsmTrail;

#[cfg(target_os = "macos")]
mod collector {
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use serde_json::Value;

    use super::{EventTable, frame_records, parse_praudit};
    use crate::{Batch, Checkpoint, Collector, CollectorError, EventTemplate, FilePosition};

    pub const AUDIT_DIR: &str = "/var/audit";
    pub const AUDIT_EVENT: &str = "/etc/security/audit_event";
    const PRAUDIT: &str = "/usr/sbin/praudit";
    /// Bytes of trail read per `praudit` run.
    const CHUNK_BYTES: usize = 512 * 1024;
    /// Largest `praudit` output read for one chunk.
    const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
    const CHECK_INTERVAL: Duration = Duration::from_millis(500);

    #[derive(Debug)]
    struct Trail {
        file: File,
        path: PathBuf,
        dev: u64,
        ino: u64,
        offset: u64,
    }

    impl Trail {
        fn open(path: &Path, offset: Option<u64>) -> Result<Self, CollectorError> {
            let mut file =
                File::open(path).map_err(|e| CollectorError(format!("{}: {e}", path.display())))?;
            let meta = file.metadata()?;
            // No offset: start at the end, like a file rule's `start_at = "end"`.
            let offset = match offset {
                Some(o) if o <= meta.len() => o,
                Some(_) => 0,
                None => meta.len(),
            };
            file.seek(SeekFrom::Start(offset))?;
            Ok(Self {
                file,
                path: path.to_owned(),
                dev: meta.dev(),
                ino: meta.ino(),
                offset,
            })
        }
    }

    /// The `macos_bsm` collector.
    #[derive(Debug)]
    pub struct BsmTrail {
        template: EventTemplate,
        classes: Vec<String>,
        dir: PathBuf,
        event_file: PathBuf,
        table: EventTable,
        trail: Option<Trail>,
        buf: Vec<u8>,
    }

    impl BsmTrail {
        pub fn new(template: EventTemplate, classes: Vec<String>) -> Self {
            Self::with_paths(template, classes, AUDIT_DIR.into(), AUDIT_EVENT.into())
        }

        /// A trail directory and event table other than the system ones (tests).
        pub fn with_paths(
            template: EventTemplate,
            classes: Vec<String>,
            dir: PathBuf,
            event_file: PathBuf,
        ) -> Self {
            Self {
                template,
                classes,
                dir,
                event_file,
                table: EventTable::default(),
                trail: None,
                buf: Vec::new(),
            }
        }

        /// The active trail file, `current` resolved.
        fn current(&self) -> Result<PathBuf, CollectorError> {
            let link = self.dir.join("current");
            fs::canonicalize(&link).map_err(|e| {
                CollectorError(format!(
                    "no active audit trail ({}: {e}); is auditd running?",
                    link.display()
                ))
            })
        }

        /// The file in the trail directory with this identity (a rotated, renamed trail).
        fn find(&self, dev: u64, ino: u64) -> Option<PathBuf> {
            fs::read_dir(&self.dir)
                .ok()?
                .filter_map(Result::ok)
                .find(|e| {
                    e.metadata()
                        .is_ok_and(|m| m.is_file() && m.dev() == dev && m.ino() == ino)
                })
                .map(|e| e.path())
        }

        /// Read and convert the next complete records of the open trail.
        fn read(
            &mut self,
            max_events: usize,
            events: &mut Vec<crate::RawEvent>,
        ) -> Result<bool, CollectorError> {
            let Some(trail) = &mut self.trail else {
                return Ok(false);
            };
            self.buf.resize(CHUNK_BYTES, 0);
            let mut filled = 0;
            while filled < self.buf.len() {
                let n = trail.file.read(&mut self.buf[filled..])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            let frames = frame_records(&self.buf[..filled], max_events.max(1));
            if frames.skipped > 0 {
                log::warn!(
                    "{}: skipped {} bytes that are not audit records",
                    trail.path.display(),
                    frames.skipped
                );
            }
            // Leave the file positioned just after what was used.
            trail.offset += frames.consumed as u64;
            trail.file.seek(SeekFrom::Start(trail.offset))?;
            if frames.records == 0 {
                return Ok(frames.consumed > 0);
            }
            let xml = run_praudit(&frames.data)?;
            let parsed = parse_praudit(&xml, &self.table, &self.classes);
            if parsed.errors > 0 {
                log::warn!(
                    "{}: {} audit records could not be converted",
                    trail.path.display(),
                    parsed.errors
                );
            }
            let path = Value::String(trail.path.display().to_string());
            for record in parsed.records {
                let mut event = self.template.event(record.ts_us, None, record.fields);
                event.attrs.insert("path".into(), path.clone());
                if record.truncated {
                    event.attrs.insert("truncated".into(), Value::Bool(true));
                }
                events.push(event);
            }
            Ok(true)
        }

        fn checkpoint(&self) -> Option<Checkpoint> {
            let t = self.trail.as_ref()?;
            let mut files = BTreeMap::new();
            files.insert(
                t.path.clone(),
                FilePosition {
                    dev: t.dev,
                    ino: t.ino,
                    offset: t.offset,
                },
            );
            Some(Checkpoint::File { files })
        }
    }

    /// `praudit -x -r` over `data`, fed on stdin.
    fn run_praudit(data: &[u8]) -> Result<String, CollectorError> {
        let mut child = Command::new(PRAUDIT)
            .args(["-x", "-r"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| CollectorError(format!("cannot start {PRAUDIT}: {e}")))?;
        let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            return Err(CollectorError(format!("{PRAUDIT}: no stdin/stdout pipe")));
        };
        let mut out = Vec::new();
        // Write on another thread so a full stdout pipe cannot deadlock the two.
        let read = thread::scope(|s| {
            s.spawn(move || {
                let _ = stdin.write_all(data);
            });
            stdout.take(MAX_OUTPUT_BYTES).read_to_end(&mut out)
        });
        // praudit exits 1 even after a clean read to the end of its input, so the status says
        // nothing; a record it could not decode shows up as unconverted XML instead.
        let _ = child.wait();
        read?;
        // Text tokens may hold any bytes; praudit copies them as they are.
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    impl Collector for BsmTrail {
        fn rule_id(&self) -> &str {
            &self.template.rule_id
        }

        fn start(&mut self, checkpoint: Option<Checkpoint>) -> Result<(), CollectorError> {
            let text = fs::read_to_string(&self.event_file)
                .map_err(|e| CollectorError(format!("{}: {e}", self.event_file.display())))?;
            self.table = EventTable::parse(&text);
            let current = self.current()?;
            let saved = match checkpoint {
                Some(Checkpoint::File { files }) => files.into_iter().next(),
                _ => None,
            };
            let previous = self.trail.take().map(|t| {
                (
                    t.path,
                    FilePosition {
                        dev: t.dev,
                        ino: t.ino,
                        offset: t.offset,
                    },
                )
            });
            self.trail = Some(match saved.or(previous) {
                Some((_, pos)) => match self.find(pos.dev, pos.ino) {
                    // The trail we were reading, possibly renamed by a rotation since.
                    Some(path) => Trail::open(&path, Some(pos.offset))?,
                    // Gone: everything in the current trail is new to us.
                    None => Trail::open(&current, Some(0))?,
                },
                None => Trail::open(&current, None)?,
            });
            Ok(())
        }

        fn poll(&mut self, max_events: usize, wait: Duration) -> Result<Batch, CollectorError> {
            let deadline = Instant::now() + wait;
            let mut events = Vec::new();
            loop {
                let progressed = self.read(max_events, &mut events)?;
                if !events.is_empty() {
                    break;
                }
                if !progressed {
                    // Nothing new: has auditd moved on to a new trail? The old one was
                    // read to the end above, after the rotation, so nothing is lost.
                    let current = self.current()?;
                    let meta = fs::metadata(&current)?;
                    if self
                        .trail
                        .as_ref()
                        .is_some_and(|t| (t.dev, t.ino) != (meta.dev(), meta.ino()))
                    {
                        log::info!("audit trail rotated to {}", current.display());
                        self.trail = Some(Trail::open(&current, Some(0))?);
                        continue;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    thread::sleep(CHECK_INTERVAL.min(deadline - now));
                } else if Instant::now() >= deadline {
                    break;
                }
            }
            Ok(Batch {
                events,
                checkpoint: self.checkpoint(),
            })
        }
    }
}

#[cfg(test)]
mod tests;
