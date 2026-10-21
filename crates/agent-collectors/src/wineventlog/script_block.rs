//! PowerShell script block reassembly.
//!
//! PowerShell logs a long script block as several 4104 events that share a `ScriptBlockId`,
//! numbered `MessageNumber` 1 to `MessageTotal`, each with a slice of `ScriptBlockText`.
//! Detections need the whole script, so the collector holds the parts and sends one event:
//! the first part's event with the joined `ScriptBlockText`, `MessageNumber` and
//! `MessageTotal` both `"1"`, and `attrs.script_block_parts = {received, total}`.
//!
//! Limits, so hostile or broken input cannot grow memory: the joined text is capped at
//! [`MAX_SCRIPT_JSON_BYTES`] (as JSON, so the event still fits the default 256 KiB event
//! limit), at most [`MAX_PENDING`] script blocks are held, and a block that is still missing
//! parts after [`FLUSH_AFTER`] (or is pushed out by newer blocks) is sent with what arrived.
//! Capped or incomplete blocks carry `attrs.truncated = true`.
//!
//! While parts are held, the collector must not move its bookmark past them (see
//! [`ScriptBlocks::is_idle`]), so a restart reads them again instead of losing them.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::RawEvent;

/// Largest joined `ScriptBlockText`, measured as escaped JSON.
pub const MAX_SCRIPT_JSON_BYTES: usize = 192 * 1024;
/// Most script blocks waiting for parts at once.
pub const MAX_PENDING: usize = 16;
/// How long a script block waits for missing parts.
pub const FLUSH_AFTER: Duration = Duration::from_secs(15);
/// Larger `MessageTotal` values are not believed (the size cap is reached long before).
const MAX_PARTS: u32 = 10_000;
const PROVIDERS: &[&str] = &["Microsoft-Windows-PowerShell", "PowerShellCore"];

/// Script blocks waiting for their remaining parts.
#[derive(Debug, Default)]
pub struct ScriptBlocks {
    pending: Vec<Pending>,
}

#[derive(Debug)]
struct Pending {
    id: String,
    total: u32,
    /// The first part to arrive, without its text.
    event: RawEvent,
    /// Text per `MessageNumber`; empty once the cap is reached.
    parts: BTreeMap<u32, String>,
    json_bytes: usize,
    capped: bool,
    since: Instant,
}

struct Fragment {
    id: String,
    number: u32,
    total: u32,
    text: String,
}

impl ScriptBlocks {
    /// Feed one event. Returns the events to send now: `event` itself unless it is one part of
    /// a split script block, plus any block it completes or pushes out.
    pub fn push(&mut self, mut event: RawEvent, now: Instant) -> Vec<RawEvent> {
        let Some(fragment) = take_fragment(&mut event) else {
            return vec![event];
        };
        let mut out = Vec::new();
        let idx = match self.pending.iter().position(|p| p.id == fragment.id) {
            Some(idx) => idx,
            None => {
                if self.pending.len() >= MAX_PENDING {
                    out.push(self.pending.remove(0).finish());
                }
                self.pending.push(Pending {
                    id: fragment.id.clone(),
                    total: fragment.total,
                    event,
                    parts: BTreeMap::new(),
                    json_bytes: 0,
                    capped: false,
                    since: now,
                });
                self.pending.len() - 1
            }
        };
        let pending = &mut self.pending[idx];
        pending.add(fragment.number, &fragment.text);
        if pending.parts.len() as u32 >= pending.total {
            out.push(self.pending.remove(idx).finish());
        }
        out
    }

    /// Script blocks that waited [`FLUSH_AFTER`] for missing parts, with what arrived.
    pub fn flush_expired(&mut self, now: Instant) -> Vec<RawEvent> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.pending.len() {
            if now.saturating_duration_since(self.pending[i].since) >= FLUSH_AFTER {
                out.push(self.pending.remove(i).finish());
            } else {
                i += 1;
            }
        }
        out
    }

    /// No parts are held: every event read so far has been returned.
    pub fn is_idle(&self) -> bool {
        self.pending.is_empty()
    }
}

impl Pending {
    fn add(&mut self, number: u32, text: &str) {
        if self.parts.contains_key(&number) {
            return;
        }
        let mut kept = String::new();
        if !self.capped {
            for c in text.chars() {
                let n = json_len(c);
                if self.json_bytes + n > MAX_SCRIPT_JSON_BYTES {
                    self.capped = true;
                    break;
                }
                self.json_bytes += n;
                kept.push(c);
            }
        }
        self.parts.insert(number, kept);
    }

    fn finish(self) -> RawEvent {
        let Self {
            total,
            mut event,
            parts,
            capped,
            ..
        } = self;
        let received = parts.len();
        let text: String = parts.into_values().collect();
        if let Some(Value::Object(data)) = event.fields.get_mut("EventData") {
            data.insert("ScriptBlockText".into(), Value::String(text));
            data.insert("MessageNumber".into(), "1".into());
            data.insert("MessageTotal".into(), "1".into());
        }
        event.attrs.insert(
            "script_block_parts".into(),
            json!({"received": received, "total": total}),
        );
        if capped || received < total as usize {
            event.attrs.insert("truncated".into(), Value::Bool(true));
        }
        event
    }
}

/// If `event` is one part of a split 4104 script block, take its text out and describe it.
fn take_fragment(event: &mut RawEvent) -> Option<Fragment> {
    let system = event.fields.get("System")?;
    let id_matches = system.get("EventID").and_then(Value::as_u64) == Some(4104);
    let provider = system.get("Provider")?.get("Name")?.as_str()?;
    if !id_matches || !PROVIDERS.contains(&provider) {
        return None;
    }
    let data = event.fields.get_mut("EventData")?.as_object_mut()?;
    let number = |key: &str| data.get(key)?.as_str()?.trim().parse::<u32>().ok();
    let (number, total) = (number("MessageNumber")?, number("MessageTotal")?);
    if !(2..=MAX_PARTS).contains(&total) || !(1..=total).contains(&number) {
        return None;
    }
    let id = data.get("ScriptBlockId")?.as_str()?.trim();
    if id.is_empty() || id.len() > 64 {
        return None;
    }
    let id = id.to_ascii_lowercase();
    let Some(Value::String(text)) = data.remove("ScriptBlockText") else {
        return None;
    };
    Some(Fragment {
        id,
        number,
        total,
        text,
    })
}

/// Bytes `c` takes in a JSON string.
fn json_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
        c if (c as u32) < 0x20 => 6,
        c => c.len_utf8(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap as Map;

    use serde_json::json;

    use super::*;
    use crate::EventTemplate;
    use crate::wineventlog::event_xml_to_wef;

    fn template() -> EventTemplate {
        EventTemplate::new(
            "windows-powershell.operational",
            "windows.eventlog",
            None,
            &Map::new(),
        )
    }

    fn part(id: &str, number: u32, total: u32, text: &str) -> RawEvent {
        let fields = json!({
            "System": {"Provider": {"Name": "Microsoft-Windows-PowerShell"}, "EventID": 4104,
                       "EventRecordID": 100 + number, "Channel": "Microsoft-Windows-PowerShell/Operational",
                       "Computer": "web-01.example.com", "TimeCreated": {"SystemTime": "2026-10-21T08:00:00Z"}},
            "EventData": {"MessageNumber": number.to_string(), "MessageTotal": total.to_string(),
                          "ScriptBlockText": text, "ScriptBlockId": id, "Path": ""}
        });
        let Value::Object(fields) = fields else {
            unreachable!()
        };
        template().event(1, None, fields)
    }

    fn text(e: &RawEvent) -> &str {
        e.fields["EventData"]["ScriptBlockText"]
            .as_str()
            .expect("text")
    }

    #[test]
    fn fixture_parts_are_joined_in_order() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../presets/windows/fixtures/windows-powershell"
        );
        let read = |n: u32| {
            let xml =
                std::fs::read_to_string(format!("{dir}/4104-split-part{n}.xml")).expect("read");
            template().event(1, None, event_xml_to_wef(&xml).expect("parse"))
        };
        let now = Instant::now();
        for order in [[1, 2, 3], [3, 1, 2], [2, 3, 1]] {
            let mut blocks = ScriptBlocks::default();
            let mut out = Vec::new();
            for n in order {
                out.extend(blocks.push(read(n), now));
                if out.is_empty() {
                    assert!(!blocks.is_idle());
                }
            }
            assert!(blocks.is_idle());
            assert_eq!(out.len(), 1, "{order:?}");
            let e = &out[0];
            let script = text(e);
            assert!(
                script.starts_with("# Wedgetail fixture: part one."),
                "{script}"
            );
            assert!(script.contains("part two"));
            assert!(script.ends_with("Write-Output 'part three'\n"), "{script}");
            assert_eq!(e.fields["EventData"]["MessageNumber"], "1");
            assert_eq!(e.fields["EventData"]["MessageTotal"], "1");
            assert_eq!(
                e.fields["EventData"]["ScriptBlockId"],
                "{3f2504e0-4f89-41d3-9a0c-0305e82c3301}"
            );
            assert_eq!(
                e.attrs["script_block_parts"],
                json!({"received": 3, "total": 3})
            );
            assert!(e.attrs.get("truncated").is_none());
        }
    }

    #[test]
    fn other_events_pass_through_unchanged() {
        let mut blocks = ScriptBlocks::default();
        let now = Instant::now();
        let single = part("{a}", 1, 1, "Get-Date");
        assert_eq!(blocks.push(single.clone(), now), vec![single]);
        let mut other = part("{a}", 1, 3, "x");
        other.fields["System"]["EventID"] = json!(4103);
        assert_eq!(blocks.push(other.clone(), now), vec![other]);
        let mut other = part("{a}", 1, 3, "x");
        other.fields["System"]["Provider"]["Name"] = json!("Some-Other-Provider");
        assert_eq!(blocks.push(other.clone(), now), vec![other]);
        assert!(blocks.is_idle());
    }

    #[test]
    fn hostile_part_numbers_pass_through() {
        let mut blocks = ScriptBlocks::default();
        let now = Instant::now();
        for (number, total) in [
            ("0", "3"),
            ("4", "3"),
            ("1", "0"),
            ("x", "3"),
            ("1", "99999"),
            ("1", "-2"),
        ] {
            let mut e = part("{a}", 1, 3, "x");
            e.fields["EventData"]["MessageNumber"] = json!(number);
            e.fields["EventData"]["MessageTotal"] = json!(total);
            assert_eq!(blocks.push(e.clone(), now), vec![e]);
        }
        let mut e = part(&"a".repeat(65), 1, 3, "x");
        assert_eq!(blocks.push(e.clone(), now), vec![e.clone()]);
        e.fields["EventData"]
            .as_object_mut()
            .expect("data")
            .remove("ScriptBlockText");
        e.fields["EventData"]["ScriptBlockId"] = json!("{b}");
        assert_eq!(blocks.push(e.clone(), now), vec![e]);
        assert!(blocks.is_idle());
    }

    #[test]
    fn duplicates_and_interleaved_blocks() {
        let mut blocks = ScriptBlocks::default();
        let now = Instant::now();
        assert!(blocks.push(part("{A}", 1, 2, "a1"), now).is_empty());
        assert!(blocks.push(part("{b}", 1, 2, "b1"), now).is_empty());
        assert!(blocks.push(part("{a}", 1, 2, "again"), now).is_empty());
        let out = blocks.push(part("{a}", 2, 2, "a2"), now);
        assert_eq!(out.len(), 1);
        assert_eq!(text(&out[0]), "a1a2");
        assert!(!blocks.is_idle());
        let out = blocks.push(part("{b}", 2, 2, "b2"), now);
        assert_eq!(text(&out[0]), "b1b2");
        assert!(blocks.is_idle());
    }

    #[test]
    fn size_is_capped_as_json() {
        let mut blocks = ScriptBlocks::default();
        let now = Instant::now();
        // Quotes double when escaped, so the cap is reached at half the characters.
        let chunk = "\"".repeat(40_000);
        let mut out = Vec::new();
        for n in 1..=5 {
            out.extend(blocks.push(part("{a}", n, 5, &chunk), now));
        }
        assert_eq!(out.len(), 1);
        let e = &out[0];
        assert_eq!(text(e).len(), MAX_SCRIPT_JSON_BYTES / 2);
        assert_eq!(e.attrs["truncated"], true);
        assert_eq!(
            e.attrs["script_block_parts"],
            json!({"received": 5, "total": 5})
        );
        assert!(e.to_wire_line().len() < 256 * 1024);
    }

    #[test]
    fn missing_parts_are_flushed_after_the_timeout() {
        let mut blocks = ScriptBlocks::default();
        let now = Instant::now();
        assert!(blocks.push(part("{a}", 1, 3, "a1"), now).is_empty());
        assert!(blocks.push(part("{a}", 3, 3, "a3"), now).is_empty());
        assert!(blocks.flush_expired(now + FLUSH_AFTER / 2).is_empty());
        let out = blocks.flush_expired(now + FLUSH_AFTER);
        assert_eq!(out.len(), 1);
        assert_eq!(text(&out[0]), "a1a3");
        assert_eq!(out[0].attrs["truncated"], true);
        assert_eq!(
            out[0].attrs["script_block_parts"],
            json!({"received": 2, "total": 3})
        );
        // The first part's record is kept.
        assert_eq!(out[0].fields["System"]["EventRecordID"], 101);
        assert!(blocks.is_idle());
    }

    #[test]
    fn oldest_block_is_pushed_out_when_too_many_wait() {
        let mut blocks = ScriptBlocks::default();
        let now = Instant::now();
        for i in 0..MAX_PENDING {
            assert!(
                blocks
                    .push(part(&format!("{{{i}}}"), 1, 2, "x"), now)
                    .is_empty()
            );
        }
        let out = blocks.push(part("{new}", 1, 2, "y"), now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].fields["EventData"]["ScriptBlockId"], "{0}");
        assert_eq!(out[0].attrs["truncated"], true);
        assert_eq!(blocks.pending.len(), MAX_PENDING);
    }
}
