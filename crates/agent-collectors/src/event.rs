use std::collections::BTreeMap;
use std::path::PathBuf;

use agent_config::Rule;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::time;

/// Wire format version, the `v` of every NDJSON line.
pub const WIRE_VERSION: u32 = 1;

/// One host event, as it travels through the pipeline and onto the wire.
///
/// Host identity is deliberately absent: the server stamps it from the credential.
#[derive(Debug, Clone, PartialEq)]
pub struct RawEvent {
    pub source_type: String,
    pub rule_id: String,
    /// Event time, microseconds since the Unix epoch (UTC).
    pub ts_us: u64,
    /// The raw line or message after redaction; `None` when `fields` already holds it.
    pub body: Option<String>,
    /// Structured fields from the source or a parser.
    pub fields: Map<String, Value>,
    /// Agent-side context: `source_label`, `tags`, `path`, `truncated`.
    pub attrs: Map<String, Value>,
}

#[derive(Serialize)]
struct WireLine<'a> {
    v: u32,
    source_type: &'a str,
    rule_id: &'a str,
    ts: String,
    body: Option<&'a str>,
    fields: &'a Map<String, Value>,
    attrs: &'a Map<String, Value>,
}

impl RawEvent {
    /// Serialise as one NDJSON line (no trailing newline).
    pub fn to_wire_line(&self) -> Vec<u8> {
        let line = WireLine {
            v: WIRE_VERSION,
            source_type: &self.source_type,
            rule_id: &self.rule_id,
            ts: time::format_rfc3339_us(self.ts_us),
            body: self.body.as_deref(),
            fields: &self.fields,
            attrs: &self.attrs,
        };
        // Serialising maps of strings and JSON values cannot fail.
        serde_json::to_vec(&line).unwrap_or_default()
    }
}

/// The per-rule parts every event from a collector shares.
#[derive(Debug, Clone)]
pub struct EventTemplate {
    pub rule_id: String,
    pub source_type: String,
    attrs: Map<String, Value>,
}

impl EventTemplate {
    pub fn from_rule(rule: &Rule) -> Self {
        Self::new(
            &rule.id,
            rule.source_type(),
            rule.source_label.as_deref(),
            &rule.tags,
        )
    }

    pub fn new(
        rule_id: &str,
        source_type: &str,
        source_label: Option<&str>,
        tags: &BTreeMap<String, String>,
    ) -> Self {
        let mut attrs = Map::new();
        if let Some(label) = source_label {
            attrs.insert("source_label".into(), label.into());
        }
        if !tags.is_empty() {
            let tags = tags
                .iter()
                .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
                .collect();
            attrs.insert("tags".into(), Value::Object(tags));
        }
        Self {
            rule_id: rule_id.to_owned(),
            source_type: source_type.to_owned(),
            attrs,
        }
    }

    /// A new event carrying this rule's id, source type, label and tags.
    pub fn event(&self, ts_us: u64, body: Option<String>, fields: Map<String, Value>) -> RawEvent {
        RawEvent {
            source_type: self.source_type.clone(),
            rule_id: self.rule_id.clone(),
            ts_us,
            body,
            fields,
            attrs: self.attrs.clone(),
        }
    }
}

/// Where a file collector is up to in one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePosition {
    /// File identity: device and inode on Unix, volume serial and file index on Windows.
    pub dev: u64,
    pub ino: u64,
    /// Byte offset just after the last complete line handed to the pipeline.
    pub offset: u64,
}

/// A collector's resume position, saved by the runtime after events are buffered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Checkpoint {
    File {
        files: BTreeMap<PathBuf, FilePosition>,
    },
    Journald {
        cursor: String,
    },
    Wineventlog {
        bookmark_xml: String,
    },
    /// Unified log: newest event time seen and the hashes of events in the overlap window
    /// before it, so a catch-up read can skip what was already sent.
    MacosUnified {
        ts: String,
        seen: Vec<String>,
    },
    /// lastlog summary: the file modification time (microseconds) last summarised.
    Lastlog {
        mtime_us: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_line_matches_contract() {
        let mut tags = BTreeMap::new();
        tags.insert("env".to_owned(), "prod".to_owned());
        let template =
            EventTemplate::new("linux-core.auth", "linux.auth", Some("web/nginx"), &tags);
        let mut ev = template.event(
            1_792_569_600_123_456,
            Some("sshd[1]: hello".into()),
            Map::new(),
        );
        ev.attrs.insert("path".into(), "/var/log/auth.log".into());
        let line = String::from_utf8(ev.to_wire_line()).expect("utf8");
        assert_eq!(
            line,
            r#"{"v":1,"source_type":"linux.auth","rule_id":"linux-core.auth","ts":"2026-10-21T08:00:00.123456Z","body":"sshd[1]: hello","fields":{},"attrs":{"path":"/var/log/auth.log","source_label":"web/nginx","tags":{"env":"prod"}}}"#
        );
        assert!(!line.contains('\n'));
    }

    #[test]
    fn checkpoint_round_trips() {
        let cps = [
            Checkpoint::Journald {
                cursor: "s=abc;i=1".into(),
            },
            Checkpoint::Wineventlog {
                bookmark_xml: "<BookmarkList/>".into(),
            },
            Checkpoint::MacosUnified {
                ts: "2026-10-21T08:00:00.000000Z".into(),
                seen: vec!["ab".into()],
            },
            Checkpoint::Lastlog { mtime_us: 1 },
        ];
        for cp in cps {
            let json = serde_json::to_string(&cp).expect("ser");
            assert_eq!(serde_json::from_str::<Checkpoint>(&json).expect("de"), cp);
        }
    }
}
