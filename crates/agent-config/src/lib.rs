//! Configuration for the Wedgetail agent.
//!
//! The agent reads one `agent.toml` and then every `*.toml` file in the `rules.d` directory
//! next to it, in file name order. Both files use the same `[[rule]]` table, so a rule can live
//! in either place.
//!
//! This crate holds only what the runtime needs today: where to ship, where to keep state, the
//! buffer and batch limits, and the collector rules. New settings are added as new fields with
//! serde defaults so existing files keep loading; unknown keys are rejected so typos are caught
//! by `wedgetail-agent check-config` instead of being silently ignored.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub mod paths;

/// Default disk buffer cap in MiB.
pub const DEFAULT_BUFFER_MAX_MB: u64 = 256;
/// Server limit on a compressed request body (bytes).
pub const SERVER_MAX_BODY_BYTES: u64 = 1024 * 1024;
/// Server limit on a decompressed request body (bytes).
pub const SERVER_MAX_DECOMPRESSED_BYTES: u64 = 8 * 1024 * 1024;
/// Server limit on records per request.
pub const SERVER_MAX_RECORDS: u32 = 5_000;
/// Server limit on requests per minute for one host credential.
pub const SERVER_MAX_REQUESTS_PER_MINUTE: u32 = 120;
/// Largest config or rules file the loader will read.
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

/// The whole agent configuration after `agent.toml` and `rules.d/*.toml` are merged.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Base URL of the Wedgetail ingest endpoint, `https://` only.
    pub endpoint: String,
    /// Directory for the disk buffer, checkpoints and status file.
    #[serde(default = "paths::default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default)]
    pub buffer: BufferConfig,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
    /// Collector rules, from `[[rule]]` tables.
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BufferConfig {
    /// Disk buffer cap in MiB. When full, the oldest events are dropped and counted.
    pub max_mb: u64,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            max_mb: DEFAULT_BUFFER_MAX_MB,
        }
    }
}

/// Shipping limits. Defaults are the server limits; they can be lowered, not raised.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Largest gzip request body in bytes.
    pub max_batch_bytes: u64,
    /// Largest request body before compression, in bytes.
    pub max_batch_uncompressed_bytes: u64,
    /// Most records in one request.
    pub max_batch_records: u32,
    /// Most requests per rolling minute.
    pub max_requests_per_minute: u32,
    /// Largest single event line in bytes; larger events are dropped and counted as oversize.
    pub max_event_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_batch_bytes: SERVER_MAX_BODY_BYTES,
            max_batch_uncompressed_bytes: SERVER_MAX_DECOMPRESSED_BYTES,
            max_batch_records: SERVER_MAX_RECORDS,
            max_requests_per_minute: SERVER_MAX_REQUESTS_PER_MINUTE,
            max_event_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HeartbeatConfig {
    pub interval_s: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self { interval_s: 60 }
    }
}

/// The collector a rule runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// Tail one or more text files.
    File,
    /// Follow the systemd journal (Linux).
    Journald,
    /// Subscribe to a Windows Event Log channel (Windows).
    Wineventlog,
    /// Stream the macOS unified log (macOS).
    MacosUnified,
}

impl RuleKind {
    /// The `source_type` used on the wire when a rule does not set one.
    pub fn default_source_type(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Journald => "journald",
            Self::Wineventlog => "windows.eventlog",
            Self::MacosUnified => "macos.unified",
        }
    }
}

/// Where a file collector starts when it has no checkpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartAt {
    /// Only lines written after the agent starts (default).
    #[default]
    End,
    /// The whole existing file.
    Beginning,
}

/// One `[[rule]]` table. Fields that do not apply to the rule's `type` must be left out.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Unique id, `[a-z0-9][a-z0-9._-]{0,63}`. Sent as `rule_id`.
    pub id: String,
    #[serde(rename = "type")]
    pub kind: RuleKind,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Wire `source_type`; defaults per `type`.
    #[serde(default)]
    pub source_type: Option<String>,
    /// Free-text label sent in `attrs.source_label`, for example `web/nginx`.
    #[serde(default)]
    pub source_label: Option<String>,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,

    /// `file`: absolute paths to tail.
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// `file`: where to start without a checkpoint.
    #[serde(default)]
    pub start_at: StartAt,

    /// `journald`: `FIELD=value` matches passed to journalctl (same field is ORed, different
    /// fields are ANDed).
    #[serde(default)]
    pub matches: Vec<String>,

    /// `wineventlog`: channel name, for example `Security`.
    #[serde(default)]
    pub channel: Option<String>,
    /// `wineventlog`: event ids to select (empty means all). Ignored if `xpath` is set.
    #[serde(default)]
    pub event_ids: Vec<u32>,
    /// `wineventlog`: raw XPath filter, for example `*[System[Level<=3]]`.
    #[serde(default)]
    pub xpath: Option<String>,

    /// `macos_unified`: `log stream --predicate` filter.
    #[serde(default)]
    pub predicate: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Rule {
    /// The `source_type` this rule's events carry.
    pub fn source_type(&self) -> &str {
        self.source_type
            .as_deref()
            .unwrap_or(self.kind.default_source_type())
    }
}

/// A configuration problem, with the file it came from where known.
#[derive(Debug)]
pub struct ConfigError {
    pub file: Option<PathBuf>,
    pub message: String,
}

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            file: None,
            message: message.into(),
        }
    }

    fn in_file(file: &Path, message: impl Into<String>) -> Self {
        Self {
            file: Some(file.to_path_buf()),
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.file {
            Some(file) => write!(f, "{}: {}", file.display(), self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    #[serde(default, rename = "rule")]
    rules: Vec<Rule>,
}

impl AgentConfig {
    /// Load `path`, then `rules.d/*.toml` next to it, then validate.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = read_bounded(path)?;
        let mut config = Self::parse(&text).map_err(|e| ConfigError::in_file(path, e.message))?;
        let rules_dir = path.parent().unwrap_or(Path::new(".")).join("rules.d");
        for file in rule_files(&rules_dir)? {
            let text = read_bounded(&file)?;
            let parsed: RulesFile =
                toml::from_str(&text).map_err(|e| ConfigError::in_file(&file, e.to_string()))?;
            config.rules.extend(parsed.rules);
        }
        config.validate()?;
        Ok(config)
    }

    /// Parse one `agent.toml` document without reading `rules.d` or validating.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::new(e.to_string()))
    }

    /// The endpoint without a trailing slash.
    pub fn endpoint_base(&self) -> &str {
        self.endpoint.trim_end_matches('/')
    }

    /// Check values the type system cannot: endpoint scheme, limits, rule ids and per-type
    /// fields.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_endpoint(&self.endpoint)?;
        if !(16..=65_536).contains(&self.buffer.max_mb) {
            return Err(ConfigError::new(
                "buffer.max_mb must be between 16 and 65536",
            ));
        }
        let l = &self.limits;
        check_range(
            "limits.max_batch_bytes",
            l.max_batch_bytes,
            1024,
            SERVER_MAX_BODY_BYTES,
        )?;
        check_range(
            "limits.max_batch_uncompressed_bytes",
            l.max_batch_uncompressed_bytes,
            1024,
            SERVER_MAX_DECOMPRESSED_BYTES,
        )?;
        check_range(
            "limits.max_batch_records",
            l.max_batch_records.into(),
            1,
            SERVER_MAX_RECORDS.into(),
        )?;
        check_range(
            "limits.max_requests_per_minute",
            l.max_requests_per_minute.into(),
            1,
            SERVER_MAX_REQUESTS_PER_MINUTE.into(),
        )?;
        check_range(
            "limits.max_event_bytes",
            l.max_event_bytes,
            1024,
            l.max_batch_bytes,
        )?;
        check_range("heartbeat.interval_s", self.heartbeat.interval_s, 10, 3600)?;

        let mut ids = HashSet::new();
        for rule in &self.rules {
            validate_rule(rule)?;
            if !ids.insert(rule.id.as_str()) {
                return Err(ConfigError::new(format!(
                    "rule id {:?} is used more than once",
                    rule.id
                )));
            }
        }
        Ok(())
    }
}

fn check_range(name: &str, value: u64, min: u64, max: u64) -> Result<(), ConfigError> {
    if value < min || value > max {
        return Err(ConfigError::new(format!(
            "{name} must be between {min} and {max}, got {value}"
        )));
    }
    Ok(())
}

fn read_bounded(path: &Path) -> Result<String, ConfigError> {
    let meta = std::fs::metadata(path).map_err(|e| ConfigError::in_file(path, e.to_string()))?;
    if meta.len() > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigError::in_file(path, "file is larger than 1 MiB"));
    }
    std::fs::read_to_string(path).map_err(|e| ConfigError::in_file(path, e.to_string()))
}

fn rule_files(dir: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(ConfigError::in_file(dir, e.to_string())),
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| ConfigError::in_file(dir, e.to_string()))?
            .path();
        if path.extension().is_some_and(|ext| ext == "toml") && path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// `https://host[:port][/path]`, no credentials, query or fragment.
pub fn validate_endpoint(endpoint: &str) -> Result<(), ConfigError> {
    let Some(rest) = endpoint.strip_prefix("https://") else {
        return Err(ConfigError::new("endpoint must start with https://"));
    };
    let authority = rest.split('/').next().unwrap_or("");
    let bad = authority.is_empty()
        || endpoint.len() > 2048
        || endpoint
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || endpoint.contains(['@', '?', '#', '\\']);
    if bad {
        return Err(ConfigError::new(
            "endpoint must be https://host[:port][/path] with no credentials, query or fragment",
        ));
    }
    Ok(())
}

/// `[a-z0-9][a-z0-9._-]{0,63}`.
pub fn is_valid_rule_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

fn validate_rule(rule: &Rule) -> Result<(), ConfigError> {
    let id = &rule.id;
    let err = |m: &str| Err(ConfigError::new(format!("rule {id:?}: {m}")));
    if !is_valid_rule_id(id) {
        return err("id must match [a-z0-9][a-z0-9._-]{0,63}");
    }
    if let Some(st) = &rule.source_type
        && (st.is_empty()
            || st.len() > 64
            || !st
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
    {
        return err("source_type must be 1-64 characters of [A-Za-z0-9._-]");
    }
    if rule
        .source_label
        .as_ref()
        .is_some_and(|l| l.len() > 256 || l.chars().any(char::is_control))
    {
        return err("source_label must be at most 256 characters with no control characters");
    }
    if rule.tags.len() > 32
        || rule
            .tags
            .iter()
            .any(|(k, v)| k.is_empty() || k.len() > 64 || v.len() > 256)
    {
        return err("at most 32 tags, keys 1-64 characters, values up to 256");
    }

    let has_file = !rule.paths.is_empty() || rule.start_at != StartAt::End;
    let has_journald = !rule.matches.is_empty();
    let has_win = rule.channel.is_some() || !rule.event_ids.is_empty() || rule.xpath.is_some();
    let has_macos = rule.predicate.is_some();
    let (own, others) = match rule.kind {
        RuleKind::File => (has_file, has_journald || has_win || has_macos),
        RuleKind::Journald => (true, has_file || has_win || has_macos),
        RuleKind::Wineventlog => (true, has_file || has_journald || has_macos),
        RuleKind::MacosUnified => (true, has_file || has_journald || has_win),
    };
    if others {
        return err("has fields that do not apply to its type");
    }
    match rule.kind {
        RuleKind::File => {
            if !own {
                return err("type \"file\" needs at least one path");
            }
            if rule.paths.len() > 64 {
                return err("at most 64 paths");
            }
            if let Some(p) = rule.paths.iter().find(|p| !p.is_absolute()) {
                return err(&format!("path {} must be absolute", p.display()));
            }
        }
        RuleKind::Journald => {
            if let Some(m) = rule.matches.iter().find(|m| !is_valid_journal_match(m)) {
                return err(&format!(
                    "journald match {m:?} must be FIELD=value with FIELD in [A-Z0-9_]"
                ));
            }
        }
        RuleKind::Wineventlog => {
            let channel = rule.channel.as_deref().unwrap_or("");
            if channel.is_empty() || channel.len() > 256 || channel.chars().any(char::is_control) {
                return err("type \"wineventlog\" needs a channel of 1-256 characters");
            }
            if rule
                .xpath
                .as_ref()
                .is_some_and(|x| x.is_empty() || x.len() > 4096 || x.contains('\0'))
            {
                return err("xpath must be 1-4096 characters");
            }
            if rule.event_ids.iter().any(|&id| id == 0 || id > 65_535) || rule.event_ids.len() > 256
            {
                return err("event_ids must be 1-65535, at most 256 of them");
            }
        }
        RuleKind::MacosUnified => {
            if rule
                .predicate
                .as_ref()
                .is_some_and(|p| p.is_empty() || p.len() > 4096 || p.contains('\0'))
            {
                return err("predicate must be 1-4096 characters");
            }
        }
    }
    Ok(())
}

fn is_valid_journal_match(m: &str) -> bool {
    let Some((field, value)) = m.split_once('=') else {
        return false;
    };
    !field.is_empty()
        && field.len() <= 64
        && field
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && value.len() <= 1024
        && !value.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> String {
        "endpoint = \"https://ingest.example.com/\"\n".to_owned()
    }

    fn parse_ok(extra: &str) -> AgentConfig {
        let config = AgentConfig::parse(&(base() + extra)).expect("parses");
        config.validate().expect("valid");
        config
    }

    fn parse_err(extra: &str) -> String {
        match AgentConfig::parse(&(base() + extra)) {
            Ok(config) => config
                .validate()
                .expect_err("should be invalid")
                .to_string(),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn defaults() {
        let config = parse_ok("");
        assert_eq!(config.endpoint_base(), "https://ingest.example.com");
        assert_eq!(config.buffer.max_mb, 256);
        assert_eq!(config.limits.max_batch_bytes, 1024 * 1024);
        assert_eq!(config.limits.max_batch_records, 5000);
        assert_eq!(config.limits.max_requests_per_minute, 120);
        assert_eq!(config.heartbeat.interval_s, 60);
        assert_eq!(config.state_dir, paths::default_state_dir());
    }

    #[test]
    fn rules_of_each_type() {
        let config = parse_ok(
            r#"
[[rule]]
id = "local.nginx"
type = "file"
paths = ["/var/log/nginx/access.log"]
source_label = "web/nginx"
tags = { env = "prod" }

[[rule]]
id = "ssh"
type = "journald"
matches = ["_SYSTEMD_UNIT=ssh.service"]

[[rule]]
id = "security"
type = "wineventlog"
channel = "Security"
event_ids = [4624, 4625]

[[rule]]
id = "macos.auth"
type = "macos_unified"
predicate = "subsystem == \"com.apple.Authorization\""
"#,
        );
        assert_eq!(config.rules.len(), 4);
        assert_eq!(config.rules[0].source_type(), "file");
        assert_eq!(config.rules[2].source_type(), "windows.eventlog");
        assert_eq!(config.rules[3].source_type(), "macos.unified");
    }

    #[test]
    fn rejects_plain_http_and_odd_endpoints() {
        for endpoint in [
            "http://ingest.example.com",
            "https://",
            "https://user:pw@ingest.example.com",
            "https://ingest.example.com/?x=1",
            "https://ingest.example.com/#x",
            "https://ingest example.com",
            "ftp://ingest.example.com",
        ] {
            assert!(validate_endpoint(endpoint).is_err(), "{endpoint}");
        }
        assert!(validate_endpoint("https://ingest-01.example.net").is_ok());
        assert!(validate_endpoint("https://ingest.example.com:8443/base").is_ok());
    }

    #[test]
    fn rejects_unknown_keys_and_limits_above_server() {
        assert!(parse_err("colour = 1").contains("unknown field"));
        assert!(parse_err("[limits]\nmax_batch_records = 5001").contains("max_batch_records"));
        assert!(parse_err("[limits]\nmax_batch_bytes = 2097152").contains("max_batch_bytes"));
        assert!(
            parse_err("[limits]\nmax_requests_per_minute = 121")
                .contains("max_requests_per_minute")
        );
        assert!(parse_err("[buffer]\nmax_mb = 1").contains("buffer.max_mb"));
    }

    #[test]
    fn rejects_bad_rules() {
        let bad = [
            (
                "[[rule]]\nid = \"Bad\"\ntype = \"file\"\npaths = [\"/x\"]",
                "id must match",
            ),
            ("[[rule]]\nid = \"a\"\ntype = \"file\"", "at least one path"),
            (
                "[[rule]]\nid = \"a\"\ntype = \"file\"\npaths = [\"rel/x\"]",
                "absolute",
            ),
            (
                "[[rule]]\nid = \"a\"\ntype = \"file\"\npaths = [\"/x\"]\nchannel = \"Security\"",
                "do not apply",
            ),
            (
                "[[rule]]\nid = \"a\"\ntype = \"journald\"\nmatches = [\"unit\"]",
                "FIELD=value",
            ),
            (
                "[[rule]]\nid = \"a\"\ntype = \"journald\"\nmatches = [\"_unit=x\"]",
                "FIELD=value",
            ),
            (
                "[[rule]]\nid = \"a\"\ntype = \"wineventlog\"",
                "needs a channel",
            ),
            (
                "[[rule]]\nid = \"a\"\ntype = \"wineventlog\"\nchannel = \"S\"\nevent_ids = [0]",
                "event_ids",
            ),
            ("[[rule]]\nid = \"a\"\ntype = \"syslog\"", "unknown variant"),
            (
                "[[rule]]\nid = \"a\"\ntype = \"journald\"\n[[rule]]\nid = \"a\"\ntype = \"journald\"",
                "more than once",
            ),
            (
                "[[rule]]\nid = \"a\"\ntype = \"journald\"\nsource_type = \"a b\"",
                "source_type",
            ),
        ];
        for (extra, want) in bad {
            let got = parse_err(extra);
            assert!(got.contains(want), "{extra:?}: {got}");
        }
    }

    #[test]
    fn load_merges_rules_d_in_name_order() {
        let dir = std::env::temp_dir().join(format!("wt-config-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rules.d")).expect("mkdir");
        std::fs::write(
            dir.join("agent.toml"),
            base() + "[[rule]]\nid = \"a\"\ntype = \"journald\"\n",
        )
        .expect("write");
        std::fs::write(
            dir.join("rules.d/20-c.toml"),
            "[[rule]]\nid = \"c\"\ntype = \"journald\"\n",
        )
        .expect("write");
        std::fs::write(
            dir.join("rules.d/10-b.toml"),
            "[[rule]]\nid = \"b\"\ntype = \"journald\"\n",
        )
        .expect("write");
        std::fs::write(dir.join("rules.d/notes.txt"), "ignored").expect("write");
        let config = AgentConfig::load(&dir.join("agent.toml")).expect("loads");
        let ids: Vec<_> = config.rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["a", "b", "c"]);

        std::fs::write(dir.join("rules.d/30-bad.toml"), "[[rule]]\nid = \"d\"\n").expect("write");
        let err = AgentConfig::load(&dir.join("agent.toml")).expect_err("bad file");
        assert!(err.to_string().contains("30-bad.toml"), "{err}");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
