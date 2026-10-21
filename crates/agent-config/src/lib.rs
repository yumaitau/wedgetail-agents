//! Configuration for the Wedgetail agent: `agent.toml`, `rules.d/*.toml` and built-in presets.
//!
//! The agent reads one `agent.toml`, then every `*.toml` file in the `rules.d` directory next
//! to it in file name order. Built-in [presets] load first. Every file uses the same schema
//! (version 1, see `schema/rules.v1.json` and `docs/rules.md`): `rules.d` files and presets
//! hold only `schema_version` and `[[rule]]` tables, `agent.toml` also holds the agent
//! settings.
//!
//! Unknown keys are rejected so typos are caught by `wedgetail-agent check-config` instead of
//! being silently ignored. Every problem is reported with its file and line. New settings are
//! added as optional fields so files written for schema 1 keep loading in later agents.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};
use toml::Spanned;

pub mod compile;
pub mod linux;
pub mod multiline;
pub mod parsers;
pub mod paths;
pub mod presets;
mod validate;

pub use compile::CompiledRule;
pub use parsers::Parser;
pub use presets::Preset;

/// The only schema version this agent reads.
pub const SCHEMA_VERSION: u32 = 1;
/// Default disk buffer cap in MiB.
pub const DEFAULT_BUFFER_MAX_MB: u64 = 256;
/// Default cap on files tailed at once, across all `file` rules.
pub const DEFAULT_MAX_OPEN_FILES: u32 = 1000;
/// Default longest line a `file` rule keeps; the rest is cut and `attrs.truncated` is set.
pub const DEFAULT_MAX_LINE_BYTES: u32 = 64 * 1024;
/// Default `multiline.max_lines`.
pub const DEFAULT_MULTILINE_MAX_LINES: u32 = 500;
/// Default replacement text for a `redact` entry.
pub const DEFAULT_REDACTION: &str = "[REDACTED]";
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
/// Most `rules.d` files read.
const MAX_RULE_FILES: usize = 1000;

/// The whole agent configuration after presets, `agent.toml` and `rules.d/*.toml` are merged.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Base URL of the Wedgetail ingest endpoint, `https://` only.
    pub endpoint: String,
    /// Directory for the disk buffer, checkpoints, status file and credential.
    pub state_dir: PathBuf,
    pub buffer: BufferConfig,
    pub limits: Limits,
    pub heartbeat: HeartbeatConfig,
    /// Collector rules: presets first, then `agent.toml`, then `rules.d` in file name order.
    pub rules: Vec<Rule>,
    /// Preset selection as written (`["auto"]` when not set).
    pub preset_selection: Vec<String>,
    /// Ids of the presets that were loaded, reported in the heartbeat.
    pub presets: Vec<String>,
    /// Rule ids switched off with `disable_rules`.
    pub disable_rules: Vec<String>,
    /// Most files tailed at once across all `file` rules.
    pub max_open_files: u32,
    /// Directory holding `agent.toml` and `rules.d`; `None` for a config parsed from text.
    pub config_dir: Option<PathBuf>,
    /// Things worth telling the operator that do not stop the agent.
    pub warnings: Vec<String>,
    lines: SettingLines,
}

/// Where the agent settings were written, for error messages.
#[derive(Debug, Clone, Default)]
struct SettingLines {
    file: Option<PathBuf>,
    endpoint: Option<usize>,
    buffer: Option<usize>,
    limits: Option<usize>,
    heartbeat: Option<usize>,
    presets: Option<usize>,
    disable_rules: Vec<usize>,
    max_open_files: Option<usize>,
}

/// `[buffer]` (deprecated: use `[agent] buffer_max_mb`).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Deserialize, JsonSchema)]
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

/// `[heartbeat]`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct HeartbeatConfig {
    /// Seconds between `agent.heartbeat` events, 10 to 3600.
    pub interval_s: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self { interval_s: 60 }
    }
}

/// The collector a rule runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema)]
#[schemars(rename_all = "snake_case")]
pub enum RuleKind {
    /// Tail one or more text files.
    File,
    /// Follow the systemd journal (Linux).
    Journald,
    /// Subscribe to a Windows Event Log channel (Windows).
    Wineventlog,
    /// Stream the macOS unified log (macOS).
    MacosUnified,
    /// Read the OpenBSM audit trail in `/var/audit` (macOS).
    MacosBsm,
}

impl RuleKind {
    pub const NAMES: &[&str] = &[
        "file",
        "journald",
        "wineventlog",
        "macos_unified",
        "macos_bsm",
    ];

    /// The `source_type` used on the wire when a rule does not set one.
    pub fn default_source_type(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Journald => "journald",
            Self::Wineventlog => "windows.eventlog",
            Self::MacosUnified => "macos.unified",
            Self::MacosBsm => "macos.bsm",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Journald => "journald",
            Self::Wineventlog => "wineventlog",
            Self::MacosUnified => "macos_unified",
            Self::MacosBsm => "macos_bsm",
        }
    }
}

// Hand-written so `type = "command"` gets a clear answer instead of "unknown variant".
impl<'de> Deserialize<'de> for RuleKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let name = String::deserialize(deserializer)?;
        match name.as_str() {
            "file" => Ok(Self::File),
            "journald" => Ok(Self::Journald),
            "wineventlog" => Ok(Self::Wineventlog),
            "macos_unified" => Ok(Self::MacosUnified),
            "macos_bsm" => Ok(Self::MacosBsm),
            "command" => Err(D::Error::custom(
                "type \"command\" (running scripts) is not supported: the agent never runs \
                 commands",
            )),
            other => Err(D::Error::unknown_variant(other, Self::NAMES)),
        }
    }
}

/// Where a file collector starts when it has no checkpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StartAt {
    /// Only lines written after the agent starts (default).
    #[default]
    End,
    /// The whole existing file.
    Beginning,
}

/// How a `file` rule turns a line into `fields`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ParserKind {
    /// No parsing: the line is sent as `body` only (default).
    #[default]
    Raw,
    /// One JSON object per line.
    Json,
    /// BSD syslog (`Oct 21 08:00:00 host app[pid]: message`, also with an RFC 3339 time).
    SyslogRfc3164,
    /// RFC 5424 syslog (`<34>1 2026-10-21T08:00:00Z host app pid msgid [sd] message`).
    SyslogRfc5424,
    /// ArcSight Common Event Format (`CEF:0|vendor|product|...|ext`).
    Cef,
    /// `key=value key2="quoted value"`.
    Logfmt,
    /// The rule's `regex`; named captures become fields.
    Regex,
    /// nginx `combined` access log.
    NginxCombined,
    /// Apache `combined` access log.
    ApacheCombined,
}

impl ParserKind {
    pub const ALL: &[Self] = &[
        Self::Raw,
        Self::Json,
        Self::SyslogRfc3164,
        Self::SyslogRfc5424,
        Self::Cef,
        Self::Logfmt,
        Self::Regex,
        Self::NginxCombined,
        Self::ApacheCombined,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Json => "json",
            Self::SyslogRfc3164 => "syslog_rfc3164",
            Self::SyslogRfc5424 => "syslog_rfc5424",
            Self::Cef => "cef",
            Self::Logfmt => "logfmt",
            Self::Regex => "regex",
            Self::NginxCombined => "nginx_combined",
            Self::ApacheCombined => "apache_combined",
        }
    }
}

/// How a `file` rule turns the bytes of a file into events.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileFormat {
    /// Text lines (default), joined by `multiline` and parsed by `parser`.
    #[default]
    Lines,
    /// The Linux audit log: records with the same serial are merged into one event.
    Auditd,
    /// Binary login records (`/var/log/wtmp`, `/var/log/btmp`), glibc layout.
    Utmp,
    /// Binary `/var/log/lastlog`, sent as a periodic summary rather than raw records.
    Lastlog,
}

impl FileFormat {
    pub fn name(self) -> &'static str {
        match self {
            Self::Lines => "lines",
            Self::Auditd => "auditd",
            Self::Utmp => "utmp",
            Self::Lastlog => "lastlog",
        }
    }
}

/// Which side of a matching line the continuation lines join.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MultilineMatch {
    /// Continuation lines join the line before them (default).
    #[default]
    After,
    /// Continuation lines join the line after them.
    Before,
}

/// `multiline = { pattern = '^\d{4}-', negate = true, match = "after", max_lines = 500 }`.
///
/// A line is a continuation when it matches `pattern` (or, with `negate`, when it does not).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MultilineConfig {
    /// Regular expression tested against each line.
    pub pattern: String,
    /// Treat lines that do NOT match `pattern` as continuations.
    #[serde(default)]
    pub negate: bool,
    /// `after` (default) or `before`.
    #[serde(default, rename = "match")]
    pub match_: MultilineMatch,
    /// Most lines in one event (1 to 10,000, default 500).
    #[serde(default = "default_multiline_max_lines")]
    pub max_lines: u32,
}

fn default_multiline_max_lines() -> u32 {
    DEFAULT_MULTILINE_MAX_LINES
}

/// `redact = [{ pattern = 'password=\S+', replace = "password=[REDACTED]" }]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Redaction {
    /// Regular expression; every match is replaced before the event is buffered.
    pub pattern: String,
    /// Literal replacement text (no `$1` expansion). Default `[REDACTED]`.
    #[serde(default = "default_redaction")]
    pub replace: String,
}

fn default_redaction() -> String {
    DEFAULT_REDACTION.to_owned()
}

/// `rate_limit = { events_per_second = 500, burst = 2000 }`: a token bucket per rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    /// Sustained events per second, 1 to 1,000,000.
    pub events_per_second: u32,
    /// Events allowed in a burst above the rate; defaults to `events_per_second`.
    #[serde(default)]
    pub burst: Option<u32>,
}

impl RateLimit {
    pub fn burst(&self) -> u32 {
        self.burst.unwrap_or(self.events_per_second)
    }
}

/// `macos_unified`: the least severe level streamed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Default-level messages and above.
    Default,
    /// Info and above (default).
    #[default]
    Info,
    /// Everything, including debug messages (noisy).
    Debug,
}

impl LogLevel {
    pub fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

/// Where a rule was defined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// The file, or `preset:<id>` for a built-in preset.
    pub file: PathBuf,
    /// 1-based line of the rule table.
    pub line: usize,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file.display(), self.line)
    }
}

/// One `[[rule]]` table. Fields that do not apply to the rule's `type` must be left out.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Unique id, `[a-z0-9][a-z0-9._-]{0,63}`. Sent as `rule_id`; used by `disable_rules`.
    #[schemars(regex(pattern = r"^[a-z0-9][a-z0-9._-]{0,63}$"))]
    pub id: String,
    /// `file`, `journald`, `wineventlog`, `macos_unified` or `macos_bsm`.
    #[serde(rename = "type")]
    pub kind: RuleKind,
    /// Set to `false` to keep a rule without running it.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Wire `source_type`; defaults per `type`.
    #[serde(default)]
    pub source_type: Option<String>,
    /// Free-text label sent in `attrs.source_label`, for example `web/nginx`.
    #[serde(default)]
    pub source_label: Option<String>,
    /// Key/value tags sent in `attrs.tags`.
    #[serde(default)]
    pub tags: BTreeMap<String, String>,

    /// Keep only events matching at least one of these regular expressions.
    #[serde(default)]
    pub include_match: Vec<String>,
    /// Drop events matching any of these regular expressions.
    #[serde(default)]
    pub exclude_match: Vec<String>,
    /// Replacements applied before the event is written to the disk buffer.
    #[serde(default)]
    pub redact: Vec<Redaction>,
    /// Fraction of events kept, `0 < sample_rate <= 1` (default 1).
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
    /// Token bucket; events over the limit are dropped and counted.
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,

    /// `file`: absolute paths or glob patterns (`*`, `?`, `[a-z]`, `**`).
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// `file`: `lines` (default), `auditd` (audit records merged per event), `utmp` (binary
    /// wtmp/btmp records) or `lastlog` (binary lastlog, summarised).
    #[serde(default)]
    pub format: FileFormat,
    /// `file`: glob patterns of files to skip. A pattern with a path separator is matched
    /// against the whole path, otherwise against the file name.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// `file`: where to start without a checkpoint.
    #[serde(default)]
    pub start_at: StartAt,
    /// `file`: join continuation lines (stack traces) into one event.
    #[serde(default)]
    pub multiline: Option<MultilineConfig>,
    /// `file`: how lines become `fields` (default `raw`).
    #[serde(default)]
    pub parser: ParserKind,
    /// `file` with `parser = "regex"`: the expression; named captures become fields.
    #[serde(default)]
    pub regex: Option<String>,
    /// `file`: longest line kept, 256 to 1,048,576 bytes (default 65,536).
    #[serde(default)]
    pub max_line_bytes: Option<u32>,

    /// `journald`: `FIELD=value` matches passed to journalctl (same field is ORed, different
    /// fields are ANDed).
    #[serde(default)]
    pub matches: Vec<String>,
    /// `journald`: systemd units, for example `ssh.service` (`.service` is added when there
    /// is no suffix).
    #[serde(default)]
    pub units: Vec<String>,
    /// `journald`: keep priorities 0 (emerg) to this value, 0 to 7.
    #[serde(default)]
    #[schemars(range(min = 0, max = 7))]
    pub priority_max: Option<u8>,

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
    /// `macos_unified`: `default`, `info` (default) or `debug`.
    #[serde(default)]
    pub level: Option<LogLevel>,

    /// `macos_bsm`: audit classes to keep (`lo`, `aa`, `ad`, `ex`, ...); empty keeps every
    /// event in the trail.
    #[serde(default)]
    pub classes: Vec<String>,

    /// Where the rule was defined. Set by the loader.
    #[serde(skip)]
    #[schemars(skip)]
    pub origin: Option<Origin>,
}

fn default_true() -> bool {
    true
}

fn default_sample_rate() -> f64 {
    1.0
}

impl Rule {
    /// The `source_type` this rule's events carry.
    pub fn source_type(&self) -> &str {
        self.source_type
            .as_deref()
            .unwrap_or(self.kind.default_source_type())
    }

    /// `file`: the longest line kept.
    pub fn max_line_bytes(&self) -> usize {
        self.max_line_bytes.unwrap_or(DEFAULT_MAX_LINE_BYTES) as usize
    }

    /// `journald`: the `units` as `_SYSTEMD_UNIT=` matches followed by `matches`.
    pub fn journal_matches(&self) -> Vec<String> {
        self.units
            .iter()
            .map(|u| {
                if u.contains('.') {
                    format!("_SYSTEMD_UNIT={u}")
                } else {
                    format!("_SYSTEMD_UNIT={u}.service")
                }
            })
            .chain(self.matches.iter().cloned())
            .collect()
    }
}

/// One configuration problem, with the file and line it came from where known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub file: Option<PathBuf>,
    pub line: Option<usize>,
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.file, self.line) {
            (Some(file), Some(line)) => write!(f, "{}:{line}: {}", file.display(), self.message),
            (Some(file), None) => write!(f, "{}: {}", file.display(), self.message),
            (None, Some(line)) => write!(f, "line {line}: {}", self.message),
            (None, None) => f.write_str(&self.message),
        }
    }
}

/// Everything wrong with a configuration. Displays one problem per line.
#[derive(Debug, Clone)]
pub struct ConfigError {
    pub problems: Vec<Problem>,
}

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            problems: vec![Problem {
                file: None,
                line: None,
                message: message.into(),
            }],
        }
    }

    fn in_file(file: &Path, message: impl Into<String>) -> Self {
        Self {
            problems: vec![Problem {
                file: Some(file.to_path_buf()),
                line: None,
                message: message.into(),
            }],
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, problem) in self.problems.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{problem}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

/// Collects problems while loading.
#[derive(Debug, Default)]
struct Problems(Vec<Problem>);

impl Problems {
    fn at(&mut self, file: Option<&Path>, line: Option<usize>, message: impl Into<String>) {
        self.0.push(Problem {
            file: file.map(Path::to_path_buf),
            line,
            message: message.into(),
        });
    }

    fn finish(self) -> Result<(), ConfigError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ConfigError { problems: self.0 })
        }
    }
}

/// One configuration file as written: `agent.toml`, a `rules.d` file or a preset. This is the
/// type `schema/rules.v1.json` is generated from.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(
    title = "Wedgetail agent configuration, schema version 1",
    description = "agent.toml and rules.d/*.toml for the Wedgetail host agent. rules.d files may only hold schema_version and [[rule]] tables. See docs/rules.md."
)]
struct ConfigFile {
    /// Schema version of this file. Only `1` exists; leaving it out means `1`.
    #[serde(default)]
    #[schemars(with = "Option<u32>")]
    schema_version: Option<Spanned<u32>>,
    /// Agent settings (`agent.toml` only).
    #[serde(default)]
    #[schemars(with = "Option<AgentSection>")]
    agent: Option<Spanned<AgentSection>>,
    /// Deprecated: use `[agent] endpoint`.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    endpoint: Option<Spanned<String>>,
    /// Deprecated: use `[agent] state_dir`.
    #[serde(default)]
    state_dir: Option<PathBuf>,
    /// Deprecated: use `[agent] buffer_max_mb`.
    #[serde(default)]
    #[schemars(with = "Option<BufferConfig>")]
    buffer: Option<Spanned<BufferConfig>>,
    /// Shipping limits; defaults are the server limits and can only be lowered.
    #[serde(default)]
    #[schemars(with = "Option<Limits>")]
    limits: Option<Spanned<Limits>>,
    /// Heartbeat settings.
    #[serde(default)]
    #[schemars(with = "Option<HeartbeatConfig>")]
    heartbeat: Option<Spanned<HeartbeatConfig>>,
    /// Collector rules.
    #[serde(default, rename = "rule")]
    #[schemars(with = "Vec<Rule>")]
    rules: Vec<Spanned<Rule>>,
}

/// `[agent]`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AgentSection {
    /// Your Wedgetail ingest URL, `https://` only.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    endpoint: Option<Spanned<String>>,
    /// Disk buffer, checkpoints, status and credential. Defaults per OS.
    #[serde(default)]
    state_dir: Option<PathBuf>,
    /// Disk buffer cap in MiB, 16 to 65536 (default 256).
    #[serde(default)]
    #[schemars(with = "Option<u64>")]
    buffer_max_mb: Option<Spanned<u64>>,
    /// Built-in presets: `"auto"` (default), a list of preset ids, or `[]` for none. `"auto"`
    /// in a list adds the presets detected for this host.
    #[serde(default)]
    #[schemars(with = "Option<PresetSelection>")]
    presets: Option<Spanned<PresetSelection>>,
    /// Rule ids (from presets or rule files) to switch off.
    #[serde(default)]
    #[schemars(with = "Vec<String>")]
    disable_rules: Vec<Spanned<String>>,
    /// Most files tailed at once across all `file` rules, 1 to 100,000 (default 1,000).
    #[serde(default)]
    #[schemars(with = "Option<u32>")]
    max_open_files: Option<Spanned<u32>>,
}

/// `presets = "auto"` or `presets = ["linux-core", "auto"]`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
enum PresetSelection {
    One(String),
    Many(Vec<String>),
}

impl PresetSelection {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(s) => vec![s],
            Self::Many(v) => v,
        }
    }
}

/// The JSON Schema for configuration files (`schema/rules.v1.json`), pretty-printed with a
/// trailing newline.
pub fn json_schema() -> String {
    let schema = schemars::schema_for!(ConfigFile);
    let mut text = serde_json::to_string_pretty(&schema).unwrap_or_default();
    text.push('\n');
    text
}

/// 1-based line of a byte offset.
fn line_at(text: &str, offset: usize) -> usize {
    let end = offset.min(text.len());
    text.as_bytes()[..end]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

fn span_line(text: &str, span: Range<usize>) -> usize {
    line_at(text, span.start)
}

/// Parse one file. Syntax and type errors are reported with their line.
fn parse_file(path: &Path, text: &str, problems: &mut Problems) -> Option<ConfigFile> {
    match toml::from_str::<ConfigFile>(text) {
        Ok(file) => {
            if let Some(v) = &file.schema_version
                && *v.get_ref() != SCHEMA_VERSION
            {
                problems.at(
                    Some(path),
                    Some(span_line(text, v.span())),
                    format!(
                        "schema_version {} is not supported by this agent (it reads {SCHEMA_VERSION})",
                        v.get_ref()
                    ),
                );
                return None;
            }
            Some(file)
        }
        Err(e) => {
            let line = e.span().map(|s| span_line(text, s));
            problems.at(Some(path), line, e.message().trim_end().to_owned());
            None
        }
    }
}

/// Take the rules out of a parsed file, recording where each was defined.
fn take_rules(file: &mut ConfigFile, origin: &Path, text: &str) -> Vec<Rule> {
    std::mem::take(&mut file.rules)
        .into_iter()
        .map(|spanned| {
            let line = span_line(text, spanned.span());
            let mut rule = spanned.into_inner();
            rule.origin = Some(Origin {
                file: origin.to_path_buf(),
                line,
            });
            rule
        })
        .collect()
}

/// Rule files and presets may only hold `schema_version` and `[[rule]]`.
fn reject_settings(file: &ConfigFile, path: &Path, text: &str, problems: &mut Problems) {
    let spans = [
        file.agent.as_ref().map(Spanned::span),
        file.endpoint.as_ref().map(Spanned::span),
        file.buffer.as_ref().map(Spanned::span),
        file.limits.as_ref().map(Spanned::span),
        file.heartbeat.as_ref().map(Spanned::span),
    ];
    let has_settings = file.state_dir.is_some() || spans.iter().any(Option::is_some);
    if has_settings {
        let line = spans
            .into_iter()
            .flatten()
            .next()
            .map(|s| span_line(text, s));
        problems.at(
            Some(path),
            line,
            "agent settings belong in agent.toml; rule files may only hold schema_version and [[rule]]",
        );
    }
}

impl AgentConfig {
    /// Load `path`, then `rules.d/*.toml` next to it, add the built-in presets for this OS,
    /// then validate.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::load_with(path, presets::BUILTIN, std::env::consts::OS)
    }

    /// [`load`](Self::load) with a given preset registry and OS (tests, tools).
    pub fn load_with(path: &Path, registry: &[Preset], os: &str) -> Result<Self, ConfigError> {
        let text = read_bounded(path)?;
        let config_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        let mut rule_texts = Vec::new();
        for file in rule_files(&config_dir.join("rules.d"))? {
            let text = read_bounded(&file)?;
            rule_texts.push((file, text));
        }
        Self::from_sources(path, &text, &rule_texts, registry, os, Some(config_dir))
    }

    /// Merge already-read documents: `agent.toml` (`main`), `rules.d` files in order, and the
    /// presets selected for `os` from `registry`; then validate.
    pub fn from_sources(
        main_path: &Path,
        main: &str,
        rule_files: &[(PathBuf, String)],
        registry: &[Preset],
        os: &str,
        config_dir: Option<PathBuf>,
    ) -> Result<Self, ConfigError> {
        let mut problems = Problems::default();
        let config = Self::from_main(main_path, main, &mut problems);
        let mut user_rules = Vec::new();
        for (path, text) in rule_files {
            if let Some(mut file) = parse_file(path, text, &mut problems) {
                reject_settings(&file, path, text, &mut problems);
                user_rules.extend(take_rules(&mut file, path, text));
            }
        }
        let Some(mut config) = config else {
            return Err(ConfigError {
                problems: problems.0,
            });
        };
        config.config_dir = config_dir;

        // Presets first, then agent.toml, then rules.d.
        let selected = presets::select(&config.preset_selection, registry, os);
        for message in selected.errors {
            problems.at(config.lines.file.as_deref(), config.lines.presets, message);
        }
        config.warnings.extend(selected.warnings);
        let mut rules = Vec::new();
        // Built-in preset rules for a source this host does not have (another distribution's
        // log file, the journal on a host without systemd) are loaded switched off.
        let host_checks = std::ptr::eq(registry, presets::BUILTIN) && os == std::env::consts::OS;
        for preset in &selected.presets {
            let origin = PathBuf::from(format!("preset:{}", preset.id));
            if let Some(mut file) = parse_file(&origin, preset.toml, &mut problems) {
                reject_settings(&file, &origin, preset.toml, &mut problems);
                for mut rule in take_rules(&mut file, &origin, preset.toml) {
                    if !rule.id.starts_with(&format!("{}.", preset.id)) {
                        problems.at(
                            Some(&origin),
                            rule.origin.as_ref().map(|o| o.line),
                            format!(
                                "preset rule id {:?} must start with \"{}.\"",
                                rule.id, preset.id
                            ),
                        );
                    }
                    if host_checks && !presets::rule_check_passes(&rule.id) {
                        rule.enabled = false;
                    }
                    rules.push(rule);
                }
            }
            config.presets.push(preset.id.to_owned());
        }
        rules.append(&mut config.rules);
        rules.append(&mut user_rules);
        config.rules = rules;

        // disable_rules switches rules off, with every rule under the id (`linux-core.auth`
        // also switches off `linux-core.auth.journald`). Ids that match nothing are only a
        // warning: a file shared between hosts may name preset rules this host does not load.
        for id in &config.disable_rules {
            let mut found = false;
            let prefix = format!("{id}.");
            for rule in config
                .rules
                .iter_mut()
                .filter(|r| &r.id == id || r.id.starts_with(&prefix))
            {
                rule.enabled = false;
                found = true;
            }
            if !found {
                config
                    .warnings
                    .push(format!("disable_rules: no rule has id {id:?}"));
            }
        }

        if let Err(e) = config.validate() {
            problems.0.extend(e.problems);
        }
        problems.finish()?;
        Ok(config)
    }

    /// Parse one `agent.toml` document without reading `rules.d`, adding presets or
    /// validating.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut problems = Problems::default();
        let config = Self::from_main(Path::new("agent.toml"), text, &mut problems);
        problems.finish()?;
        config.ok_or_else(|| ConfigError::new("cannot parse agent.toml"))
    }

    fn from_main(path: &Path, text: &str, problems: &mut Problems) -> Option<Self> {
        let mut file = parse_file(path, text, problems)?;
        let rules = take_rules(&mut file, path, text);
        let agent = file.agent.map(Spanned::into_inner).unwrap_or_default();
        let line = |span: Range<usize>| Some(span_line(text, span));
        let mut lines = SettingLines {
            file: Some(path.to_path_buf()),
            ..SettingLines::default()
        };

        let endpoint = match (agent.endpoint, file.endpoint) {
            (Some(a), Some(b)) => {
                problems.at(
                    Some(path),
                    line(b.span()),
                    format!(
                        "endpoint is set twice (also at line {}); keep only [agent] endpoint",
                        span_line(text, a.span())
                    ),
                );
                return None;
            }
            (Some(e), None) | (None, Some(e)) => {
                lines.endpoint = line(e.span());
                e.into_inner()
            }
            (None, None) => String::new(),
        };
        let state_dir = match (agent.state_dir, file.state_dir) {
            (Some(_), Some(_)) => {
                problems.at(
                    Some(path),
                    None,
                    "state_dir is set twice; keep only [agent] state_dir",
                );
                return None;
            }
            (Some(d), None) | (None, Some(d)) => d,
            (None, None) => paths::default_state_dir(),
        };
        let buffer = match (agent.buffer_max_mb, file.buffer) {
            (Some(_), Some(b)) => {
                problems.at(
                    Some(path),
                    line(b.span()),
                    "the buffer size is set twice; keep only [agent] buffer_max_mb",
                );
                return None;
            }
            (Some(mb), None) => {
                lines.buffer = line(mb.span());
                BufferConfig {
                    max_mb: mb.into_inner(),
                }
            }
            (None, Some(b)) => {
                lines.buffer = line(b.span());
                b.into_inner()
            }
            (None, None) => BufferConfig::default(),
        };
        let limits = file.limits.map_or_else(Limits::default, |l| {
            lines.limits = line(l.span());
            l.into_inner()
        });
        let heartbeat = file.heartbeat.map_or_else(HeartbeatConfig::default, |h| {
            lines.heartbeat = line(h.span());
            h.into_inner()
        });
        let preset_selection = agent.presets.map_or_else(
            || vec![presets::AUTO.to_owned()],
            |p| {
                lines.presets = line(p.span());
                p.into_inner().into_vec()
            },
        );
        let disable_rules = agent
            .disable_rules
            .into_iter()
            .map(|id| {
                lines.disable_rules.push(span_line(text, id.span()));
                id.into_inner()
            })
            .collect();
        let max_open_files = agent.max_open_files.map_or(DEFAULT_MAX_OPEN_FILES, |m| {
            lines.max_open_files = line(m.span());
            m.into_inner()
        });

        Some(Self {
            endpoint,
            state_dir,
            buffer,
            limits,
            heartbeat,
            rules,
            preset_selection,
            presets: Vec::new(),
            disable_rules,
            max_open_files,
            config_dir: None,
            warnings: Vec::new(),
            lines,
        })
    }

    /// The endpoint without a trailing slash.
    pub fn endpoint_base(&self) -> &str {
        self.endpoint.trim_end_matches('/')
    }

    /// Directories no rule may read: the agent's own state (credential, buffer) and
    /// configuration. See [`paths::protected_dirs`].
    pub fn protected_dirs(&self) -> Vec<PathBuf> {
        let config_dir = self.config_dir.clone().unwrap_or_else(paths::config_dir);
        paths::protected_dirs(&self.state_dir, &config_dir)
    }

    /// Check values the type system cannot: endpoint scheme, limits, rule ids and per-type
    /// fields, regular expressions, globs, protected paths and duplicate ids. Reports every
    /// problem found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut problems = Problems::default();
        let file = self.lines.file.as_deref();

        if self.endpoint.is_empty() {
            problems.at(
                file,
                None,
                "[agent] endpoint is required: your Wedgetail ingest URL",
            );
        } else if let Err(e) = validate_endpoint(&self.endpoint) {
            problems.at(file, self.lines.endpoint, e);
        }
        if !(16..=65_536).contains(&self.buffer.max_mb) {
            problems.at(
                file,
                self.lines.buffer,
                format!(
                    "buffer_max_mb must be between 16 and 65536, got {}",
                    self.buffer.max_mb
                ),
            );
        }
        let l = &self.limits;
        let checks = [
            (
                "limits.max_batch_bytes",
                l.max_batch_bytes,
                1024,
                SERVER_MAX_BODY_BYTES,
            ),
            (
                "limits.max_batch_uncompressed_bytes",
                l.max_batch_uncompressed_bytes,
                1024,
                SERVER_MAX_DECOMPRESSED_BYTES,
            ),
            (
                "limits.max_batch_records",
                l.max_batch_records.into(),
                1,
                SERVER_MAX_RECORDS.into(),
            ),
            (
                "limits.max_requests_per_minute",
                l.max_requests_per_minute.into(),
                1,
                SERVER_MAX_REQUESTS_PER_MINUTE.into(),
            ),
            (
                "limits.max_event_bytes",
                l.max_event_bytes,
                1024,
                l.max_batch_bytes,
            ),
        ];
        for (name, value, min, max) in checks {
            if let Err(e) = check_range(name, value, min, max) {
                problems.at(file, self.lines.limits, e);
            }
        }
        if let Err(e) = check_range("heartbeat.interval_s", self.heartbeat.interval_s, 10, 3600) {
            problems.at(file, self.lines.heartbeat, e);
        }
        if let Err(e) = check_range("max_open_files", self.max_open_files.into(), 1, 100_000) {
            problems.at(file, self.lines.max_open_files, e);
        }
        for (i, id) in self.disable_rules.iter().enumerate() {
            if !is_valid_rule_id(id) {
                problems.at(
                    file,
                    self.lines.disable_rules.get(i).copied(),
                    format!("disable_rules: {id:?} is not a valid rule id"),
                );
            }
        }

        let protected = self.protected_dirs();
        let mut seen: HashMap<&str, Option<&Origin>> = HashMap::new();
        for rule in &self.rules {
            let origin = rule.origin.as_ref();
            let (rule_file, rule_line) = match origin {
                Some(o) => (Some(o.file.as_path()), Some(o.line)),
                None => (file, None),
            };
            for message in validate::rule(rule, &protected) {
                problems.at(
                    rule_file,
                    rule_line,
                    format!("rule {:?}: {message}", rule.id),
                );
            }
            if let Some(first) = seen.insert(&rule.id, origin) {
                let place = first.map_or_else(String::new, |o| format!(" (first defined at {o})"));
                problems.at(
                    rule_file,
                    rule_line,
                    format!("rule id {:?} is used more than once{place}", rule.id),
                );
            }
        }
        problems.finish()
    }
}

fn check_range(name: &str, value: u64, min: u64, max: u64) -> Result<(), String> {
    if value < min || value > max {
        return Err(format!(
            "{name} must be between {min} and {max}, got {value}"
        ));
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

/// `*.toml` files in `dir`, in lexical (byte-wise) file name order.
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
    if files.len() > MAX_RULE_FILES {
        return Err(ConfigError::in_file(
            dir,
            format!("more than {MAX_RULE_FILES} rule files"),
        ));
    }
    files.sort();
    Ok(files)
}

/// `https://host[:port][/path]`, no credentials, query or fragment.
pub fn validate_endpoint(endpoint: &str) -> Result<(), String> {
    let Some(rest) = endpoint.strip_prefix("https://") else {
        return Err("endpoint must start with https://".into());
    };
    let authority = rest.split('/').next().unwrap_or("");
    let bad = authority.is_empty()
        || endpoint.len() > 2048
        || endpoint
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || endpoint.contains(['@', '?', '#', '\\']);
    if bad {
        return Err(
            "endpoint must be https://host[:port][/path] with no credentials, query or fragment"
                .into(),
        );
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

#[cfg(test)]
mod tests;
