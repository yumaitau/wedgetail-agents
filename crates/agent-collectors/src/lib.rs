//! Collectors read events from the host and hand them to the agent pipeline.
//!
//! Every collector implements [`Collector`]. The runtime calls [`Collector::start`] with the
//! last saved [`Checkpoint`] for the rule, then calls [`Collector::poll`] in a loop on its own
//! thread. Each [`Batch`] carries the checkpoint that is valid once all of its events are
//! durably buffered; the runtime saves it only after that, so a crash replays at most the
//! events after the last saved checkpoint.
//!
//! [`from_rule`] maps a configured rule to its collector. A new collector type is a new
//! [`agent_config::RuleKind`] variant plus one arm there. [`CollectorEnv`] carries what rules
//! share: the open file cap and the directories no rule may read.

// Only the OS FFI modules under `os/` may use `unsafe`, and each block carries a SAFETY note.
#![deny(unsafe_code)]

use std::fmt;
use std::time::Duration;

use agent_config::{FileFormat, Rule, RuleKind};

pub mod auditd;
mod event;
pub mod file_tail;
pub mod journald;
pub mod lastlog;
pub mod lines;
pub mod macos_bsm;
pub mod macos_unified;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod subprocess;
pub mod time;
pub mod utmp;
pub mod wineventlog;

#[cfg(windows)]
#[allow(unsafe_code)]
mod os;

pub use event::{Checkpoint, EventTemplate, FilePosition, RawEvent, WIRE_VERSION};
pub use file_tail::{CollectorEnv, FileSpec, OpenFiles};

/// Longest line or message a collector keeps; the rest is cut and `attrs.truncated` is set.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// Events read since the last poll, plus the checkpoint that covers them.
#[derive(Debug, Default)]
pub struct Batch {
    pub events: Vec<RawEvent>,
    /// Position after the last event in `events`; `None` when nothing moved.
    pub checkpoint: Option<Checkpoint>,
}

/// A source of host events. Implementations must be cheap when idle: `poll` should block for
/// up to `wait` rather than spin.
pub trait Collector: Send {
    /// The rule id this collector serves, used for checkpoints and health.
    fn rule_id(&self) -> &str;

    /// Start (or restart after an error) from `checkpoint`, or from the rule's default start
    /// position when `None`. Must be safe to call again after a failed `poll`.
    fn start(&mut self, checkpoint: Option<Checkpoint>) -> Result<(), CollectorError>;

    /// Return up to `max_events` new events, waiting at most `wait` for the first one.
    fn poll(&mut self, max_events: usize, wait: Duration) -> Result<Batch, CollectorError>;
}

/// A collector failure. The runtime records it in the heartbeat, backs off and restarts the
/// collector.
#[derive(Debug)]
pub struct CollectorError(pub String);

impl fmt::Display for CollectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CollectorError {}

impl From<std::io::Error> for CollectorError {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

/// Build the collector for `rule`. Fails for rule types this OS does not support.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(unused_variables)
)]
pub fn from_rule(rule: &Rule, env: &CollectorEnv) -> Result<Box<dyn Collector>, CollectorError> {
    let template = EventTemplate::from_rule(rule);
    match rule.kind {
        RuleKind::File if rule.format == FileFormat::Lastlog => {
            let path = rule.paths.first().cloned().unwrap_or_default();
            Ok(Box::new(lastlog::Lastlog::new(template, path, env.clone())))
        }
        RuleKind::File => Ok(Box::new(file_tail::FileTail::new(
            template,
            FileSpec::from_rule(rule),
            env.clone(),
        )?)),
        #[cfg(target_os = "linux")]
        RuleKind::Journald => Ok(Box::new(journald::Journald::new(
            template,
            rule.journal_matches(),
            rule.priority_max,
        ))),
        #[cfg(target_os = "macos")]
        RuleKind::MacosUnified => Ok(Box::new(macos_unified::UnifiedLog::new(
            template,
            rule.predicate.clone(),
            rule.level.unwrap_or_default(),
        ))),
        #[cfg(target_os = "macos")]
        RuleKind::MacosBsm => Ok(Box::new(macos_bsm::BsmTrail::new(
            template,
            macos_bsm::EventFilter {
                classes: rule.classes.clone(),
                exclude: rule.exclude_events.clone(),
            },
        ))),
        #[cfg(windows)]
        RuleKind::Wineventlog => {
            let channel = rule.channel.clone().unwrap_or_default();
            let query = wineventlog::build_xpath(&channel, &rule.event_ids, rule.xpath.as_deref());
            Ok(Box::new(os::windows::eventlog::EventLog::new(
                template, channel, query,
            )))
        }
        #[allow(unreachable_patterns)]
        kind => Err(CollectorError(format!(
            "rule {:?}: type {kind:?} is not supported on {}",
            rule.id,
            std::env::consts::OS
        ))),
    }
}

/// Read at most `max` bytes of a text file.
pub(crate) fn read_bounded(path: &std::path::Path, max: u64) -> std::io::Result<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(max)
        .read_to_string(&mut text)?;
    Ok(text)
}
