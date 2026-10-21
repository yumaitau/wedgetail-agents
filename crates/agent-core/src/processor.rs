//! The hook between collectors and the disk buffer. Redaction, filtering and sampling rules
//! implement [`Processor`]; it runs before an event is written to disk, so a redacted secret
//! never reaches the buffer.

use agent_collectors::RawEvent;

/// What to do with an event.
#[derive(Debug)]
pub enum Verdict {
    /// Buffer and ship this (possibly rewritten) event.
    Keep(RawEvent),
    /// Drop it on purpose (a filter rule); not counted as data loss.
    Filtered,
    /// Drop it by sampling; counted in the heartbeat's `dropped.sampled`.
    Sampled,
}

pub trait Processor: Send {
    fn process(&mut self, event: RawEvent) -> Verdict;
}

/// Passes every event through unchanged.
#[derive(Debug, Default)]
pub struct PassThrough;

impl Processor for PassThrough {
    fn process(&mut self, event: RawEvent) -> Verdict {
        Verdict::Keep(event)
    }
}
