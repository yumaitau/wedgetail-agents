//! The hook between collectors and the disk buffer. The rule pipeline
//! ([`crate::rules::RuleProcessor`]: filtering, sampling, rate limiting, redaction, parsing)
//! implements [`Processor`]; it runs before an event is written to disk, so a redacted secret
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
    /// Drop it for a rule's rate limit; counted in the heartbeat's `dropped.rate_limited`.
    RateLimited,
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
