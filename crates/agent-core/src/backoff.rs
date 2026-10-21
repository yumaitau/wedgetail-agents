//! Retry pacing: exponential backoff with full jitter, `Retry-After`, and the per-credential
//! request rate limit.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Longest `Retry-After` honoured; larger values from a misbehaving server are capped.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);

/// Exponential backoff with full jitter: the n-th delay is uniform in
/// `[0, min(cap, base * 2^n)]`.
#[derive(Debug)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
    rng: fastrand::Rng,
}

impl Backoff {
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap,
            attempt: 0,
            rng: fastrand::Rng::new(),
        }
    }

    /// Deterministic jitter for tests.
    pub fn with_seed(base: Duration, cap: Duration, seed: u64) -> Self {
        Self {
            base,
            cap,
            attempt: 0,
            rng: fastrand::Rng::with_seed(seed),
        }
    }

    /// The upper bound for the next delay.
    pub fn ceiling(&self) -> Duration {
        let factor = 1u32.checked_shl(self.attempt.min(31)).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.cap)
    }

    pub fn next_delay(&mut self) -> Duration {
        let ceiling = self.ceiling();
        self.attempt = self.attempt.saturating_add(1);
        let ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(self.rng.u64(0..=ms))
    }

    /// The delay after a response that carried `Retry-After`: the server's value plus up to
    /// a second of jitter so many agents do not retry in lockstep. Counts as an attempt.
    pub fn retry_after(&mut self, server: Duration) -> Duration {
        self.attempt = self.attempt.saturating_add(1);
        server.min(MAX_RETRY_AFTER) + Duration::from_millis(self.rng.u64(0..=1000))
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn attempts(&self) -> u32 {
        self.attempt
    }
}

/// Parse a `Retry-After` value in delta-seconds. HTTP dates are not used by the Wedgetail
/// API and fall back to normal backoff.
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    let v = value.trim();
    if v.is_empty() || v.len() > 10 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse::<u64>()
        .ok()
        .map(|s| Duration::from_secs(s).min(MAX_RETRY_AFTER))
}

/// At most `per_minute` requests in any rolling 60 seconds.
#[derive(Debug)]
pub struct RateLimiter {
    per_minute: usize,
    sent: VecDeque<Instant>,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        let per_minute = per_minute.max(1) as usize;
        Self {
            per_minute,
            sent: VecDeque::with_capacity(per_minute),
        }
    }

    /// How long to wait before the next request may go.
    pub fn wait(&mut self, now: Instant) -> Duration {
        let window = Duration::from_secs(60);
        while self
            .sent
            .front()
            .is_some_and(|&t| now.saturating_duration_since(t) >= window)
        {
            self.sent.pop_front();
        }
        match self.sent.front() {
            Some(&oldest) if self.sent.len() >= self.per_minute => {
                window.saturating_sub(now.saturating_duration_since(oldest))
            }
            _ => Duration::ZERO,
        }
    }

    pub fn record(&mut self, now: Instant) {
        self.sent.push_back(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_jitter_grows_to_the_cap() {
        let mut b = Backoff::with_seed(Duration::from_secs(1), Duration::from_secs(300), 7);
        let mut ceilings = Vec::new();
        for _ in 0..12 {
            let ceiling = b.ceiling();
            let d = b.next_delay();
            assert!(d <= ceiling, "{d:?} > {ceiling:?}");
            ceilings.push(ceiling.as_secs());
        }
        assert_eq!(ceilings, [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300, 300]);
        b.reset();
        assert_eq!(b.ceiling(), Duration::from_secs(1));
        // Many attempts never overflow.
        for _ in 0..100 {
            b.next_delay();
        }
        assert_eq!(b.ceiling(), Duration::from_secs(300));
    }

    #[test]
    fn jitter_is_spread_out() {
        let mut b = Backoff::with_seed(Duration::from_secs(64), Duration::from_secs(64), 1);
        let delays: Vec<u64> = (0..200)
            .map(|_| b.next_delay().as_millis() as u64)
            .collect();
        let min = delays.iter().min().copied().unwrap_or_default();
        let max = delays.iter().max().copied().unwrap_or_default();
        assert!(min < 10_000 && max > 54_000, "{min} {max}");
    }

    #[test]
    fn retry_after_parsing() {
        assert_eq!(parse_retry_after("30"), Some(Duration::from_secs(30)));
        assert_eq!(parse_retry_after(" 0 "), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("999999999"), Some(MAX_RETRY_AFTER));
        for bad in [
            "",
            "-1",
            "1.5",
            "Wed, 21 Oct 2026 07:28:00 GMT",
            "99999999999999999999",
            "1e3",
        ] {
            assert_eq!(parse_retry_after(bad), None, "{bad}");
        }
        let mut b = Backoff::with_seed(Duration::from_secs(1), Duration::from_secs(60), 3);
        let d = b.retry_after(Duration::from_secs(30));
        assert!(d >= Duration::from_secs(30) && d <= Duration::from_secs(31));
        assert_eq!(b.attempts(), 1);
    }

    #[test]
    fn rate_limiter_allows_per_minute_then_waits() {
        let start = Instant::now();
        let mut r = RateLimiter::new(120);
        for i in 0..120 {
            let now = start + Duration::from_millis(i * 10);
            assert_eq!(r.wait(now), Duration::ZERO);
            r.record(now);
        }
        let now = start + Duration::from_millis(1_200);
        let wait = r.wait(now);
        assert_eq!(wait, Duration::from_millis(58_800));
        assert_eq!(r.wait(start + Duration::from_secs(60)), Duration::ZERO);
    }
}
