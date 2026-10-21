//! The per-rule event pipeline, run by the writer before events reach the disk buffer:
//!
//! 1. `include_match` / `exclude_match` (dropped events are filtered, not counted as loss);
//! 2. `sample_rate` (dropped events count as `dropped.sampled` in the heartbeat);
//! 3. `rate_limit`, a token bucket (dropped events count as `dropped.rate_limited`);
//! 4. `redact`, on the body and on every string in `fields`, so a secret never reaches the
//!    disk buffer, the wire or a parser;
//! 5. the `parser`, which fills `fields` from the redacted body. A line it does not recognise
//!    is kept with `attrs.parse_error` naming the parser.
//!
//! Matching uses the raw line, or for events without one (journald, unified log, Windows
//! Event Log) the event's fields as compact JSON.

use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Instant;

use agent_collectors::RawEvent;
use agent_config::{CompiledRule, Rule};
use serde_json::Value;

use crate::processor::{Processor, Verdict};

/// A token bucket: `rate` tokens a second, holding at most `burst`.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket.
    pub fn new(rate: u32, burst: u32, now: Instant) -> Self {
        Self {
            rate: f64::from(rate),
            burst: f64::from(burst.max(1)),
            tokens: f64::from(burst.max(1)),
            last: now,
        }
    }

    /// Take one token if there is one.
    pub fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
struct RuleState {
    compiled: CompiledRule,
    sample_rate: f64,
    bucket: Option<TokenBucket>,
}

/// [`Processor`] for the configured rules. Events from collectors without a rule (and the
/// heartbeat) pass through unchanged.
#[derive(Debug)]
pub struct RuleProcessor {
    rules: HashMap<String, RuleState>,
    rng: fastrand::Rng,
}

impl RuleProcessor {
    pub fn new(rules: &[Rule]) -> Result<Self, String> {
        let now = Instant::now();
        let mut states = HashMap::new();
        for rule in rules.iter().filter(|r| r.enabled) {
            let compiled =
                CompiledRule::new(rule).map_err(|e| format!("rule {:?}: {e}", rule.id))?;
            states.insert(
                rule.id.clone(),
                RuleState {
                    compiled,
                    sample_rate: rule.sample_rate,
                    bucket: rule
                        .rate_limit
                        .map(|rl| TokenBucket::new(rl.events_per_second, rl.burst(), now)),
                },
            );
        }
        Ok(Self {
            rules: states,
            rng: fastrand::Rng::new(),
        })
    }

    /// Fix the sampling sequence (tests).
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.rng = fastrand::Rng::with_seed(seed);
        self
    }
}

fn match_text(event: &RawEvent) -> Cow<'_, str> {
    match &event.body {
        Some(body) => Cow::Borrowed(body),
        None => Cow::Owned(serde_json::to_string(&event.fields).unwrap_or_default()),
    }
}

/// Redact every string inside `value`.
fn redact_value(compiled: &CompiledRule, value: &mut Value) {
    match value {
        Value::String(s) => {
            if let Some(redacted) = compiled.redact(s) {
                *s = redacted;
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| redact_value(compiled, v)),
        Value::Object(map) => map.values_mut().for_each(|v| redact_value(compiled, v)),
        _ => {}
    }
}

impl Processor for RuleProcessor {
    fn process(&mut self, mut event: RawEvent) -> Verdict {
        let Some(rule) = self.rules.get_mut(&event.rule_id) else {
            return Verdict::Keep(event);
        };
        if rule.compiled.has_filters() && !rule.compiled.keeps(&match_text(&event)) {
            return Verdict::Filtered;
        }
        if rule.sample_rate < 1.0 && self.rng.f64() >= rule.sample_rate {
            return Verdict::Sampled;
        }
        if let Some(bucket) = &mut rule.bucket
            && !bucket.take(Instant::now())
        {
            return Verdict::RateLimited;
        }
        if rule.compiled.has_redactions() {
            if let Some(body) = &mut event.body
                && let Some(redacted) = rule.compiled.redact(body)
            {
                *body = redacted;
            }
            for value in event.fields.values_mut() {
                redact_value(&rule.compiled, value);
            }
        }
        let parser = &rule.compiled.parser;
        if !parser.is_raw()
            && let Some(body) = &event.body
        {
            match parser.parse(body) {
                Some(fields) => event.fields.extend(fields),
                None => {
                    event
                        .attrs
                        .insert("parse_error".into(), Value::from(parser.name()));
                }
            }
        }
        Verdict::Keep(event)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use agent_collectors::EventTemplate;
    use serde_json::{Map, json};

    use super::*;

    fn rule(extra: &str) -> Rule {
        toml::from_str(&format!("id = \"r\"\ntype = \"journald\"\n{extra}")).expect("rule")
    }

    fn file_rule(extra: &str) -> Rule {
        toml::from_str(&format!(
            "id = \"r\"\ntype = \"file\"\npaths = [\"/var/log/x.log\"]\n{extra}"
        ))
        .expect("rule")
    }

    fn event(body: Option<&str>, fields: Value) -> RawEvent {
        let fields = match fields {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        EventTemplate::new("r", "file", None, &BTreeMap::new()).event(
            1,
            body.map(str::to_owned),
            fields,
        )
    }

    fn keep(p: &mut RuleProcessor, e: RawEvent) -> RawEvent {
        match p.process(e) {
            Verdict::Keep(e) => e,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn token_bucket() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(10, 3, t0);
        assert!(b.take(t0) && b.take(t0) && b.take(t0));
        assert!(!b.take(t0));
        assert!(b.take(t0 + Duration::from_millis(100)));
        assert!(!b.take(t0 + Duration::from_millis(100)));
        // Refills to the burst, not beyond.
        let later = t0 + Duration::from_secs(60);
        assert_eq!((0..10).filter(|_| b.take(later)).count(), 3);
    }

    #[test]
    fn filters_then_redacts_then_parses() {
        let mut p = RuleProcessor::new(&[file_rule(
            r#"include_match = ['user=']
exclude_match = ['healthz']
redact = [{ pattern = 'password=\S+', replace = "password=[REDACTED]" }]
parser = "logfmt""#,
        )])
        .expect("processor");
        assert!(matches!(
            p.process(event(Some("no match"), json!({}))),
            Verdict::Filtered
        ));
        assert!(matches!(
            p.process(event(Some("user=x path=/healthz"), json!({}))),
            Verdict::Filtered
        ));
        let e = keep(
            &mut p,
            event(Some("user=alice password=hunter2"), json!({})),
        );
        assert_eq!(e.body.as_deref(), Some("user=alice password=[REDACTED]"));
        assert_eq!(
            Value::Object(e.fields),
            json!({"user": "alice", "password": "[REDACTED]"})
        );
        let e = keep(&mut p, event(Some("user=\"unterminated"), json!({})));
        assert_eq!(e.attrs["parse_error"], "logfmt");
    }

    #[test]
    fn events_without_a_body_match_and_redact_on_fields() {
        let mut p = RuleProcessor::new(&[rule(
            r"include_match = ['sshd']
redact = [{ pattern = 'token=\w+' }]",
        )])
        .expect("processor");
        let fields = json!({"MESSAGE": "sshd: login token=abc123", "nested": ["token=zz", 1]});
        let e = keep(&mut p, event(None, fields));
        assert_eq!(e.fields["MESSAGE"], "sshd: login [REDACTED]");
        assert_eq!(e.fields["nested"], json!(["[REDACTED]", 1]));
        assert!(matches!(
            p.process(event(None, json!({"MESSAGE": "cron: ran"}))),
            Verdict::Filtered
        ));
    }

    #[test]
    fn sampling_and_rate_limits_drop_with_their_own_verdicts() {
        let mut p = RuleProcessor::new(&[rule("sample_rate = 0.25")])
            .expect("processor")
            .with_seed(7);
        let kept = (0..10_000)
            .filter(|_| matches!(p.process(event(Some("x"), json!({}))), Verdict::Keep(_)))
            .count();
        assert!((2_000..3_000).contains(&kept), "{kept}");

        let mut p =
            RuleProcessor::new(&[rule("rate_limit = { events_per_second = 1, burst = 5 }")])
                .expect("processor");
        let verdicts: Vec<bool> = (0..20)
            .map(|_| matches!(p.process(event(Some("x"), json!({}))), Verdict::RateLimited))
            .collect();
        assert_eq!(verdicts.iter().filter(|v| !**v).count(), 5);
    }

    #[test]
    fn other_rules_and_disabled_rules_pass_through() {
        let mut disabled = rule("include_match = ['never']");
        disabled.enabled = false;
        let mut p = RuleProcessor::new(&[disabled]).expect("processor");
        keep(&mut p, event(Some("anything"), json!({})));
        let mut other = event(Some("x"), json!({}));
        other.rule_id = "agent".into();
        keep(&mut p, other);
    }
}
