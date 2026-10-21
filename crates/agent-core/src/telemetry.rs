//! Self-telemetry: counters, collector health, the `agent.heartbeat` event and the local
//! `status.json` read by `wedgetail-agent status`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use agent_collectors::{EventTemplate, RawEvent, time};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::host::HostInfo;

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const HEARTBEAT_SOURCE_TYPE: &str = "agent.heartbeat";
pub const HEARTBEAT_RULE_ID: &str = "agent";
pub const STATUS_FILE: &str = "status.json";
const MAX_ERROR_CHARS: usize = 512;

/// Counters shared by the pipeline threads.
#[derive(Debug, Default)]
pub struct Metrics {
    pub dropped_oversize: AtomicU64,
    pub dropped_sampled: AtomicU64,
    pub dropped_rate_limited: AtomicU64,
    /// Unacknowledged records dropped because the disk buffer was full.
    pub dropped_buffer_full: AtomicU64,
    /// Records in batches the server rejected permanently (4xx other than auth/limits).
    pub rejected_events: AtomicU64,
    pub sent_events: AtomicU64,
    pub sent_batches: AtomicU64,
    pub collectors: Mutex<Vec<CollectorHealth>>,
    pub last_ship: Mutex<ShipStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CollectorHealth {
    pub rule_id: String,
    /// `starting`, `running` or `error`.
    pub state: String,
    pub errors: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ShipStatus {
    /// Time of the last accepted batch.
    pub last_success: Option<String>,
    /// Last shipping problem (HTTP status or transport error), cleared on success.
    pub last_error: Option<String>,
}

impl Metrics {
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    pub fn register_collector(&self, rule_id: &str) -> usize {
        let mut c = self
            .collectors
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        c.push(CollectorHealth {
            rule_id: rule_id.to_owned(),
            state: "starting".into(),
            errors: 0,
            last_error: None,
        });
        c.len() - 1
    }

    pub fn collector_running(&self, idx: usize) {
        if let Some(h) = self
            .collectors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(idx)
        {
            h.state = "running".into();
        }
    }

    pub fn collector_error(&self, idx: usize, error: &str) {
        if let Some(h) = self
            .collectors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(idx)
        {
            h.state = "error".into();
            h.errors += 1;
            h.last_error = Some(error.chars().take(MAX_ERROR_CHARS).collect());
        }
    }

    pub fn ship_ok(&self) {
        let mut s = self
            .last_ship
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        s.last_success = Some(time::format_rfc3339_us(time::now_us()));
        s.last_error = None;
    }

    pub fn ship_error(&self, error: &str) {
        self.last_ship
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last_error = Some(error.chars().take(MAX_ERROR_CHARS).collect());
    }
}

/// Buffer figures for the heartbeat.
#[derive(Debug, Clone, Copy, Default)]
pub struct BufferStats {
    pub bytes: u64,
    pub events: u64,
}

/// The heartbeat `fields` object, per the wire contract.
pub fn heartbeat_fields(
    host: &HostInfo,
    started: Instant,
    buffer: BufferStats,
    metrics: &Metrics,
    presets: &[String],
) -> Map<String, Value> {
    let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
    let collectors = metrics
        .collectors
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let value = json!({
        "agent_version": AGENT_VERSION,
        "uptime_s": started.elapsed().as_secs(),
        "buffer_bytes": buffer.bytes,
        "buffer_events": buffer.events,
        "dropped": {
            "buffer_full": load(&metrics.dropped_buffer_full),
            "rate_limited": load(&metrics.dropped_rate_limited),
            "sampled": load(&metrics.dropped_sampled),
            "oversize": load(&metrics.dropped_oversize),
        },
        "collectors": collectors,
        "presets": presets,
        "os": host.os,
        "os_version": host.os_version,
        "hostname": host.hostname,
    });
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

pub fn heartbeat_event(fields: Map<String, Value>) -> RawEvent {
    let template = EventTemplate::new(
        HEARTBEAT_RULE_ID,
        HEARTBEAT_SOURCE_TYPE,
        None,
        &Default::default(),
    );
    template.event(time::now_us(), None, fields)
}

/// `status.json`: the heartbeat fields plus local-only details.
pub fn status_json(fields: &Map<String, Value>, metrics: &Metrics) -> Value {
    let mut status = fields.clone();
    status.insert(
        "updated".into(),
        time::format_rfc3339_us(time::now_us()).into(),
    );
    status.insert("pid".into(), std::process::id().into());
    status.insert(
        "sent_events".into(),
        metrics.sent_events.load(Ordering::Relaxed).into(),
    );
    status.insert(
        "sent_batches".into(),
        metrics.sent_batches.load(Ordering::Relaxed).into(),
    );
    status.insert(
        "rejected_events".into(),
        metrics.rejected_events.load(Ordering::Relaxed).into(),
    );
    let ship = metrics
        .last_ship
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    status.insert(
        "ship".into(),
        serde_json::to_value(ship).unwrap_or_default(),
    );
    Value::Object(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_has_contract_fields() {
        let host = HostInfo {
            hostname: "web-01".into(),
            os: "linux",
            os_version: "Ubuntu 24.04".into(),
            arch: "x86_64",
        };
        let metrics = Metrics::default();
        let idx = metrics.register_collector("ssh");
        metrics.collector_error(idx, "journalctl exited");
        Metrics::add(&metrics.dropped_oversize, 2);
        let fields = heartbeat_fields(
            &host,
            Instant::now(),
            BufferStats {
                bytes: 10,
                events: 1,
            },
            &metrics,
            &["linux-core".into()],
        );
        for key in [
            "agent_version",
            "uptime_s",
            "buffer_bytes",
            "buffer_events",
            "dropped",
            "collectors",
            "presets",
            "os",
            "os_version",
            "hostname",
        ] {
            assert!(fields.contains_key(key), "{key}");
        }
        assert_eq!(fields["dropped"]["oversize"], 2);
        assert_eq!(
            fields["collectors"][0],
            json!({"rule_id": "ssh", "state": "error", "errors": 1, "last_error": "journalctl exited"})
        );
        let ev = heartbeat_event(fields);
        let line: Value = serde_json::from_slice(&ev.to_wire_line()).expect("json");
        assert_eq!(line["source_type"], "agent.heartbeat");
        assert_eq!(line["rule_id"], "agent");
        assert_eq!(line["v"], 1);
    }
}
