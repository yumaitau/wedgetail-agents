//! The runtime: collector threads feed a writer that runs the [`Processor`] hook, writes to
//! the disk buffer and saves checkpoints; a shipper thread drains the buffer; the writer also
//! emits the heartbeat.
//!
//! ```text
//! collector threads ──batches──▶ writer (processor → buffer.append+fsync → checkpoint) ──▶ disk
//!                                  │ every interval: heartbeat event + status.json
//! shipper thread ◀── peek/begin/ack ── disk buffer ──▶ POST /v1/agent/events
//! ```

use std::fmt;
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use agent_collectors::{Batch, Checkpoint, Collector, CollectorEnv, RawEvent};
use agent_config::AgentConfig;

use crate::backoff::Backoff;
use crate::batch::BatchLimits;
use crate::buffer::{DiskBuffer, write_atomic};
use crate::checkpoints::CheckpointStore;
use crate::credential::{CredentialProvider, CredentialStore};
use crate::enrolment::{RotationOptions, Rotator};
use crate::host::HostInfo;
use crate::processor::{Processor, Verdict};
use crate::rules::RuleProcessor;
use crate::shipper::{Shipper, ShipperOptions};
use crate::stop::Stop;
use crate::telemetry::{self, BufferStats, Metrics};

/// Most events a collector returns per poll.
const POLL_MAX_EVENTS: usize = 1000;
const POLL_WAIT: Duration = Duration::from_secs(1);
/// Batches queued between collectors and the writer.
const QUEUE_BATCHES: usize = 16;
/// How often `status.json` is refreshed for `wedgetail-agent status`.
const STATUS_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct AgentError(pub String);

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AgentError {}

struct Message {
    collector: usize,
    batch: Batch,
}

/// A configured agent, ready to [`run`](Agent::run).
pub struct Agent {
    config: AgentConfig,
    collectors: Vec<Box<dyn Collector>>,
    processor: Box<dyn Processor>,
    credential: Arc<dyn CredentialProvider>,
    host: HostInfo,
    presets: Vec<String>,
    shipper_options: ShipperOptions,
    rotation: Option<(Arc<dyn CredentialStore>, RotationOptions)>,
}

impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("collectors", &self.collectors.len())
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl Agent {
    /// Build the collectors for every enabled rule, and the rule pipeline (filters, sampling,
    /// rate limits, redaction, parsers) as the processor. Fails if a rule's type is not
    /// supported on this OS.
    pub fn new(
        config: AgentConfig,
        credential: Arc<dyn CredentialProvider>,
    ) -> Result<Self, AgentError> {
        let env = CollectorEnv::for_config(&config);
        let mut collectors = Vec::new();
        for rule in config.rules.iter().filter(|r| r.enabled) {
            collectors.push(agent_collectors::from_rule(rule, &env).map_err(|e| AgentError(e.0))?);
        }
        let processor = RuleProcessor::new(&config.rules).map_err(AgentError)?;
        let presets = config.presets.clone();
        let mut shipper_options = ShipperOptions::new(config.endpoint_base());
        shipper_options.limits = BatchLimits::from(&config.limits);
        shipper_options.max_requests_per_minute = config.limits.max_requests_per_minute;
        Ok(Self {
            config,
            collectors,
            processor: Box::new(processor),
            credential,
            host: HostInfo::detect(),
            presets,
            shipper_options,
            rotation: None,
        })
    }

    /// Rotate the host credential in `store` in the background when it is due (see
    /// [`Rotator`]). `store` should be the same store the agent reads its credential from.
    pub fn with_rotation(
        mut self,
        store: Arc<dyn CredentialStore>,
        options: RotationOptions,
    ) -> Self {
        self.rotation = Some((store, options));
        self
    }

    /// Replace the rule pipeline that runs before events reach the disk buffer (tests, custom
    /// pipelines). The replacement is then responsible for redaction.
    pub fn with_processor(mut self, processor: Box<dyn Processor>) -> Self {
        self.processor = processor;
        self
    }

    /// Add a collector that is not built from a config rule.
    pub fn with_collector(mut self, collector: Box<dyn Collector>) -> Self {
        self.collectors.push(collector);
        self
    }

    /// Preset names reported in the heartbeat.
    pub fn with_presets(mut self, presets: Vec<String>) -> Self {
        self.presets = presets;
        self
    }

    /// Override shipping options (tests, tuning).
    pub fn with_shipper_options(mut self, options: ShipperOptions) -> Self {
        self.shipper_options = options;
        self
    }

    /// Run until `stop` is triggered. Everything durable is fsynced as it happens, so the
    /// process can also be killed at any point without losing acknowledged state.
    pub fn run(self, stop: Stop) -> Result<(), AgentError> {
        let Self {
            config,
            collectors,
            mut processor,
            credential,
            host,
            presets,
            shipper_options,
            rotation,
        } = self;
        let started = Instant::now();
        let state_dir = config.state_dir.clone();
        let io_err = |what: &str, e: std::io::Error| {
            AgentError(format!("{what} in {}: {e}", state_dir.display()))
        };

        let buffer = DiskBuffer::open(
            &state_dir.join("buffer"),
            config.buffer.max_mb * 1024 * 1024,
        )
        .map_err(|e| io_err("cannot open the disk buffer", e))?;
        let buffer = Arc::new(Mutex::new(buffer));
        let mut checkpoints =
            CheckpointStore::open(&state_dir).map_err(|e| io_err("cannot open checkpoints", e))?;
        let metrics = Arc::new(Metrics::default());

        let rotator = match rotation {
            Some((store, options)) => Some(
                Rotator::new(&shipper_options.endpoint, store, &state_dir, options)
                    .map_err(AgentError)?,
            ),
            None => None,
        };
        let shipper =
            Shipper::new(shipper_options, credential, Arc::clone(&metrics)).map_err(AgentError)?;
        let shipper_thread = {
            let buffer = Arc::clone(&buffer);
            let stop = stop.clone();
            thread::Builder::new()
                .name("shipper".into())
                .spawn(move || shipper.run(buffer, stop))
                .map_err(|e| AgentError(format!("cannot start the shipper: {e}")))?
        };
        let rotation_thread = match rotator {
            Some(rotator) => {
                let stop = stop.clone();
                Some(
                    thread::Builder::new()
                        .name("rotation".into())
                        .spawn(move || rotator.run(stop))
                        .map_err(|e| AgentError(format!("cannot start rotation: {e}")))?,
                )
            }
            None => None,
        };

        let (tx, rx) = mpsc::sync_channel::<Message>(QUEUE_BATCHES);
        let mut rule_ids = Vec::new();
        let mut collector_threads = Vec::new();
        for collector in collectors {
            let idx = metrics.register_collector(collector.rule_id());
            rule_ids.push(collector.rule_id().to_owned());
            let checkpoint = checkpoints.get(collector.rule_id());
            let (tx, metrics, stop) = (tx.clone(), Arc::clone(&metrics), stop.clone());
            let handle = thread::Builder::new()
                .name(format!("collector-{}", collector.rule_id()))
                .spawn(move || collect(collector, idx, checkpoint, &tx, &metrics, &stop))
                .map_err(|e| AgentError(format!("cannot start a collector: {e}")))?;
            collector_threads.push(handle);
        }
        drop(tx);
        log::info!(
            "agent {} started with {} collectors",
            telemetry::AGENT_VERSION,
            rule_ids.len()
        );

        let max_event_bytes = usize::try_from(config.limits.max_event_bytes).unwrap_or(usize::MAX);
        let interval = Duration::from_secs(config.heartbeat.interval_s);
        let mut next_heartbeat = Instant::now();
        let mut next_status = Instant::now();
        let mut collectors_done = false;
        loop {
            let now = Instant::now();
            if now >= next_heartbeat {
                let fields = snapshot(&buffer, &metrics, &host, started, &presets);
                let line = telemetry::heartbeat_event(fields).to_wire_line();
                if let Err(e) = buffer
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .append(&[line])
                {
                    log::error!("cannot buffer the heartbeat: {e}");
                }
                next_heartbeat = now + interval;
            }
            if now >= next_status {
                let fields = snapshot(&buffer, &metrics, &host, started, &presets);
                write_status(&state_dir, &telemetry::status_json(&fields, &metrics));
                next_status = now + STATUS_INTERVAL;
            }
            if stop.is_stopped() && collectors_done {
                break;
            }
            if collectors_done {
                stop.wait(Duration::from_secs(1));
                continue;
            }
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(Message { collector, batch }) => {
                    let lines =
                        process(batch.events, processor.as_mut(), max_event_bytes, &metrics);
                    let appended = buffer
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .append(&lines);
                    match appended {
                        Ok(()) => {
                            if let Some(cp) = batch.checkpoint
                                && let Err(e) = checkpoints.save(&rule_ids[collector], cp)
                            {
                                log::error!(
                                    "cannot save checkpoint for {}: {e}",
                                    rule_ids[collector]
                                );
                            }
                        }
                        // Without the checkpoint these events are read again after a restart.
                        Err(e) => log::error!("cannot write to the disk buffer: {e}"),
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => collectors_done = true,
            }
        }

        for handle in collector_threads {
            let _ = handle.join();
        }
        let _ = shipper_thread.join();
        if let Some(handle) = rotation_thread {
            let _ = handle.join();
        }
        let fields = snapshot(&buffer, &metrics, &host, started, &presets);
        write_status(&state_dir, &telemetry::status_json(&fields, &metrics));
        log::info!("agent stopped");
        Ok(())
    }
}

/// Run the redaction/filter hook and serialise. Oversize events are dropped and counted.
fn process(
    events: Vec<RawEvent>,
    processor: &mut dyn Processor,
    max_event_bytes: usize,
    metrics: &Metrics,
) -> Vec<Vec<u8>> {
    let mut lines = Vec::with_capacity(events.len());
    for event in events {
        match processor.process(event) {
            Verdict::Keep(event) => {
                let line = event.to_wire_line();
                if line.len() > max_event_bytes {
                    Metrics::add(&metrics.dropped_oversize, 1);
                } else {
                    lines.push(line);
                }
            }
            Verdict::Filtered => {}
            Verdict::Sampled => Metrics::add(&metrics.dropped_sampled, 1),
            Verdict::RateLimited => Metrics::add(&metrics.dropped_rate_limited, 1),
        }
    }
    lines
}

/// Heartbeat fields for the current buffer and counters.
fn snapshot(
    buffer: &Mutex<DiskBuffer>,
    metrics: &Metrics,
    host: &HostInfo,
    started: Instant,
    presets: &[String],
) -> serde_json::Map<String, serde_json::Value> {
    let stats = {
        let buf = buffer.lock().unwrap_or_else(PoisonError::into_inner);
        metrics
            .dropped_buffer_full
            .store(buf.dropped_full(), std::sync::atomic::Ordering::Relaxed);
        BufferStats {
            bytes: buf.bytes(),
            events: buf.pending_records(),
        }
    };
    telemetry::heartbeat_fields(host, started, stats, metrics, presets)
}

fn write_status(dir: &Path, status: &serde_json::Value) {
    let bytes = serde_json::to_vec_pretty(status).unwrap_or_default();
    if let Err(e) = write_atomic(dir, telemetry::STATUS_FILE, &bytes) {
        log::warn!("cannot write {}: {e}", telemetry::STATUS_FILE);
    }
}

/// One collector's thread: start, poll, hand batches to the writer, restart with backoff on
/// errors.
fn collect(
    mut collector: Box<dyn Collector>,
    idx: usize,
    mut checkpoint: Option<Checkpoint>,
    tx: &SyncSender<Message>,
    metrics: &Metrics,
    stop: &Stop,
) {
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
    let mut running = false;
    while !stop.is_stopped() {
        if !running {
            match collector.start(checkpoint.clone()) {
                Ok(()) => {
                    running = true;
                    metrics.collector_running(idx);
                }
                Err(e) => {
                    log::warn!("collector {}: {e}", collector.rule_id());
                    metrics.collector_error(idx, &e.0);
                    stop.wait(backoff.next_delay());
                    continue;
                }
            }
        }
        match collector.poll(POLL_MAX_EVENTS, POLL_WAIT) {
            Ok(batch) => {
                backoff.reset();
                if batch.events.is_empty() {
                    continue;
                }
                if let Some(cp) = &batch.checkpoint {
                    checkpoint = Some(cp.clone());
                }
                if tx
                    .send(Message {
                        collector: idx,
                        batch,
                    })
                    .is_err()
                {
                    break;
                }
            }
            Err(e) => {
                log::warn!("collector {}: {e}", collector.rule_id());
                metrics.collector_error(idx, &e.0);
                running = false;
                stop.wait(backoff.next_delay());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::path::Path;

    use agent_collectors::EventTemplate;
    use serde_json::Value;

    use super::*;
    use crate::buffer::tests::TempDir;
    use crate::credential::{Secret, StaticCredential};
    use crate::shipper::test_server::Server;

    #[test]
    fn end_to_end_file_to_server_with_redaction_before_disk() {
        let dir = TempDir::new("agent-e2e");
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        let log_path = dir.0.join("app.log");
        let noisy_path = dir.0.join("noisy.log");
        let sampled_path = dir.0.join("sampled.log");
        for p in [&log_path, &noisy_path, &sampled_path] {
            std::fs::write(p, "").expect("create");
        }
        let server = Server::start(vec![]);
        // Redaction, filtering, rate limiting and sampling all come from the rules.
        let config = AgentConfig::parse(&format!(
            r#"[agent]
endpoint = "{}"
state_dir = {:?}
[[rule]]
id = "app"
type = "file"
paths = [{:?}]
source_label = "web/app"
exclude_match = ['^drop me$']
redact = [{{ pattern = 'password=\S+', replace = "password=[REDACTED]" }}]
parser = "logfmt"
[[rule]]
id = "noisy"
type = "file"
paths = [{:?}]
rate_limit = {{ events_per_second = 1, burst = 2 }}
[[rule]]
id = "sampled"
type = "file"
paths = [{:?}]
sample_rate = 0.000000001
"#,
            server.url,
            dir.0.join("state"),
            log_path,
            noisy_path,
            sampled_path,
        ))
        .expect("config");
        let cred = Arc::new(StaticCredential(Some(Secret::new(
            "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        ))));
        let mut opts = ShipperOptions::new(&server.url);
        opts.flush_interval = Duration::from_millis(100);
        let agent = Agent::new(config, cred)
            .expect("agent")
            .with_shipper_options(opts);
        let stop = Stop::new();
        let runner = {
            let stop = stop.clone();
            thread::spawn(move || agent.run(stop))
        };

        thread::sleep(Duration::from_millis(500));
        let append = |path: &Path, lines: &[&str]| {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .expect("open");
            for line in lines {
                writeln!(f, "{line}").expect("write");
            }
        };
        append(
            &log_path,
            &[
                "login user=alice password=hunter2",
                "drop me",
                "second line",
            ],
        );
        append(&noisy_path, &["noise"; 10]);
        append(&sampled_path, &["sample"; 20]);

        let deadline = Instant::now() + Duration::from_secs(10);
        let lines = loop {
            let lines: Vec<Value> = server
                .requests()
                .iter()
                .flat_map(|r| {
                    r.lines
                        .iter()
                        .map(|l| serde_json::from_str(l).expect("json"))
                })
                .collect();
            if lines.iter().filter(|l| l["source_type"] == "file").count() >= 4
                || Instant::now() > deadline
            {
                break lines;
            }
            thread::sleep(Duration::from_millis(50));
        };
        stop.stop();
        runner.join().expect("join").expect("run");

        let app: Vec<&Value> = lines.iter().filter(|l| l["rule_id"] == "app").collect();
        assert_eq!(app.len(), 2, "{lines:?}");
        assert_eq!(app[0]["body"], "login user=alice password=[REDACTED]");
        assert_eq!(app[0]["fields"]["user"], "alice");
        assert_eq!(app[0]["fields"]["password"], "[REDACTED]");
        assert_eq!(app[0]["attrs"]["source_label"], "web/app");
        assert_eq!(app[1]["body"], "second line");
        let noisy = lines.iter().filter(|l| l["rule_id"] == "noisy").count();
        assert!((2..=3).contains(&noisy), "{noisy}");
        assert!(!lines.iter().any(|l| l["rule_id"] == "sampled"));
        assert!(lines.iter().any(|l| l["source_type"] == "agent.heartbeat"));

        // The secret never reached the disk buffer.
        for entry in std::fs::read_dir(dir.0.join("state/buffer")).expect("buffer dir") {
            let bytes = std::fs::read(entry.expect("entry").path()).expect("read");
            assert!(!bytes.windows(7).any(|w| w == b"hunter2"));
        }
        // Drops are counted in the heartbeat fields (status.json carries the same fields).
        let status: Value = serde_json::from_slice(
            &std::fs::read(dir.0.join("state/status.json")).expect("status"),
        )
        .expect("json");
        assert_eq!(status["collectors"][0]["rule_id"], "app");
        assert_eq!(status["dropped"]["sampled"], 20);
        assert_eq!(status["dropped"]["rate_limited"], 10 - noisy);
    }

    #[test]
    fn rule_drops_are_counted_in_the_heartbeat() {
        let config = AgentConfig::parse(
            "[agent]\nendpoint = \"https://ingest.example.com\"\n[[rule]]\nid = \"r\"\ntype = \"journald\"\nsample_rate = 0.5\nrate_limit = { events_per_second = 1, burst = 3 }\n",
        )
        .expect("config");
        let mut processor = RuleProcessor::new(&config.rules)
            .expect("processor")
            .with_seed(1);
        let template = EventTemplate::new("r", "journald", None, &BTreeMap::new());
        let events = (0..100)
            .map(|_| template.event(1, None, serde_json::Map::new()))
            .collect();
        let metrics = Metrics::default();
        let lines = process(events, &mut processor, 1 << 20, &metrics);
        assert_eq!(lines.len(), 3);
        let fields = telemetry::heartbeat_fields(
            &HostInfo::detect(),
            Instant::now(),
            BufferStats::default(),
            &metrics,
            &[],
        );
        let sampled = fields["dropped"]["sampled"].as_u64().expect("sampled");
        let limited = fields["dropped"]["rate_limited"].as_u64().expect("limited");
        assert!(sampled > 20 && limited > 20, "{fields:?}");
        assert_eq!(sampled + limited + 3, 100);
        let event = telemetry::heartbeat_event(fields);
        let line: Value = serde_json::from_slice(&event.to_wire_line()).expect("json");
        assert_eq!(line["fields"]["dropped"]["rate_limited"], limited);
    }

    /// A collector that fails on start a few times, then produces one event.
    struct Flaky {
        template: EventTemplate,
        failures: u32,
        sent: bool,
    }

    impl Collector for Flaky {
        fn rule_id(&self) -> &str {
            "flaky"
        }

        fn start(&mut self, _: Option<Checkpoint>) -> Result<(), agent_collectors::CollectorError> {
            if self.failures > 0 {
                self.failures -= 1;
                return Err(agent_collectors::CollectorError("not yet".into()));
            }
            Ok(())
        }

        fn poll(
            &mut self,
            _: usize,
            wait: Duration,
        ) -> Result<Batch, agent_collectors::CollectorError> {
            if self.sent {
                thread::sleep(wait.min(Duration::from_millis(50)));
                return Ok(Batch::default());
            }
            self.sent = true;
            Ok(Batch {
                events: vec![
                    self.template
                        .event(1, Some("hello".into()), Default::default()),
                ],
                checkpoint: None,
            })
        }
    }

    #[test]
    fn collector_errors_are_reported_and_retried() {
        let dir = TempDir::new("agent-flaky");
        let server = Server::start(vec![]);
        let config = AgentConfig::parse(&format!(
            "endpoint = \"{}\"\nstate_dir = {:?}\n",
            server.url, dir.0
        ))
        .expect("config");
        let template = EventTemplate::new("flaky", "file", None, &BTreeMap::new());
        let mut opts = ShipperOptions::new(&server.url);
        opts.flush_interval = Duration::ZERO;
        let agent = Agent::new(config, Arc::new(StaticCredential(None)))
            .expect("agent")
            .with_collector(Box::new(Flaky {
                template,
                failures: 1,
                sent: false,
            }))
            .with_shipper_options(opts);
        let stop = Stop::new();
        let runner = {
            let stop = stop.clone();
            thread::spawn(move || agent.run(stop))
        };
        // One failed start, a backoff of up to 1 s, then the event is buffered (not shipped:
        // the host is not enrolled).
        thread::sleep(Duration::from_millis(2500));
        stop.stop();
        runner.join().expect("join").expect("run");
        let buf = DiskBuffer::open(&dir.0.join("buffer"), 16 << 20).expect("open");
        let lines = buf.peek(100, u64::MAX).expect("peek").lines;
        assert!(
            lines
                .iter()
                .any(|l| String::from_utf8_lossy(l).contains("\"hello\""))
        );
        let status: Value =
            serde_json::from_slice(&std::fs::read(dir.0.join("status.json")).expect("status"))
                .expect("json");
        assert_eq!(status["ship"]["last_error"], "not enrolled");
        assert!(server.requests().is_empty());
    }
}
