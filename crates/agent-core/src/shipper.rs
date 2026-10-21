//! Sends batches from the disk buffer to `POST <endpoint>/v1/agent/events`.
//!
//! One batch is in flight at a time. Its id (`X-Wedgetail-Batch-Id`) is fixed before the first
//! attempt and reused on every retry and after a restart, so the server can answer a repeat
//! from its idempotency store instead of storing the events twice.

use std::io;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Deserialize;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

use crate::backoff::{Backoff, RateLimiter, parse_retry_after};
use crate::batch::{self, BatchLimits, Oversize};
use crate::buffer::DiskBuffer;
use crate::credential::{CredentialProvider, Secret};
use crate::stop::Stop;
use crate::telemetry::{AGENT_VERSION, Metrics};

const EVENTS_PATH: &str = "/v1/agent/events";
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct ShipperOptions {
    /// Base URL, `https://` only outside tests.
    pub endpoint: String,
    pub limits: BatchLimits,
    pub max_requests_per_minute: u32,
    /// A partly filled batch is sent once its oldest record has waited this long.
    pub flush_interval: Duration,
    pub backoff_base: Duration,
    pub backoff_cap: Duration,
}

impl ShipperOptions {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            limits: BatchLimits::default(),
            max_requests_per_minute: agent_config::SERVER_MAX_REQUESTS_PER_MINUTE,
            flush_interval: Duration::from_secs(5),
            backoff_base: Duration::from_secs(1),
            backoff_cap: Duration::from_secs(300),
        }
    }
}

/// Server reply to an accepted batch.
#[derive(Debug, Default, Deserialize)]
pub struct Accepted {
    #[serde(default)]
    pub accepted: u64,
    #[serde(default)]
    pub skipped: u64,
    #[serde(default)]
    pub errors: Vec<RecordError>,
}

#[derive(Debug, Deserialize)]
pub struct RecordError {
    #[serde(default)]
    pub index: u64,
    #[serde(default)]
    pub reason: String,
}

/// How one POST ended.
#[derive(Debug)]
pub enum Outcome {
    Accepted(Accepted),
    /// The server will never take this batch (malformed): drop it.
    Rejected(String),
    /// 413: split the batch.
    TooLarge,
    /// Try again later, after `after` if the server said so.
    Retry {
        after: Option<Duration>,
        reason: String,
    },
}

/// Map an HTTP status to an outcome. `retry_after` is the raw header.
pub fn classify(status: u16, retry_after: Option<&str>, body: &str) -> Outcome {
    let after = retry_after.and_then(parse_retry_after);
    match status {
        200..=299 => Outcome::Accepted(serde_json::from_str(body).unwrap_or_default()),
        413 => Outcome::TooLarge,
        // Auth failures keep the data: the host may be re-enrolled or the credential rotated.
        401 | 403 => Outcome::Retry {
            after: None,
            reason: format!("HTTP {status}: credential rejected"),
        },
        // Wrong endpoint or path: a configuration problem, not a reason to lose data.
        404 | 405 => Outcome::Retry {
            after: None,
            reason: format!("HTTP {status}: check the endpoint"),
        },
        408 | 425 | 429 | 500..=599 => Outcome::Retry {
            after,
            reason: format!("HTTP {status}"),
        },
        300..=399 => Outcome::Retry {
            after: None,
            reason: format!("HTTP {status}: redirects are not followed"),
        },
        _ => Outcome::Rejected(format!(
            "HTTP {status}: {}",
            body.chars().take(200).collect::<String>()
        )),
    }
}

/// The HTTP client for every agent request: rustls (TLS 1.2 and 1.3 only, the ring provider)
/// with the OS certificate verifier, which is always on; no redirects; `https://` only. Plain
/// HTTP exists only for the in-process test server, so release builds cannot use it.
pub(crate) fn http_agent(endpoint: &str) -> Result<ureq::Agent, String> {
    let allow_http = cfg!(test);
    check_scheme(endpoint, allow_http)?;
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .root_certs(RootCerts::PlatformVerifier)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .build();
    Ok(ureq::Agent::config_builder()
        .https_only(!allow_http)
        .tls_config(tls)
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_global(Some(Duration::from_secs(120)))
        .user_agent(format!("wedgetail-agent/{AGENT_VERSION}"))
        .build()
        .new_agent())
}

/// Refuse anything but `https://` unless `allow_http` (tests only).
pub fn check_scheme(endpoint: &str, allow_http: bool) -> Result<(), String> {
    if endpoint.starts_with("https://") || (allow_http && endpoint.starts_with("http://")) {
        Ok(())
    } else {
        Err("endpoint must use https://".into())
    }
}

#[derive(Debug)]
pub struct Shipper {
    opts: ShipperOptions,
    url: String,
    agent: ureq::Agent,
    credential: Arc<dyn CredentialProvider>,
    metrics: Arc<Metrics>,
    rate: RateLimiter,
    backoff: Backoff,
    pending_since: Option<Instant>,
    warned_not_enrolled: bool,
}

impl Shipper {
    pub fn new(
        opts: ShipperOptions,
        credential: Arc<dyn CredentialProvider>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, String> {
        let agent = http_agent(&opts.endpoint)?;
        Ok(Self {
            url: format!("{}{EVENTS_PATH}", opts.endpoint),
            rate: RateLimiter::new(opts.max_requests_per_minute),
            backoff: Backoff::new(opts.backoff_base, opts.backoff_cap),
            opts,
            agent,
            credential,
            metrics,
            pending_since: None,
            warned_not_enrolled: false,
        })
    }

    /// Ship until stopped.
    pub fn run(mut self, buffer: Arc<Mutex<DiskBuffer>>, stop: Stop) {
        while !stop.is_stopped() {
            match self.ship_once(&buffer, &stop) {
                Ok(true) => {}
                Ok(false) => {
                    stop.wait(Duration::from_secs(1));
                }
                Err(e) => {
                    log::error!("disk buffer: {e}");
                    self.metrics.ship_error(&format!("disk buffer: {e}"));
                    stop.wait(Duration::from_secs(10));
                }
            }
        }
    }

    /// Send the next batch if one is due. Returns true if a batch was finished (sent or
    /// dropped), false if there was nothing to do or a stop was requested.
    pub fn ship_once(&mut self, buffer: &Mutex<DiskBuffer>, stop: &Stop) -> io::Result<bool> {
        let limits = self.opts.limits;
        let peeked = lock(buffer).peek(limits.max_records, limits.max_uncompressed_bytes as u64)?;
        if peeked.lines.is_empty() {
            self.pending_since = None;
            return Ok(false);
        }
        // Not enrolled (or the credential is unreadable): keep buffering, and do not fix a
        // batch yet so the first one sent is as full as the limits allow.
        if peeked.inflight_id.is_none() && self.current_credential().is_none() {
            return Ok(false);
        }
        let since = *self.pending_since.get_or_insert_with(Instant::now);
        let raw: usize = peeked.lines.iter().map(|l| l.len() + 1).sum();
        let full =
            peeked.lines.len() >= limits.max_records || raw * 2 >= limits.max_uncompressed_bytes;
        if peeked.inflight_id.is_none() && !full && since.elapsed() < self.opts.flush_interval {
            return Ok(false);
        }

        let mut lines = peeked.lines;
        loop {
            let encoded = match batch::encode(&lines, &limits) {
                Ok(e) => e,
                Err(Oversize) => {
                    // A single record too big for any request: drop it so the queue moves.
                    log::warn!("dropping one event too large for a request");
                    let mut buf = lock(buffer);
                    if let Some(id) = buf.begin(peeked.start, 1, peeked.ends[0])? {
                        buf.ack(&id)?;
                        Metrics::add(&self.metrics.dropped_oversize, 1);
                    }
                    return Ok(true);
                }
            };
            let n = encoded.records;
            let Some(id) = lock(buffer).begin(peeked.start, n, peeked.ends[n - 1])? else {
                // Records were dropped for space since the peek; start over.
                return Ok(true);
            };
            match self.send_with_retry(&id, &encoded.body, stop) {
                // Stopped: the batch stays in flight and is resent with the same id next time.
                None | Some(Outcome::Retry { .. }) => return Ok(false),
                Some(Outcome::TooLarge) if n > 1 => {
                    log::warn!("server said batch {id} was too large; splitting it");
                    lines.truncate(n / 2);
                    continue;
                }
                Some(Outcome::TooLarge) => {
                    lock(buffer).ack(&id)?;
                    Metrics::add(&self.metrics.dropped_oversize, 1);
                }
                Some(Outcome::Accepted(reply)) => {
                    lock(buffer).ack(&id)?;
                    Metrics::add(&self.metrics.sent_events, n as u64);
                    Metrics::add(&self.metrics.sent_batches, 1);
                    self.metrics.ship_ok();
                    if !reply.errors.is_empty() || reply.skipped > 0 {
                        let first = reply.errors.first().map(|e| {
                            format!(
                                " (record {}: {})",
                                e.index,
                                e.reason.chars().take(200).collect::<String>()
                            )
                        });
                        log::warn!(
                            "batch {id}: {} accepted, {} skipped{}",
                            reply.accepted,
                            reply.skipped,
                            first.unwrap_or_default()
                        );
                    }
                }
                Some(Outcome::Rejected(reason)) => {
                    log::error!("batch {id} rejected, dropping {n} events: {reason}");
                    lock(buffer).ack(&id)?;
                    Metrics::add(&self.metrics.rejected_events, n as u64);
                    self.metrics.ship_error(&reason);
                }
            }
            self.pending_since = None;
            return Ok(true);
        }
    }

    /// The credential, or `None` (logged and reported in status) when there is none yet or it
    /// cannot be read.
    fn current_credential(&mut self) -> Option<Secret> {
        match self.credential.credential() {
            Ok(Some(s)) => {
                self.warned_not_enrolled = false;
                Some(s)
            }
            Ok(None) => {
                if !self.warned_not_enrolled {
                    log::warn!(
                        "not enrolled yet: buffering events until a credential is available"
                    );
                    self.warned_not_enrolled = true;
                }
                self.metrics.ship_error("not enrolled");
                None
            }
            Err(e) => {
                log::error!("credential: {e}");
                self.metrics.ship_error(&format!("credential: {e}"));
                None
            }
        }
    }

    /// POST until the outcome is final (never `Retry`). `None` if stopped first.
    fn send_with_retry(&mut self, id: &str, body: &[u8], stop: &Stop) -> Option<Outcome> {
        loop {
            if stop.is_stopped() {
                return None;
            }
            let wait = self.rate.wait(Instant::now());
            if !wait.is_zero() {
                if stop.wait(wait) {
                    return None;
                }
                continue;
            }
            let Some(secret) = self.current_credential() else {
                if stop.wait(Duration::from_secs(30)) {
                    return None;
                }
                continue;
            };
            self.rate.record(Instant::now());
            match self.post(id, body, secret.expose()) {
                Outcome::Retry { after, reason } => {
                    let delay = match after {
                        Some(a) => self.backoff.retry_after(a),
                        None => self.backoff.next_delay(),
                    };
                    log::warn!(
                        "batch {id}: {reason}; retrying in {:.1}s",
                        delay.as_secs_f32()
                    );
                    self.metrics.ship_error(&reason);
                    if stop.wait(delay) {
                        return None;
                    }
                }
                other => {
                    self.backoff.reset();
                    return Some(other);
                }
            }
        }
    }

    fn post(&self, id: &str, body: &[u8], credential: &str) -> Outcome {
        let result = self
            .agent
            .post(&self.url)
            .header("Authorization", &format!("Bearer {credential}"))
            .header("Content-Type", "application/x-ndjson")
            .header("Content-Encoding", "gzip")
            .header("X-Wedgetail-Batch-Id", id)
            .send(body);
        match result {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                let retry_after = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let text = resp
                    .body_mut()
                    .with_config()
                    .limit(MAX_RESPONSE_BYTES)
                    .read_to_string()
                    .unwrap_or_default();
                classify(status, retry_after.as_deref(), &text)
            }
            // Transport errors (DNS, connect, TLS, timeout) are always retried. The error text
            // never includes request headers, so the credential cannot leak into logs.
            Err(e) => Outcome::Retry {
                after: None,
                reason: e.to_string(),
            },
        }
    }
}

fn lock(buffer: &Mutex<DiskBuffer>) -> std::sync::MutexGuard<'_, DiskBuffer> {
    buffer.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
pub(crate) mod test_server {
    //! A tiny HTTP/1.1 server for tests: records each request and answers from a script.

    use std::collections::{HashMap, VecDeque};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    use flate2::read::GzDecoder;

    #[derive(Debug, Clone)]
    pub struct Request {
        pub at: Instant,
        pub path: String,
        pub headers: HashMap<String, String>,
        /// The body, gunzipped if it was sent with `Content-Encoding: gzip`.
        pub body: String,
        pub lines: Vec<String>,
    }

    impl Request {
        pub fn bearer(&self) -> &str {
            self.headers
                .get("authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("")
        }
    }

    /// `(status, extra headers, body)`; `None` closes the connection without answering.
    pub type Reply = Option<(u16, Vec<(String, String)>, String)>;

    type Handler = Box<dyn Fn(&Request) -> Reply + Send + Sync>;

    #[derive(Clone)]
    pub struct Server {
        pub url: String,
        pub requests: Arc<Mutex<Vec<Request>>>,
        handler: Arc<Handler>,
    }

    impl std::fmt::Debug for Server {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Server").field("url", &self.url).finish()
        }
    }

    pub fn ok_reply(n: usize) -> Reply {
        Some((
            200,
            vec![],
            format!(r#"{{"accepted":{n},"skipped":0,"errors":[]}}"#),
        ))
    }

    impl Server {
        /// Answers from `script` in order, then 200 for everything.
        pub fn start(script: Vec<Reply>) -> Self {
            let script = Mutex::new(VecDeque::from(script));
            Self::with_handler(move |req| {
                script
                    .lock()
                    .expect("lock")
                    .pop_front()
                    .unwrap_or_else(|| ok_reply(req.lines.len()))
            })
        }

        /// Answers every request with `handler`.
        pub fn with_handler(handler: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let url = format!("http://{}", listener.local_addr().expect("addr"));
            let server = Self {
                url,
                requests: Arc::default(),
                handler: Arc::new(Box::new(handler)),
            };
            let s = server.clone();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                        continue;
                    }
                    let mut headers = HashMap::new();
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).expect("header");
                        let line = line.trim_end();
                        if line.is_empty() {
                            break;
                        }
                        if let Some((k, v)) = line.split_once(':') {
                            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
                        }
                    }
                    let len: usize = headers
                        .get("content-length")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let mut body = vec![0; len];
                    reader.read_exact(&mut body).expect("body");
                    let mut text = String::new();
                    if headers.get("content-encoding").map(String::as_str) == Some("gzip") {
                        GzDecoder::new(&body[..])
                            .read_to_string(&mut text)
                            .expect("gzip body");
                    } else {
                        text = String::from_utf8(body).expect("utf-8 body");
                    }
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("")
                        .to_owned();
                    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
                    let request = Request {
                        at: Instant::now(),
                        path,
                        headers,
                        body: text,
                        lines,
                    };
                    let reply = (s.handler)(&request);
                    s.requests.lock().expect("lock").push(request);
                    let Some((status, extra, body)) = reply else {
                        continue;
                    };
                    let mut resp = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                        body.len()
                    );
                    for (k, v) in extra {
                        resp.push_str(&format!("{k}: {v}\r\n"));
                    }
                    resp.push_str("\r\n");
                    resp.push_str(&body);
                    let _ = stream.write_all(resp.as_bytes());
                }
            });
            server
        }

        pub fn requests(&self) -> Vec<Request> {
            self.requests.lock().expect("lock").clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::test_server::{Server, ok_reply};
    use super::*;
    use crate::buffer::tests::TempDir;
    use crate::credential::{Secret, StaticCredential};

    const CRED: &str = "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn shipper(url: &str, max_records: usize) -> Shipper {
        let mut opts = ShipperOptions::new(url);
        opts.limits.max_records = max_records;
        opts.flush_interval = Duration::ZERO;
        opts.backoff_base = Duration::from_millis(50);
        opts.backoff_cap = Duration::from_millis(200);
        let cred = Arc::new(StaticCredential(Some(Secret::new(CRED.into()))));
        Shipper::new(opts, cred, Arc::new(Metrics::default())).expect("shipper")
    }

    fn records(range: std::ops::Range<u32>) -> Vec<String> {
        range.map(|i| format!(r#"{{"v":1,"n":{i}}}"#)).collect()
    }

    fn filled(dir: &TempDir, range: std::ops::Range<u32>) -> Arc<Mutex<DiskBuffer>> {
        let mut buf = DiskBuffer::open(&dir.0, 16 << 20).expect("open");
        buf.append(&records(range)).expect("append");
        Arc::new(Mutex::new(buf))
    }

    #[test]
    fn posts_gzip_ndjson_with_contract_headers() {
        let server = Server::start(vec![]);
        let dir = TempDir::new("ship-headers");
        let buf = filled(&dir, 0..3);
        let mut s = shipper(&server.url, 100);
        assert!(s.ship_once(&buf, &Stop::new()).expect("ship"));
        let reqs = server.requests();
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        assert_eq!(r.path, "/v1/agent/events");
        assert_eq!(r.headers["authorization"], format!("Bearer {CRED}"));
        assert_eq!(r.headers["content-encoding"], "gzip");
        assert_eq!(r.headers["content-type"], "application/x-ndjson");
        let id = &r.headers["x-wedgetail-batch-id"];
        assert!(
            id.len() <= 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert!(r.headers["user-agent"].starts_with("wedgetail-agent/"));
        assert_eq!(r.lines, records(0..3));
        assert_eq!(lock(&buf).pending_records(), 0);
        assert_eq!(
            s.metrics
                .sent_events
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );
    }

    #[test]
    fn honours_retry_after_on_429_and_keeps_the_batch_id() {
        let server = Server::start(vec![
            Some((429, vec![("Retry-After".into(), "1".into())], "{}".into())),
            ok_reply(2),
        ]);
        let dir = TempDir::new("ship-429");
        let buf = filled(&dir, 0..2);
        let mut s = shipper(&server.url, 100);
        assert!(s.ship_once(&buf, &Stop::new()).expect("ship"));
        let reqs = server.requests();
        assert_eq!(reqs.len(), 2);
        assert!(
            reqs[1].at - reqs[0].at >= Duration::from_secs(1),
            "waited {:?}",
            reqs[1].at - reqs[0].at
        );
        assert_eq!(
            reqs[0].headers["x-wedgetail-batch-id"],
            reqs[1].headers["x-wedgetail-batch-id"]
        );
        assert_eq!(reqs[1].lines, records(0..2));
        assert_eq!(lock(&buf).pending_records(), 0);
    }

    #[test]
    fn backs_off_on_503_without_retry_after_and_never_drops_on_401() {
        let server = Server::start(vec![
            Some((503, vec![], String::new())),
            Some((
                401,
                vec![],
                r#"{"error":"Missing or invalid credential."}"#.into(),
            )),
            Some((500, vec![], String::new())),
            ok_reply(1),
        ]);
        let dir = TempDir::new("ship-503");
        let buf = filled(&dir, 0..1);
        let mut s = shipper(&server.url, 100);
        assert!(s.ship_once(&buf, &Stop::new()).expect("ship"));
        let reqs = server.requests();
        assert_eq!(reqs.len(), 4);
        assert!(reqs.iter().all(|r| r.lines == records(0..1)));
        assert_eq!(lock(&buf).pending_records(), 0);
    }

    #[test]
    fn revoked_credential_backs_off_and_keeps_the_events() {
        let server = Server::with_handler(|_| {
            Some((
                401,
                vec![],
                r#"{"error":"Missing or invalid credential."}"#.into(),
            ))
        });
        let dir = TempDir::new("ship-revoked");
        let buf = filled(&dir, 0..5);
        let stop = Stop::new();
        let worker = {
            let (buf, stop, url) = (Arc::clone(&buf), stop.clone(), server.url.clone());
            thread::spawn(move || shipper(&url, 100).ship_once(&buf, &stop).expect("ship"))
        };
        thread::sleep(Duration::from_secs(1));
        stop.stop();
        assert!(!worker.join().expect("join"));
        // Backoff (50 ms doubling to 200 ms, with jitter) allows a handful of attempts a
        // second, not a storm, and the batch is kept for when the host is enrolled again.
        let attempts = server.requests().len();
        assert!((2..40).contains(&attempts), "{attempts} attempts");
        assert_eq!(lock(&buf).pending_records(), 5);
    }

    #[test]
    fn permanent_rejection_drops_the_batch_and_counts_it() {
        let server = Server::start(vec![Some((400, vec![], r#"{"error":"bad"}"#.into()))]);
        let dir = TempDir::new("ship-400");
        let buf = filled(&dir, 0..4);
        let mut s = shipper(&server.url, 100);
        assert!(s.ship_once(&buf, &Stop::new()).expect("ship"));
        assert_eq!(lock(&buf).pending_records(), 0);
        assert_eq!(
            s.metrics
                .rejected_events
                .load(std::sync::atomic::Ordering::Relaxed),
            4
        );
    }

    #[test]
    fn splits_on_413() {
        let server = Server::start(vec![Some((
            413,
            vec![],
            r#"{"error":"too large","limit":1048576}"#.into(),
        ))]);
        let dir = TempDir::new("ship-413");
        let buf = filled(&dir, 0..10);
        let mut s = shipper(&server.url, 100);
        assert!(s.ship_once(&buf, &Stop::new()).expect("ship"));
        assert!(s.ship_once(&buf, &Stop::new()).expect("ship"));
        let reqs = server.requests();
        assert_eq!(
            reqs.iter().map(|r| r.lines.len()).collect::<Vec<_>>(),
            [10, 5, 5]
        );
        assert_ne!(
            reqs[0].headers["x-wedgetail-batch-id"],
            reqs[1].headers["x-wedgetail-batch-id"]
        );
        assert_eq!(lock(&buf).pending_records(), 0);
    }

    #[test]
    fn splits_at_record_limit_into_separate_requests() {
        let server = Server::start(vec![]);
        let dir = TempDir::new("ship-split");
        let buf = filled(&dir, 0..25);
        let mut s = shipper(&server.url, 10);
        while s.ship_once(&buf, &Stop::new()).expect("ship") {}
        let sizes: Vec<usize> = server.requests().iter().map(|r| r.lines.len()).collect();
        assert_eq!(sizes, [10, 10, 5]);
    }

    #[test]
    fn waits_for_flush_interval_before_sending_a_partial_batch() {
        let server = Server::start(vec![]);
        let dir = TempDir::new("ship-flush");
        let buf = filled(&dir, 0..3);
        let mut s = shipper(&server.url, 100);
        s.opts.flush_interval = Duration::from_millis(300);
        assert!(!s.ship_once(&buf, &Stop::new()).expect("ship"));
        assert!(server.requests().is_empty());
        thread::sleep(Duration::from_millis(350));
        assert!(s.ship_once(&buf, &Stop::new()).expect("ship"));
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn kill_mid_batch_then_restart_resends_only_the_unacked_batch() {
        // First process: the server reads the request but the process dies before any reply.
        let first = Server::start(vec![None, None, None, None, None, None]);
        let dir = TempDir::new("ship-kill");
        let buf = filled(&dir, 0..25);
        let stop = Stop::new();
        let worker = {
            let buf = Arc::clone(&buf);
            let stop = stop.clone();
            let url = first.url.clone();
            thread::spawn(move || {
                let mut s = shipper(&url, 10);
                s.ship_once(&buf, &stop).expect("ship")
            })
        };
        while first.requests().is_empty() {
            thread::sleep(Duration::from_millis(10));
        }
        stop.stop();
        assert!(!worker.join().expect("join"), "stopped before an ack");
        let unacked = first.requests()[0].clone();
        assert_eq!(unacked.lines, records(0..10));
        drop(buf); // no clean shutdown

        // Restart: a new buffer and shipper on the same directory.
        let second = Server::start(vec![]);
        let buf = Arc::new(Mutex::new(
            DiskBuffer::open(&dir.0, 16 << 20).expect("reopen"),
        ));
        let mut s = shipper(&second.url, 10);
        while s.ship_once(&buf, &Stop::new()).expect("ship") {}
        let reqs = second.requests();
        assert_eq!(
            reqs[0].headers["x-wedgetail-batch-id"],
            unacked.headers["x-wedgetail-batch-id"]
        );
        assert_eq!(reqs[0].lines, unacked.lines);
        let all: Vec<String> = reqs.iter().flat_map(|r| r.lines.clone()).collect();
        assert_eq!(
            all,
            records(0..25),
            "every record exactly once after the restart"
        );
    }

    #[test]
    fn not_enrolled_keeps_buffering() {
        let server = Server::start(vec![]);
        let dir = TempDir::new("ship-noenrol");
        let buf = filled(&dir, 0..2);
        let mut opts = ShipperOptions::new(&server.url);
        opts.flush_interval = Duration::ZERO;
        let mut s = Shipper::new(
            opts,
            Arc::new(StaticCredential(None)),
            Arc::new(Metrics::default()),
        )
        .expect("shipper");
        let stop = Stop::new();
        let stopper = stop.clone();
        let t = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            stopper.stop();
        });
        assert!(!s.ship_once(&buf, &stop).expect("ship"));
        t.join().expect("join");
        assert!(server.requests().is_empty());
        assert_eq!(lock(&buf).pending_records(), 2);
    }

    #[test]
    fn tls_is_1_2_or_1_3_only() {
        // The client's rustls build offers these versions and nothing older.
        for v in rustls::ALL_VERSIONS {
            assert!(
                matches!(
                    v.version,
                    rustls::ProtocolVersion::TLSv1_2 | rustls::ProtocolVersion::TLSv1_3
                ),
                "{:?}",
                v.version
            );
        }
        assert!(http_agent("https://ingest.example.com").is_ok());
        assert!(http_agent("ftp://ingest.example.com").is_err());
    }

    #[test]
    fn scheme_and_status_classification() {
        assert!(check_scheme("http://ingest.example.com", false).is_err());
        assert!(check_scheme("ftp://ingest.example.com", true).is_err());
        assert!(check_scheme("https://ingest.example.com", false).is_ok());
        assert!(matches!(
            classify(200, None, "not json"),
            Outcome::Accepted(_)
        ));
        assert!(
            matches!(classify(429, Some("7"), ""), Outcome::Retry { after: Some(d), .. } if d == Duration::from_secs(7))
        );
        assert!(matches!(
            classify(503, Some("soon"), ""),
            Outcome::Retry { after: None, .. }
        ));
        assert!(matches!(classify(401, None, ""), Outcome::Retry { .. }));
        assert!(matches!(classify(302, None, ""), Outcome::Retry { .. }));
        assert!(matches!(classify(413, None, ""), Outcome::TooLarge));
        assert!(matches!(classify(400, None, ""), Outcome::Rejected(_)));
        assert!(matches!(classify(415, None, ""), Outcome::Rejected(_)));
    }
}
