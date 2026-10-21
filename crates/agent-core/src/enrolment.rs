//! Enrolment and credential rotation: `POST /v1/agent/enrol` swaps a one-off enrolment token
//! for a per-host credential, `POST /v1/agent/rotate` swaps the current credential for a new
//! one. The non-secret facts (host id, endpoint, when the credential was issued, the rotation
//! period) are kept in `enrolment.json` in the state directory; the credential itself only in
//! the [`CredentialStore`].

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_collectors::time;
use serde::{Deserialize, Serialize};

use crate::backoff::{Backoff, parse_retry_after};
use crate::credential::{CredentialStore, Secret, is_host_credential, write_private};
use crate::host::{self, HostInfo};
use crate::shipper::http_agent;
use crate::stop::Stop;
use crate::telemetry::AGENT_VERSION;

pub const ENROL_PATH: &str = "/v1/agent/enrol";
pub const ROTATE_PATH: &str = "/v1/agent/rotate";
/// Non-secret enrolment facts, in the state directory.
pub const ENROLMENT_FILE: &str = "enrolment.json";
/// Used when the server does not say.
pub const DEFAULT_ROTATE_AFTER_DAYS: u32 = 30;
const MAX_ROTATE_AFTER_DAYS: u32 = 365;
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
const DAY_S: u64 = 86_400;

/// The enrolment request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnrolRequest {
    pub hostname: String,
    /// `linux`, `windows` or `macos`.
    pub os: String,
    pub os_version: String,
    pub arch: String,
    pub machine_id: String,
    pub agent_version: String,
}

impl EnrolRequest {
    /// Facts about this host. Fails only if the machine id cannot be read.
    pub fn detect() -> Result<Self, String> {
        let host = HostInfo::detect();
        Ok(Self {
            hostname: host.hostname,
            os: host.os.to_owned(),
            os_version: host.os_version,
            arch: host.arch.to_owned(),
            machine_id: host::machine_id()
                .map_err(|e| format!("cannot read the machine id: {e}"))?,
            agent_version: AGENT_VERSION.to_owned(),
        })
    }
}

/// A successful enrolment.
#[derive(Debug)]
pub struct Enrolled {
    pub host_id: String,
    pub credential: Secret,
    pub rotate_after_days: u32,
}

/// A successful rotation.
#[derive(Debug)]
pub struct Rotated {
    pub credential: Secret,
    pub previous_valid_until: Option<String>,
}

/// Why an enrol or rotate call failed. No variant ever holds a token or credential.
#[derive(Debug, PartialEq, Eq)]
pub enum ApiError {
    /// 401: the token or credential was not accepted. The server never says why (unknown,
    /// expired, revoked or used up all look the same).
    Unauthorized,
    /// 408, 425, 429 or 5xx: try again later, after `retry_after` if the server said so.
    Unavailable {
        status: u16,
        retry_after: Option<Duration>,
    },
    /// Any other HTTP status, with the server's `error` text if it gave one.
    Status { status: u16, message: String },
    /// The TLS handshake failed (certificate not trusted, wrong name, protocol mismatch).
    Tls(String),
    /// DNS, connect, timeout or another transport error.
    Network(String),
    /// A 2xx reply that does not match the contract.
    BadResponse(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("HTTP 401: not accepted"),
            Self::Unavailable {
                status,
                retry_after: Some(after),
            } => write!(f, "HTTP {status}: retry in {} s", after.as_secs()),
            Self::Unavailable { status, .. } => write!(f, "HTTP {status}: try again later"),
            Self::Status { status, message } if message.is_empty() => write!(f, "HTTP {status}"),
            Self::Status { status, message } => write!(f, "HTTP {status}: {message}"),
            Self::Tls(e) => write!(f, "TLS error: {e}"),
            Self::Network(e) => write!(f, "network error: {e}"),
            Self::BadResponse(e) => write!(f, "unexpected response: {e}"),
        }
    }
}

#[derive(Deserialize)]
struct EnrolReply {
    host_id: String,
    credential: String,
    #[serde(default)]
    rotate_after_days: Option<u32>,
}

#[derive(Deserialize)]
struct RotateReply {
    credential: String,
    #[serde(default)]
    previous_valid_until: Option<String>,
}

/// Talks to the enrol and rotate routes of one endpoint.
#[derive(Debug)]
pub struct Client {
    endpoint: String,
    agent: ureq::Agent,
}

impl Client {
    /// `endpoint` is the ingest base URL; `https://` only outside tests.
    pub fn new(endpoint: &str) -> Result<Self, String> {
        let endpoint = endpoint.trim_end_matches('/').to_owned();
        let agent = http_agent(&endpoint)?;
        Ok(Self { endpoint, agent })
    }

    /// Swap an enrolment token for a host credential.
    pub fn enrol(&self, token: &Secret, request: &EnrolRequest) -> Result<Enrolled, ApiError> {
        let body = serde_json::to_vec(request).map_err(|e| ApiError::BadResponse(e.to_string()))?;
        let text = self.post(ENROL_PATH, token, Some(&body))?;
        let reply: EnrolReply = serde_json::from_str(&text)
            .map_err(|_| ApiError::BadResponse("not the enrolment JSON".into()))?;
        if !is_host_id(&reply.host_id) {
            return Err(ApiError::BadResponse(
                "host_id is missing or malformed".into(),
            ));
        }
        Ok(Enrolled {
            host_id: reply.host_id,
            credential: checked_credential(reply.credential)?,
            rotate_after_days: rotate_after_days(reply.rotate_after_days),
        })
    }

    /// Swap the current host credential for a new one. The old one stays valid for an overlap
    /// window (24 h) so requests already sent with it still land.
    pub fn rotate(&self, current: &Secret) -> Result<Rotated, ApiError> {
        let text = self.post(ROTATE_PATH, current, None)?;
        let reply: RotateReply = serde_json::from_str(&text)
            .map_err(|_| ApiError::BadResponse("not the rotation JSON".into()))?;
        Ok(Rotated {
            credential: checked_credential(reply.credential)?,
            previous_valid_until: reply.previous_valid_until.map(|v| clean_text(&v, 64)),
        })
    }

    fn post(&self, path: &str, bearer: &Secret, json: Option<&[u8]>) -> Result<String, ApiError> {
        let request = self
            .agent
            .post(format!("{}{path}", self.endpoint))
            .header("Authorization", &format!("Bearer {}", bearer.expose()))
            .header("Accept", "application/json");
        let result = match json {
            Some(body) => request
                .header("Content-Type", "application/json")
                .send(body),
            None => request.send_empty(),
        };
        // ureq errors never include request headers, so the secret cannot leak into them.
        let mut resp = result.map_err(transport_error)?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_retry_after);
        let text = resp
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .unwrap_or_default();
        match status {
            200..=299 => Ok(text),
            401 => Err(ApiError::Unauthorized),
            408 | 425 | 429 | 500..=599 => Err(ApiError::Unavailable {
                status,
                retry_after,
            }),
            _ => Err(ApiError::Status {
                status,
                message: error_message(&text),
            }),
        }
    }
}

fn transport_error(e: ureq::Error) -> ApiError {
    let tls = match &e {
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => true,
        ureq::Error::Io(io) => io
            .get_ref()
            .is_some_and(|inner| inner.is::<rustls::Error>()),
        _ => false,
    };
    if tls {
        ApiError::Tls(e.to_string())
    } else {
        ApiError::Network(e.to_string())
    }
}

fn checked_credential(value: String) -> Result<Secret, ApiError> {
    if is_host_credential(&value) {
        Ok(Secret::new(value))
    } else {
        Err(ApiError::BadResponse(
            "credential is missing or malformed".into(),
        ))
    }
}

fn rotate_after_days(days: Option<u32>) -> u32 {
    match days {
        None | Some(0) => DEFAULT_ROTATE_AFTER_DAYS,
        Some(d) => d.min(MAX_ROTATE_AFTER_DAYS),
    }
}

/// 1 to 64 of `[A-Za-z0-9_-]`.
fn is_host_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The `error` text of a JSON error body, printable and short.
fn error_message(body: &str) -> String {
    let error = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .unwrap_or_default();
    clean_text(&error, 200)
}

fn clean_text(text: &str, max: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// The non-secret enrolment facts kept in `enrolment.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolmentInfo {
    pub host_id: String,
    /// The endpoint enrolled with.
    pub endpoint: String,
    /// RFC 3339 UTC.
    pub enrolled_at: String,
    /// RFC 3339 UTC; the rotation clock starts here.
    pub credential_issued_at: String,
    pub rotate_after_days: u32,
}

impl EnrolmentInfo {
    pub fn new(host_id: &str, endpoint: &str, rotate_after_days: u32, now_s: u64) -> Self {
        let now = rfc3339(now_s);
        Self {
            host_id: host_id.to_owned(),
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            enrolled_at: now.clone(),
            credential_issued_at: now,
            rotate_after_days,
        }
    }

    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(ENROLMENT_FILE)
    }

    /// `Ok(None)` when the host has not been enrolled.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, String> {
        let path = Self::path(state_dir);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn save(&self, state_dir: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        write_private(state_dir, ENROLMENT_FILE, &bytes)
            .map_err(|e| format!("cannot write {}: {e}", Self::path(state_dir).display()))
    }

    /// Unix seconds when the credential was issued, if the stored time parses.
    pub fn issued_at_s(&self) -> Option<u64> {
        time::parse_timestamp_us(&self.credential_issued_at).map(|us| us / 1_000_000)
    }

    /// Unix seconds when the credential is due for rotation.
    pub fn rotate_due_s(&self) -> Option<u64> {
        let days = u64::from(rotate_after_days(Some(self.rotate_after_days)));
        Some(self.issued_at_s()? + days * DAY_S)
    }
}

/// Unix seconds now.
pub fn now_s() -> u64 {
    time::now_us() / 1_000_000
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
pub fn rfc3339(s: u64) -> String {
    let full = time::format_rfc3339_us(s * 1_000_000);
    // Drop the always-zero microseconds.
    format!("{}Z", &full[..19])
}

/// When to check and how to retry.
#[derive(Debug, Clone)]
pub struct RotationOptions {
    /// How often to compare the credential's age with `rotate_after_days`.
    pub check_interval: Duration,
    pub retry_base: Duration,
    pub retry_cap: Duration,
}

impl Default for RotationOptions {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(3600),
            retry_base: Duration::from_secs(60),
            retry_cap: Duration::from_secs(3600),
        }
    }
}

/// Background rotation: when the credential is `rotate_after_days` old, swap it for a new one
/// and store that atomically. The shipper reads the store before every request, so it moves
/// to the new credential with its next request; requests already sent with the old one are
/// still accepted during the server's overlap window.
#[derive(Debug)]
pub struct Rotator {
    client: Client,
    store: Arc<dyn CredentialStore>,
    state_dir: PathBuf,
    opts: RotationOptions,
    backoff: Backoff,
}

impl Rotator {
    pub fn new(
        endpoint: &str,
        store: Arc<dyn CredentialStore>,
        state_dir: &Path,
        opts: RotationOptions,
    ) -> Result<Self, String> {
        Ok(Self {
            client: Client::new(endpoint)?,
            store,
            state_dir: state_dir.to_owned(),
            backoff: Backoff::new(opts.retry_base, opts.retry_cap),
            opts,
        })
    }

    pub fn run(mut self, stop: Stop) {
        while !stop.is_stopped() {
            let wait = self.check(now_s());
            if stop.wait(wait) {
                break;
            }
        }
    }

    /// Rotate if due. Returns how long to wait before the next check.
    pub fn check(&mut self, now: u64) -> Duration {
        let info = match EnrolmentInfo::load(&self.state_dir) {
            Ok(Some(info)) => info,
            // Not enrolled (or enrolled by hand without enrolment.json): nothing to rotate.
            Ok(None) => return self.opts.check_interval,
            Err(e) => {
                log::error!("rotation: {e}");
                return self.opts.check_interval;
            }
        };
        let Some(due) = info.rotate_due_s() else {
            log::error!("rotation: {ENROLMENT_FILE} has an unreadable credential_issued_at");
            return self.opts.check_interval;
        };
        if now < due {
            return self.opts.check_interval.min(Duration::from_secs(due - now));
        }
        let current = match self.store.credential() {
            Ok(Some(c)) => c,
            Ok(None) => return self.opts.check_interval,
            Err(e) => {
                log::error!("rotation: credential: {e}");
                return self.retry_delay(None);
            }
        };
        match self.client.rotate(&current) {
            Ok(rotated) => {
                if let Err(e) = self.store.store(&rotated.credential) {
                    // The old credential still works during the overlap window; try again.
                    log::error!("rotation: cannot store the new credential: {e}");
                    return self.retry_delay(None);
                }
                let mut info = info;
                info.credential_issued_at = rfc3339(now);
                if let Err(e) = info.save(&self.state_dir) {
                    log::error!("rotation: {e}");
                }
                log::info!(
                    "host credential rotated; the previous one is accepted until {}",
                    rotated.previous_valid_until.as_deref().unwrap_or("-")
                );
                self.backoff.reset();
                self.opts.check_interval
            }
            Err(ApiError::Unauthorized) => {
                log::error!(
                    "rotation: the server did not accept the current credential (HTTP 401); \
                     if this host was revoked, enrol it again"
                );
                self.retry_delay(None)
            }
            Err(ApiError::Unavailable { retry_after, .. }) => {
                log::warn!("rotation: server busy; will retry");
                self.retry_delay(retry_after)
            }
            Err(e) => {
                log::warn!("rotation: {e}");
                self.retry_delay(None)
            }
        }
    }

    fn retry_delay(&mut self, server: Option<Duration>) -> Duration {
        let delay = match server {
            Some(after) => self.backoff.retry_after(after),
            None => self.backoff.next_delay(),
        };
        // Never spin: at least half the base delay even with full jitter.
        delay.max(self.opts.retry_base / 2)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    use serde_json::Value;

    use super::*;
    use crate::buffer::tests::TempDir;
    use crate::credential::{CredentialProvider, FileCredential};
    use crate::shipper::test_server::{Reply, Server};

    pub(crate) const TOKEN: &str = "wge_0123456789az_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO-_";
    pub(crate) const CRED_A: &str = "wgh_h0st00000001_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    pub(crate) const CRED_B: &str = "wgh_h0st00000001_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    fn request() -> EnrolRequest {
        EnrolRequest {
            hostname: "web-01".into(),
            os: "linux".into(),
            os_version: "Ubuntu 24.04.1 LTS".into(),
            arch: "x86_64".into(),
            machine_id: "4c4c4544004d3510804bc4c04f4e4a32".into(),
            agent_version: "0.1.0".into(),
        }
    }

    fn json_reply(status: u16, body: &str) -> Reply {
        Some((status, vec![], body.to_owned()))
    }

    fn token() -> Secret {
        Secret::new(TOKEN.into())
    }

    #[test]
    fn enrol_sends_the_contract_request_and_reads_the_reply() {
        let server = Server::start(vec![json_reply(
            200,
            &format!(
                r#"{{"host_id":"h0st00000001","credential":"{CRED_A}","rotate_after_days":14}}"#
            ),
        )]);
        let client = Client::new(&format!("{}/", server.url)).expect("client");
        let enrolled = client.enrol(&token(), &request()).expect("enrol");
        assert_eq!(enrolled.host_id, "h0st00000001");
        assert_eq!(enrolled.credential.expose(), CRED_A);
        assert_eq!(enrolled.rotate_after_days, 14);
        assert!(!format!("{enrolled:?}").contains("AAAA"));

        let reqs = server.requests();
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        assert_eq!(r.path, "/v1/agent/enrol");
        assert_eq!(r.headers["authorization"], format!("Bearer {TOKEN}"));
        assert_eq!(r.headers["content-type"], "application/json");
        assert!(!r.headers.contains_key("content-encoding"));
        let body: Value = serde_json::from_str(&r.body).expect("json");
        assert_eq!(
            body,
            serde_json::json!({
                "hostname": "web-01", "os": "linux", "os_version": "Ubuntu 24.04.1 LTS",
                "arch": "x86_64", "machine_id": "4c4c4544004d3510804bc4c04f4e4a32",
                "agent_version": "0.1.0"
            })
        );
    }

    #[test]
    fn enrol_defaults_and_rejects_malformed_replies() {
        let ok = format!(r#"{{"host_id":"h0st00000001","credential":"{CRED_A}"}}"#);
        let server = Server::start(vec![
            json_reply(200, &ok),
            json_reply(
                200,
                r#"{"host_id":"h0st00000001","credential":"wgh_short"}"#,
            ),
            json_reply(
                200,
                &format!(r#"{{"host_id":"../x","credential":"{CRED_A}"}}"#),
            ),
            json_reply(200, "<html>proxy login</html>"),
            json_reply(
                200,
                &format!(
                    r#"{{"host_id":"h0st00000001","credential":"{CRED_A}","rotate_after_days":0}}"#
                ),
            ),
        ]);
        let client = Client::new(&server.url).expect("client");
        let first = client.enrol(&token(), &request()).expect("ok");
        assert_eq!(first.rotate_after_days, DEFAULT_ROTATE_AFTER_DAYS);
        for _ in 0..3 {
            let err = client.enrol(&token(), &request()).expect_err("malformed");
            assert!(matches!(err, ApiError::BadResponse(_)), "{err:?}");
            assert!(!err.to_string().contains("wgh_"));
        }
        let zero = client.enrol(&token(), &request()).expect("ok");
        assert_eq!(zero.rotate_after_days, DEFAULT_ROTATE_AFTER_DAYS);
    }

    #[test]
    fn enrol_status_codes() {
        let server = Server::start(vec![
            json_reply(401, r#"{"error":"Missing or invalid credential."}"#),
            Some((429, vec![("Retry-After".into(), "30".into())], "{}".into())),
            json_reply(503, ""),
            json_reply(400, "{\"error\":\"hostname is required\\u0007\"}"),
            json_reply(404, "not found"),
        ]);
        let client = Client::new(&server.url).expect("client");
        let call = || client.enrol(&token(), &request()).expect_err("fails");
        assert_eq!(call(), ApiError::Unauthorized);
        assert_eq!(
            call(),
            ApiError::Unavailable {
                status: 429,
                retry_after: Some(Duration::from_secs(30))
            }
        );
        assert_eq!(
            call(),
            ApiError::Unavailable {
                status: 503,
                retry_after: None
            }
        );
        assert_eq!(
            call(),
            ApiError::Status {
                status: 400,
                message: "hostname is required".into()
            }
        );
        assert_eq!(
            call(),
            ApiError::Status {
                status: 404,
                message: String::new()
            }
        );
    }

    #[test]
    fn network_and_tls_errors_are_told_apart() {
        // Nothing listens on a port that was just released.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port();
        let client = Client::new(&format!("http://127.0.0.1:{port}")).expect("client");
        let err = client.enrol(&token(), &request()).expect_err("refused");
        assert!(matches!(err, ApiError::Network(_)), "{err:?}");

        // https:// to a server that answers in plain HTTP: the TLS handshake fails.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for mut stream in listener.incoming().flatten() {
                // Read the ClientHello before answering and wait for the client to hang up:
                // closing with unread data makes Windows reset the connection instead.
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
            }
        });
        let client = Client::new(&format!("https://{addr}")).expect("client");
        let err = client.enrol(&token(), &request()).expect_err("not TLS");
        assert!(matches!(err, ApiError::Tls(_)), "{err:?}");
    }

    #[test]
    fn untrusted_certificates_are_rejected() {
        let server = tls_server::start();
        let client = Client::new(&server).expect("client");
        let err = client.enrol(&token(), &request()).expect_err("self-signed");
        assert!(matches!(err, ApiError::Tls(_)), "{err:?}");
    }

    #[test]
    fn rotate_posts_the_current_credential_with_no_body() {
        let server = Server::start(vec![
            json_reply(
                200,
                &format!(
                    r#"{{"credential":"{CRED_B}","previous_valid_until":"2026-10-22T08:00:00Z"}}"#
                ),
            ),
            json_reply(401, r#"{"error":"Missing or invalid credential."}"#),
        ]);
        let client = Client::new(&server.url).expect("client");
        let rotated = client.rotate(&Secret::new(CRED_A.into())).expect("rotate");
        assert_eq!(rotated.credential.expose(), CRED_B);
        assert_eq!(
            rotated.previous_valid_until.as_deref(),
            Some("2026-10-22T08:00:00Z")
        );
        assert_eq!(
            client.rotate(&Secret::new(CRED_A.into())).expect_err("401"),
            ApiError::Unauthorized
        );
        let reqs = server.requests();
        assert_eq!(reqs[0].path, "/v1/agent/rotate");
        assert_eq!(reqs[0].bearer(), CRED_A);
        assert_eq!(reqs[0].body, "");
    }

    #[test]
    fn enrolment_info_round_trip_and_due_date() {
        let dir = TempDir::new("enrol-info");
        fs::create_dir_all(&dir.0).expect("mkdir");
        assert_eq!(EnrolmentInfo::load(&dir.0).expect("load"), None);
        let info = EnrolmentInfo::new(
            "h0st00000001",
            "https://ingest.example.com/",
            30,
            1_790_000_000,
        );
        info.save(&dir.0).expect("save");
        let loaded = EnrolmentInfo::load(&dir.0).expect("load").expect("some");
        assert_eq!(loaded, info);
        assert_eq!(loaded.endpoint, "https://ingest.example.com");
        assert_eq!(loaded.issued_at_s(), Some(1_790_000_000));
        assert_eq!(loaded.rotate_due_s(), Some(1_790_000_000 + 30 * DAY_S));
        let text = fs::read_to_string(EnrolmentInfo::path(&dir.0)).expect("read");
        assert!(!text.contains("wgh_") && !text.contains("credential\":"));
        fs::write(EnrolmentInfo::path(&dir.0), "{\"host_id\":1}").expect("write");
        assert!(EnrolmentInfo::load(&dir.0).is_err());
    }

    fn enrolled_state(name: &str, issued_days_ago: u64) -> (TempDir, Arc<FileCredential>) {
        let dir = TempDir::new(name);
        fs::create_dir_all(&dir.0).expect("mkdir");
        let store = Arc::new(FileCredential {
            path: dir.0.join("credential"),
        });
        store.store(&Secret::new(CRED_A.into())).expect("store");
        EnrolmentInfo::new(
            "h0st00000001",
            "https://ingest.example.com",
            30,
            now_s() - issued_days_ago * DAY_S,
        )
        .save(&dir.0)
        .expect("save");
        (dir, store)
    }

    fn quick() -> RotationOptions {
        RotationOptions {
            check_interval: Duration::from_millis(100),
            retry_base: Duration::from_millis(100),
            retry_cap: Duration::from_millis(400),
        }
    }

    fn stored(store: &FileCredential) -> String {
        store
            .credential()
            .expect("read")
            .expect("some")
            .expose()
            .to_owned()
    }

    #[test]
    fn rotator_waits_until_due_then_rotates_once() {
        let rotations = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&rotations);
        let server = Server::with_handler(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            json_reply(200, &format!(r#"{{"credential":"{CRED_B}"}}"#))
        });
        let (dir, store) = enrolled_state("rotate-due", 10);
        let mut rotator = Rotator::new(
            &server.url,
            store.clone(),
            &dir.0,
            RotationOptions::default(),
        )
        .expect("rotator");
        // Not due: the next check is no later than the check interval.
        assert_eq!(rotator.check(now_s()), Duration::from_secs(3600));
        assert_eq!(rotations.load(Ordering::SeqCst), 0);
        // 30 days after issue: due.
        let due = now_s() + 20 * DAY_S;
        assert_eq!(rotator.check(due), Duration::from_secs(3600));
        assert_eq!(rotations.load(Ordering::SeqCst), 1);
        assert_eq!(stored(&store), CRED_B);
        let info = EnrolmentInfo::load(&dir.0).expect("load").expect("some");
        assert_eq!(info.issued_at_s(), Some(due));
        // Freshly rotated: not due again.
        rotator.check(due + 60);
        assert_eq!(rotations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rotator_keeps_the_credential_on_401_and_bad_replies_and_backs_off() {
        let server = Server::start(vec![
            json_reply(401, r#"{"error":"Missing or invalid credential."}"#),
            json_reply(200, r#"{"credential":"not-a-credential"}"#),
            Some((503, vec![("Retry-After".into(), "2".into())], String::new())),
        ]);
        let (dir, store) = enrolled_state("rotate-401", 31);
        let mut rotator =
            Rotator::new(&server.url, store.clone(), &dir.0, quick()).expect("rotator");
        let first = rotator.check(now_s());
        assert!(first >= Duration::from_millis(50), "{first:?}");
        assert_eq!(stored(&store), CRED_A);
        rotator.check(now_s());
        assert_eq!(stored(&store), CRED_A);
        let after = rotator.check(now_s());
        assert!(after >= Duration::from_secs(2), "{after:?}");
        assert_eq!(stored(&store), CRED_A);
        assert_eq!(server.requests().len(), 3);
    }

    /// The acceptance test for rotation: an agent ships a continuous stream of events while its
    /// credential rotates. Every event arrives exactly once, no request is refused, and once
    /// the new credential is stored the old one is never used again.
    #[test]
    fn rotation_during_continuous_shipping_loses_nothing() {
        use std::collections::BTreeMap;

        use agent_collectors::{Batch, Checkpoint, Collector, CollectorError, EventTemplate};
        use agent_config::AgentConfig;

        use crate::shipper::ShipperOptions;
        use crate::{Agent, Stop};

        const TOTAL: u32 = 600;

        /// Emits `TOTAL` numbered events, two every 10 ms (about 3 s).
        struct Counter {
            template: EventTemplate,
            next: u32,
        }

        impl Collector for Counter {
            fn rule_id(&self) -> &str {
                "counter"
            }

            fn start(&mut self, _: Option<Checkpoint>) -> Result<(), CollectorError> {
                Ok(())
            }

            fn poll(&mut self, _: usize, wait: Duration) -> Result<Batch, CollectorError> {
                std::thread::sleep(Duration::from_millis(10).min(wait));
                let end = (self.next + 2).min(TOTAL);
                let events = (self.next..end)
                    .map(|i| {
                        self.template
                            .event(1, Some(format!("event-{i}")), Default::default())
                    })
                    .collect();
                self.next = end;
                Ok(Batch {
                    events,
                    checkpoint: None,
                })
            }
        }

        let valid = Arc::new(Mutex::new(vec![CRED_A.to_owned()]));
        let refused = Arc::new(AtomicU32::new(0));
        let server = {
            let (valid, refused) = (Arc::clone(&valid), Arc::clone(&refused));
            Server::with_handler(move |req| {
                let mut valid = valid.lock().expect("lock");
                if !valid.iter().any(|v| v == req.bearer()) {
                    refused.fetch_add(1, Ordering::SeqCst);
                    return json_reply(401, r#"{"error":"Missing or invalid credential."}"#);
                }
                if req.path == ROTATE_PATH {
                    // The old credential stays valid (the server's 24 h overlap).
                    valid.push(CRED_B.to_owned());
                    return json_reply(
                        200,
                        &format!(
                            r#"{{"credential":"{CRED_B}","previous_valid_until":"2026-10-22T08:00:00Z"}}"#
                        ),
                    );
                }
                json_reply(
                    200,
                    &format!(
                        r#"{{"accepted":{},"skipped":0,"errors":[]}}"#,
                        req.lines.len()
                    ),
                )
            })
        };

        // Due for rotation 1 to 2 s from now, in the middle of the stream.
        let dir = TempDir::new("rotate-continuous");
        fs::create_dir_all(&dir.0).expect("mkdir");
        let store = Arc::new(FileCredential {
            path: dir.0.join("credential"),
        });
        store.store(&Secret::new(CRED_A.into())).expect("store");
        EnrolmentInfo::new("h0st00000001", &server.url, 30, now_s() - 30 * DAY_S + 2)
            .save(&dir.0)
            .expect("save");
        let config = AgentConfig::parse(&format!(
            "endpoint = \"{}\"\nstate_dir = {:?}\n",
            server.url, dir.0
        ))
        .expect("config");
        let mut opts = ShipperOptions::new(&server.url);
        opts.flush_interval = Duration::from_millis(20);
        opts.limits.max_records = 25;
        let rotation = quick();
        let agent = Agent::new(config, store.clone())
            .expect("agent")
            .with_collector(Box::new(Counter {
                template: EventTemplate::new("counter", "file", None, &BTreeMap::new()),
                next: 0,
            }))
            .with_shipper_options(opts)
            .with_rotation(store.clone(), rotation);
        let stop = Stop::new();
        let runner = {
            let stop = stop.clone();
            std::thread::spawn(move || agent.run(stop))
        };

        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let received = || -> Vec<String> {
            server
                .requests()
                .iter()
                .filter(|r| r.path == "/v1/agent/events")
                .flat_map(|r| r.lines.clone())
                .filter_map(|l| {
                    let v: Value = serde_json::from_str(&l).expect("json");
                    v["body"].as_str().map(str::to_owned)
                })
                .collect()
        };
        while received().len() < TOTAL as usize && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        stop.stop();
        runner.join().expect("join").expect("run");

        let mut bodies = received();
        bodies.sort_by_key(|b| b["event-".len()..].parse::<u32>().expect("n"));
        let expected: Vec<String> = (0..TOTAL).map(|i| format!("event-{i}")).collect();
        assert_eq!(bodies, expected, "every event exactly once");
        assert_eq!(refused.load(Ordering::SeqCst), 0, "no request was refused");

        let reqs = server.requests();
        let rotates = reqs.iter().filter(|r| r.path == ROTATE_PATH).count();
        assert_eq!(rotates, 1);
        let creds: Vec<&str> = reqs
            .iter()
            .filter(|r| r.path == "/v1/agent/events")
            .map(|r| r.bearer())
            .collect();
        let first_b = creds
            .iter()
            .position(|c| *c == CRED_B)
            .expect("switched to B");
        assert!(first_b > 0, "shipped with A before the rotation");
        assert!(
            creds[first_b..].iter().all(|c| *c == CRED_B),
            "the old credential is not used after the new one is stored"
        );
        assert_eq!(stored(&store), CRED_B);
    }

    /// A TLS server with a self-signed certificate for `localhost`, which no OS trusts.
    mod tls_server {
        use std::io::Read;
        use std::net::TcpListener;
        use std::sync::Arc;

        pub fn start() -> String {
            let cert =
                rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("cert");
            let key =
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .expect("server config");
            let config = Arc::new(config);
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = listener.local_addr().expect("addr").port();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let Ok(mut conn) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                        continue;
                    };
                    let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                    let mut buf = [0u8; 1024];
                    let _ = tls.read(&mut buf);
                }
            });
            format!("https://localhost:{port}")
        }
    }
}
