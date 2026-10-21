//! `format = "lastlog"`: a summary of `/var/log/lastlog` (every user's last login) instead of
//! its raw records.
//!
//! The file is checked every [`CHECK_INTERVAL`]; when its modification time changed since the
//! last summary, and at least [`MIN_INTERVAL`] has passed, one event lists every user with a
//! recorded login (uid, user name from `/etc/passwd`, time, terminal, host). The checkpoint
//! is the modification time summarised, so a restart does not repeat an unchanged summary.
//! lastlog is sparse and indexed by uid, so only the first [`MAX_READ_BYTES`] are read.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use agent_config::paths;
use serde_json::{Map, Value, json};

use crate::utmp::{self, LastLogin};
use crate::{Batch, Checkpoint, Collector, CollectorEnv, CollectorError, EventTemplate, time};

/// How often the file's modification time is checked.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(60);
/// Least time between two summaries.
pub const MIN_INTERVAL: Duration = Duration::from_secs(3600);
/// Most of the file read: uids up to about 57,000.
pub const MAX_READ_BYTES: u64 = 16 * 1024 * 1024;
/// Most users listed in one summary.
pub const MAX_USERS: usize = 1000;
const PASSWD: &str = "/etc/passwd";
const MAX_PASSWD_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct Lastlog {
    template: EventTemplate,
    path: PathBuf,
    env: CollectorEnv,
    passwd: PathBuf,
    layout: utmp::Layout,
    /// Modification time (microseconds) of the last summary.
    summarised_mtime: Option<u64>,
    last_summary: Option<Instant>,
    next_check: Instant,
    check_interval: Duration,
    min_interval: Duration,
}

impl Lastlog {
    pub fn new(template: EventTemplate, path: PathBuf, env: CollectorEnv) -> Self {
        Self {
            template,
            path,
            env,
            passwd: PathBuf::from(PASSWD),
            layout: utmp::Layout::NATIVE,
            summarised_mtime: None,
            last_summary: None,
            next_check: Instant::now(),
            check_interval: CHECK_INTERVAL,
            min_interval: MIN_INTERVAL,
        }
    }

    /// Read user names from `passwd` instead of `/etc/passwd` (tests, fixtures).
    pub fn with_passwd(mut self, passwd: PathBuf) -> Self {
        self.passwd = passwd;
        self
    }

    /// Read records in `layout` instead of this architecture's (tests, fixtures).
    pub fn with_layout(mut self, layout: utmp::Layout) -> Self {
        self.layout = layout;
        self
    }

    fn mtime_us(path: &Path) -> Option<u64> {
        let modified = std::fs::metadata(path).ok()?.modified().ok()?;
        u64::try_from(modified.duration_since(UNIX_EPOCH).ok()?.as_micros()).ok()
    }

    /// The summary event if the file changed and one is due.
    fn check(&mut self) -> Result<Option<crate::RawEvent>, CollectorError> {
        let root = paths::glob_root(&self.path);
        let canonical = match paths::check_file(&self.path, &root, &self.env.protected) {
            Ok(c) => c,
            // Not there (yet): nothing to summarise.
            Err(_)
                if matches!(self.path.symlink_metadata(),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(CollectorError(e)),
        };
        let Some(mtime) = Self::mtime_us(&canonical) else {
            return Ok(None);
        };
        let due = self
            .last_summary
            .is_none_or(|t| t.elapsed() >= self.min_interval);
        if self.summarised_mtime == Some(mtime) || !due {
            return Ok(None);
        }
        let mut data = Vec::new();
        File::open(&canonical)
            .and_then(|f| f.take(MAX_READ_BYTES).read_to_end(&mut data))
            .map_err(|e| CollectorError(format!("{}: {e}", self.path.display())))?;
        let passwd = crate::read_bounded(&self.passwd, MAX_PASSWD_BYTES).unwrap_or_default();
        let fields = summary(
            &utmp::decode_lastlog(&data, self.layout),
            &utmp::passwd_names(&passwd),
        );
        self.summarised_mtime = Some(mtime);
        self.last_summary = Some(Instant::now());
        let mut ev = self.template.event(time::now_us(), None, fields);
        ev.attrs.insert(
            "path".into(),
            Value::from(self.path.to_string_lossy().as_ref()),
        );
        Ok(Some(ev))
    }
}

/// The summary `fields`: `{"log": "lastlog", "users_total": n, "users": [...]}`, at most
/// [`MAX_USERS`] users, most recent first.
pub fn summary(
    logins: &[LastLogin],
    names: &std::collections::HashMap<u32, String>,
) -> Map<String, Value> {
    let mut sorted: Vec<&LastLogin> = logins.iter().collect();
    sorted.sort_by(|a, b| b.time_us.cmp(&a.time_us).then(a.uid.cmp(&b.uid)));
    let users: Vec<Value> = sorted
        .iter()
        .take(MAX_USERS)
        .map(|l| {
            let mut user = Map::new();
            user.insert("uid".into(), Value::from(l.uid));
            if let Some(name) = names.get(&l.uid) {
                user.insert("user".into(), Value::from(name.as_str()));
            }
            user.insert(
                "time".into(),
                Value::from(time::format_rfc3339_us(l.time_us)),
            );
            if !l.line.is_empty() {
                user.insert("line".into(), Value::from(l.line.as_str()));
            }
            if !l.host.is_empty() {
                user.insert("host".into(), Value::from(l.host.as_str()));
            }
            Value::Object(user)
        })
        .collect();
    let value = json!({
        "log": "lastlog",
        "users_total": logins.len(),
        "truncated": logins.len() > MAX_USERS,
        "users": users,
    });
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

impl Collector for Lastlog {
    fn rule_id(&self) -> &str {
        &self.template.rule_id
    }

    fn start(&mut self, checkpoint: Option<Checkpoint>) -> Result<(), CollectorError> {
        if let Some(Checkpoint::Lastlog { mtime_us }) = checkpoint {
            self.summarised_mtime = Some(mtime_us);
        }
        self.next_check = Instant::now();
        Ok(())
    }

    fn poll(&mut self, _max_events: usize, wait: Duration) -> Result<Batch, CollectorError> {
        let now = Instant::now();
        if now < self.next_check {
            thread::sleep(wait.min(self.next_check - now));
            return Ok(Batch::default());
        }
        self.next_check = now + self.check_interval;
        let event = self.check()?;
        Ok(Batch {
            checkpoint: self
                .summarised_mtime
                .map(|mtime_us| Checkpoint::Lastlog { mtime_us }),
            events: event.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn record(time: i32, line: &str, host: &str) -> Vec<u8> {
        let mut rec = vec![0u8; utmp::Layout::X86_64.lastlog_size()];
        rec[0..4].copy_from_slice(&time.to_le_bytes());
        rec[4..4 + line.len()].copy_from_slice(line.as_bytes());
        rec[36..36 + host.len()].copy_from_slice(host.as_bytes());
        rec
    }

    #[test]
    fn summarises_when_changed_and_due() {
        let dir = Dir(std::env::temp_dir().join(format!("wt-lastlog-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        let path = dir.0.join("lastlog");
        let mut data = record(0, "", "");
        data.extend(record(1_792_569_600, "pts/0", "192.0.2.10"));
        std::fs::write(&path, &data).expect("write");
        let passwd = dir.0.join("passwd");
        std::fs::write(
            &passwd,
            "root:x:0:0::/root:/bin/sh\ndaemon:x:1:1::/:/bin/false\n",
        )
        .expect("write");

        let template = EventTemplate::new("ll", "linux.login", None, &Default::default());
        let mut c = Lastlog::new(template, path.clone(), CollectorEnv::default())
            .with_layout(utmp::Layout::X86_64);
        c.passwd = passwd;
        c.check_interval = Duration::ZERO;
        c.start(None).expect("start");
        let batch = c.poll(10, Duration::ZERO).expect("poll");
        assert_eq!(batch.events.len(), 1);
        let fields = Value::Object(batch.events[0].fields.clone());
        assert_eq!(
            fields,
            json!({"log": "lastlog", "users_total": 1, "truncated": false, "users": [
                {"uid": 1, "user": "daemon", "time": "2026-10-21T08:00:00.000000Z",
                 "line": "pts/0", "host": "192.0.2.10"}]})
        );
        let Some(Checkpoint::Lastlog { mtime_us }) = batch.checkpoint else {
            panic!("checkpoint");
        };
        // Unchanged: nothing more, also after a restart from the checkpoint.
        assert!(c.poll(10, Duration::ZERO).expect("poll").events.is_empty());
        c.start(Some(Checkpoint::Lastlog { mtime_us }))
            .expect("start");
        assert!(c.poll(10, Duration::ZERO).expect("poll").events.is_empty());
        // Changed, but within MIN_INTERVAL of the last summary.
        c.summarised_mtime = Some(1);
        c.last_summary = Some(Instant::now());
        assert!(c.poll(10, Duration::ZERO).expect("poll").events.is_empty());
        c.min_interval = Duration::ZERO;
        assert_eq!(c.poll(10, Duration::ZERO).expect("poll").events.len(), 1);
    }

    /// A file the agent cannot reach is an error (shown in the heartbeat), not "absent".
    #[cfg(unix)]
    #[test]
    fn unreadable_directory_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = Dir(std::env::temp_dir().join(format!("wt-lastlog-x-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        std::fs::write(dir.0.join("lastlog"), [0u8; 292]).expect("write");
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let template = EventTemplate::new("ll", "linux.login", None, &Default::default());
        let mut c = Lastlog::new(template, dir.0.join("lastlog"), CollectorEnv::default());
        c.start(None).expect("start");
        let result = c.poll(10, Duration::ZERO);
        // Root reads the directory anyway; then there is nothing to test.
        let privileged = std::fs::read_dir(&dir.0).is_ok();
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        if !privileged {
            assert!(result.is_err(), "{result:?}");
        }
    }

    #[test]
    fn missing_file_is_quiet_and_summary_is_bounded() {
        let template = EventTemplate::new("ll", "linux.login", None, &Default::default());
        let mut c = Lastlog::new(
            template,
            std::env::temp_dir().join("wt-no-such-lastlog"),
            CollectorEnv::default(),
        );
        c.start(None).expect("start");
        let batch = c.poll(10, Duration::ZERO).expect("poll");
        assert!(batch.events.is_empty() && batch.checkpoint.is_none());

        let logins: Vec<LastLogin> = (0..1500)
            .map(|uid| LastLogin {
                uid,
                time_us: u64::from(uid) * 1_000_000,
                line: String::new(),
                host: String::new(),
            })
            .collect();
        let s = summary(&logins, &Default::default());
        assert_eq!(s["users"].as_array().map(Vec::len), Some(MAX_USERS));
        assert_eq!(s["users"][0]["uid"], 1499);
        assert_eq!(s["truncated"], true);
        assert_eq!(s["users_total"], 1500);
    }
}
