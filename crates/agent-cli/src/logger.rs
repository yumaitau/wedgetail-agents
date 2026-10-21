//! A small `log` backend: one line per record to stderr (systemd, launchd) or to a size-capped
//! file (Windows service, which has no console).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use agent_collectors::time;
use log::{Level, LevelFilter, Log, Metadata, Record};

const MAX_LOG_FILE_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug)]
enum Sink {
    Stderr,
    File { path: PathBuf, file: Option<File> },
}

#[derive(Debug)]
struct Logger {
    level: LevelFilter,
    sink: Mutex<Sink>,
}

/// Level from `WEDGETAIL_LOG` (`error`, `warn`, `info`, `debug`), default `info`.
fn level_from_env() -> LevelFilter {
    match std::env::var("WEDGETAIL_LOG")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    }
}

pub fn init_stderr() {
    init(Sink::Stderr);
}

/// Log to `path`, rotating to `<path>.1` at 10 MiB.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn init_file(path: PathBuf) {
    init(Sink::File { path, file: None });
}

fn init(sink: Sink) {
    let level = level_from_env();
    let logger = Box::leak(Box::new(Logger {
        level,
        sink: Mutex::new(sink),
    }));
    if log::set_logger(logger).is_ok() {
        log::set_max_level(level);
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // Third-party crates log at debug; keep their info chatter out of service logs.
        if record.level() > Level::Warn
            && !record.target().starts_with("agent")
            && self.level < LevelFilter::Debug
        {
            return;
        }
        let line = format!(
            "{} {:<5} {}\n",
            time::format_rfc3339_us(time::now_us()),
            record.level(),
            record.args()
        );
        let mut sink = self.sink.lock().unwrap_or_else(PoisonError::into_inner);
        match &mut *sink {
            Sink::Stderr => {
                let _ = std::io::stderr().write_all(line.as_bytes());
            }
            Sink::File { path, file } => {
                if file
                    .as_ref()
                    .and_then(|f| f.metadata().ok())
                    .is_some_and(|m| m.len() > MAX_LOG_FILE_BYTES)
                {
                    *file = None;
                    let _ = std::fs::rename(&*path, path.with_extension("log.1"));
                }
                if file.is_none() {
                    *file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&*path)
                        .ok();
                }
                if let Some(f) = file {
                    let _ = f.write_all(line.as_bytes());
                }
            }
        }
    }

    fn flush(&self) {}
}
