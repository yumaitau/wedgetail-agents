//! A child process whose stdout lines are read on a background thread.
//!
//! Used for `journalctl` and `log`. The command is always an absolute path with an argument
//! vector, never a shell string.

use std::io::{BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::CollectorError;
use crate::lines::read_line_bounded;

/// Lines buffered between the reader thread and the collector. When full, the reader blocks
/// and the child blocks on its stdout pipe, so memory stays bounded.
const CHANNEL_LINES: usize = 128;
/// Longest JSON line accepted from a child. Longer lines cannot be parsed once cut, so they are
/// skipped; field values inside accepted lines are still cut to `MAX_LINE_BYTES`.
const MAX_JSON_LINE_BYTES: usize = 256 * 1024;

/// One line of child output, without the newline.
pub type Line = Vec<u8>;

#[derive(Debug)]
pub struct LineProcess {
    name: String,
    child: Child,
    rx: Receiver<Line>,
    stderr_tail: Arc<Mutex<String>>,
}

impl LineProcess {
    pub fn spawn(mut command: Command) -> Result<Self, CollectorError> {
        let name = command.get_program().to_string_lossy().into_owned();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| CollectorError(format!("cannot start {name}: {e}")))?;
        let (stdout, stderr) = match (child.stdout.take(), child.stderr.take()) {
            (Some(out), Some(err)) => (out, err),
            _ => return Err(CollectorError(format!("{name}: no stdout/stderr pipe"))),
        };

        let (tx, rx) = mpsc::sync_channel(CHANNEL_LINES);
        let reader_name = name.clone();
        thread::Builder::new()
            .name("collector-stdout".into())
            .spawn(move || {
                let mut reader = BufReader::with_capacity(64 * 1024, stdout);
                let mut buf = Vec::new();
                while let Ok(Some(truncated)) =
                    read_line_bounded(&mut reader, &mut buf, MAX_JSON_LINE_BYTES)
                {
                    if truncated {
                        log::warn!(
                            "{reader_name}: skipped an output line over {MAX_JSON_LINE_BYTES} bytes"
                        );
                        continue;
                    }
                    if tx.send(std::mem::take(&mut buf)).is_err() {
                        break;
                    }
                }
            })
            .map_err(|e| CollectorError(format!("cannot start reader thread: {e}")))?;

        // Keep the last stderr line so a failure (for example a permission error) reaches the
        // heartbeat.
        let stderr_tail = Arc::new(Mutex::new(String::new()));
        let tail = Arc::clone(&stderr_tail);
        thread::Builder::new()
            .name("collector-stderr".into())
            .spawn(move || {
                let mut reader = BufReader::new(stderr.take(1024 * 1024));
                let mut buf = Vec::new();
                while let Ok(Some(_)) = read_line_bounded(&mut reader, &mut buf, 512) {
                    let line = String::from_utf8_lossy(&buf).trim().to_owned();
                    if !line.is_empty()
                        && let Ok(mut t) = tail.lock()
                    {
                        *t = line;
                    }
                }
            })
            .map_err(|e| CollectorError(format!("cannot start reader thread: {e}")))?;

        Ok(Self {
            name,
            child,
            rx,
            stderr_tail,
        })
    }

    /// Next line, waiting up to `wait`. `Ok(None)` on timeout; an error once the process has
    /// exited and its output is drained.
    pub fn recv(&mut self, wait: Duration) -> Result<Option<Line>, CollectorError> {
        match self.rx.recv_timeout(wait) {
            Ok(line) => Ok(Some(line)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(self.exit_error()),
        }
    }

    /// Next line if one is ready.
    pub fn try_recv(&mut self) -> Result<Option<Line>, CollectorError> {
        match self.rx.try_recv() {
            Ok(line) => Ok(Some(line)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(self.exit_error()),
        }
    }

    fn exit_error(&mut self) -> CollectorError {
        let status = self
            .child
            .wait()
            .map(|s| s.to_string())
            .unwrap_or_else(|e| e.to_string());
        // Give the stderr thread a moment to record the final line.
        thread::sleep(Duration::from_millis(50));
        let tail = self
            .stderr_tail
            .lock()
            .map(|t| t.clone())
            .unwrap_or_default();
        if tail.is_empty() {
            CollectorError(format!("{} exited ({status})", self.name))
        } else {
            CollectorError(format!("{} exited ({status}): {tail}", self.name))
        }
    }
}

impl Drop for LineProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
