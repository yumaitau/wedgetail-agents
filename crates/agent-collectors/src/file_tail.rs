//! Tail text files named by paths and globs, following rotation (rename and create) and
//! truncation (copytruncate).
//!
//! Files are tracked by identity (device and inode on Unix, volume serial and file index on
//! Windows), not by name: a file renamed by rotation keeps being read from its open handle
//! until it is drained and no longer matched, while the new file at the old name is read from
//! the start. A file is read by at most one reader even when several paths or globs match it.
//!
//! Every matched file is checked against the policy in [`agent_config::paths`] (canonical
//! path inside the rule's root, outside the agent's own directories, a regular file) before
//! it is opened, and all `file` rules share one cap on open files ([`OpenFiles`]).
//!
//! Each file's checkpoint is its identity plus the byte offset after the last complete event
//! handed to the pipeline. A partial last line is not sent until its newline arrives, or until
//! the file is rotated away; a pending multiline event is checkpointed at its first line, so a
//! restart reads and joins it again.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use agent_config::multiline::{self, Assembled, Assembler, Multiline};
use agent_config::{MultilineConfig, Rule, StartAt, paths};
use serde_json::{Map, Value};

use crate::{Batch, Checkpoint, Collector, CollectorError, EventTemplate, FilePosition, time};

/// How often open files are checked for new data, rotation and truncation.
const CHECK_INTERVAL: Duration = Duration::from_millis(250);
/// How often globs are expanded again to find new files. Plain paths are checked on every
/// poll.
const GLOB_SCAN_INTERVAL: Duration = Duration::from_secs(5);
const READ_CHUNK: usize = 64 * 1024;
/// Identities of rotated-away files remembered so a rename into a matched name resumes
/// instead of re-reading.
const MAX_RETIRED: usize = 4096;
/// Most paths one glob expansion walks.
const MAX_GLOB_MATCHES: usize = 100_000;

type FileId = (u64, u64);

/// A cap on files open for tailing, shared by every `file` rule.
#[derive(Debug)]
pub struct OpenFiles {
    max: usize,
    used: AtomicUsize,
}

impl OpenFiles {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max,
            used: AtomicUsize::new(0),
        })
    }

    /// Take a slot, released when the returned guard drops. `None` at the cap.
    pub fn acquire(self: &Arc<Self>) -> Option<FileSlot> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.max).then_some(n + 1)
            })
            .ok()
            .map(|_| FileSlot(Arc::clone(self)))
    }

    pub fn in_use(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

/// One open-file slot.
#[derive(Debug)]
pub struct FileSlot(Arc<OpenFiles>);

impl Drop for FileSlot {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What collectors share across rules.
#[derive(Debug, Clone)]
pub struct CollectorEnv {
    /// Directories no rule may read (see [`agent_config::paths::protected_dirs`]).
    pub protected: Vec<PathBuf>,
    pub open_files: Arc<OpenFiles>,
}

impl CollectorEnv {
    pub fn new(protected: Vec<PathBuf>, max_open_files: usize) -> Self {
        Self {
            protected,
            open_files: OpenFiles::new(max_open_files),
        }
    }

    pub fn for_config(config: &agent_config::AgentConfig) -> Self {
        Self::new(config.protected_dirs(), config.max_open_files as usize)
    }
}

impl Default for CollectorEnv {
    fn default() -> Self {
        Self::new(Vec::new(), agent_config::DEFAULT_MAX_OPEN_FILES as usize)
    }
}

/// What a `file` rule reads.
#[derive(Debug, Clone)]
pub struct FileSpec {
    pub paths: Vec<PathBuf>,
    pub exclude: Vec<String>,
    pub start_at: StartAt,
    pub max_line_bytes: usize,
    pub multiline: Option<MultilineConfig>,
}

impl FileSpec {
    pub fn new(paths: Vec<PathBuf>, start_at: StartAt) -> Self {
        Self {
            paths,
            exclude: Vec::new(),
            start_at,
            max_line_bytes: agent_config::DEFAULT_MAX_LINE_BYTES as usize,
            multiline: None,
        }
    }

    pub fn from_rule(rule: &Rule) -> Self {
        Self {
            paths: rule.paths.clone(),
            exclude: rule.exclude.clone(),
            start_at: rule.start_at,
            max_line_bytes: rule.max_line_bytes(),
            multiline: rule.multiline.clone(),
        }
    }
}

#[derive(Debug)]
struct Watch {
    /// Set for a glob; plain paths are checked directly.
    glob: Option<String>,
    path: PathBuf,
    root: PathBuf,
}

#[derive(Debug)]
enum Exclude {
    /// Has a path separator: matched against the whole path.
    Path(glob::Pattern),
    /// Matched against the file name.
    Name(glob::Pattern),
}

fn match_options() -> glob::MatchOptions {
    glob::MatchOptions {
        case_sensitive: !cfg!(windows),
        require_literal_separator: true,
        require_literal_leading_dot: false,
    }
}

#[derive(Debug)]
pub struct FileTail {
    template: EventTemplate,
    start_at: StartAt,
    max_line_bytes: usize,
    watches: Vec<Watch>,
    exclude: Vec<Exclude>,
    multiline: Option<Multiline>,
    env: CollectorEnv,
    harvesters: Vec<Harvester>,
    retired: HashMap<FileId, u64>,
    saved: BTreeMap<PathBuf, FilePosition>,
    first_scan: bool,
    scan_interval: Duration,
    next_scan: Instant,
    flush_after: Duration,
    warned: HashSet<PathBuf>,
    chunk: Vec<u8>,
}

/// One line read from a file, with the offset it starts at.
#[derive(Debug)]
struct Line {
    bytes: Vec<u8>,
    truncated: bool,
    start: u64,
}

/// Reads one file (one identity).
#[derive(Debug)]
struct Harvester {
    /// The path it was last matched at: `attrs.path` and the checkpoint key.
    path: PathBuf,
    /// Matched by the latest scan.
    seen: bool,
    closed: bool,
    file: File,
    id: FileId,
    /// After the last complete line: the checkpoint offset without multiline.
    offset: u64,
    /// After the last byte consumed (`offset` plus the partial line, including any bytes
    /// discarded from an over-long line).
    read_pos: u64,
    partial: Vec<u8>,
    partial_truncated: bool,
    assembler: Option<Assembler>,
    last_line: Instant,
    _slot: FileSlot,
}

/// Identity and length of the file at `path`; `None` if there is none.
#[cfg(unix)]
fn path_id(path: &Path) -> io::Result<Option<(FileId, u64)>> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(meta) => Ok(Some(((meta.dev(), meta.ino()), meta.len()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn handle_id(file: &File) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}

// Windows has no inode in std metadata; the volume serial and file index come from the handle.
#[cfg(windows)]
fn path_id(path: &Path) -> io::Result<Option<(FileId, u64)>> {
    match File::open(path) {
        Ok(file) => Ok(Some((handle_id(&file)?, file.metadata()?.len()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn handle_id(file: &File) -> io::Result<FileId> {
    crate::os::windows::file_id::file_id(file)
}

impl FileTail {
    pub fn new(
        template: EventTemplate,
        spec: FileSpec,
        env: CollectorEnv,
    ) -> Result<Self, CollectorError> {
        let multiline = spec
            .multiline
            .as_ref()
            .map(Multiline::new)
            .transpose()
            .map_err(CollectorError)?;
        let mut exclude = Vec::new();
        for pattern in &spec.exclude {
            let compiled = glob::Pattern::new(pattern)
                .map_err(|e| CollectorError(format!("exclude {pattern:?}: {e}")))?;
            exclude.push(if pattern.contains(['/', '\\']) {
                Exclude::Path(compiled)
            } else {
                Exclude::Name(compiled)
            });
        }
        let watches: Vec<Watch> = spec
            .paths
            .into_iter()
            .map(|path| {
                let text = path.to_string_lossy();
                Watch {
                    glob: paths::has_glob(&text).then(|| text.into_owned()),
                    root: paths::glob_root(&path),
                    path,
                }
            })
            .collect();
        let scan_interval = if watches.iter().any(|w| w.glob.is_some()) {
            GLOB_SCAN_INTERVAL
        } else {
            Duration::ZERO
        };
        Ok(Self {
            template,
            start_at: spec.start_at,
            max_line_bytes: spec.max_line_bytes,
            watches,
            exclude,
            multiline,
            env,
            harvesters: Vec::new(),
            retired: HashMap::new(),
            saved: BTreeMap::new(),
            first_scan: true,
            scan_interval,
            next_scan: Instant::now(),
            flush_after: multiline::FLUSH_AFTER,
            warned: HashSet::new(),
            chunk: vec![0; READ_CHUNK],
        })
    }

    fn checkpoint(&self) -> Checkpoint {
        let mut files = BTreeMap::new();
        // Files still matched win when a rotated file shares their path.
        let ordered = self
            .harvesters
            .iter()
            .filter(|h| !h.seen)
            .chain(self.harvesters.iter().filter(|h| h.seen));
        for h in ordered {
            let offset = h
                .assembler
                .as_ref()
                .and_then(Assembler::pending_start)
                .unwrap_or(h.offset);
            files.insert(
                h.path.clone(),
                FilePosition {
                    dev: h.id.0,
                    ino: h.id.1,
                    offset,
                },
            );
        }
        Checkpoint::File { files }
    }

    fn excluded(&self, path: &Path) -> bool {
        let options = match_options();
        self.exclude.iter().any(|e| match e {
            Exclude::Path(p) => p.matches_path_with(path, options),
            Exclude::Name(p) => path
                .file_name()
                .is_some_and(|n| p.matches_with(&n.to_string_lossy(), options)),
        })
    }

    fn warn_once(&mut self, path: &Path, message: &str) {
        if self.warned.insert(path.to_path_buf()) {
            log::warn!("{}: {message}", self.template.rule_id);
        }
    }

    /// Expand paths and globs; start reading files not seen before.
    fn scan(&mut self) {
        for h in &mut self.harvesters {
            h.seen = false;
        }
        let mut matched: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut refused: Vec<(PathBuf, String)> = Vec::new();
        for watch in &self.watches {
            let candidates: Vec<PathBuf> = match &watch.glob {
                None => vec![watch.path.clone()],
                Some(pattern) => match glob::glob_with(pattern, match_options()) {
                    Ok(found) => found
                        .take(MAX_GLOB_MATCHES)
                        .filter_map(Result::ok)
                        .collect(),
                    Err(_) => Vec::new(),
                },
            };
            for path in candidates {
                if self.excluded(&path) || matched.iter().any(|(p, _)| *p == path) {
                    continue;
                }
                match paths::check_file(&path, &watch.root, &self.env.protected) {
                    Ok(canonical) => matched.push((path, canonical)),
                    // A plain path that does not exist yet is picked up once it does.
                    Err(_) if path.symlink_metadata().is_err() => {}
                    Err(e) => refused.push((path, e)),
                }
            }
        }
        for (path, message) in refused {
            self.warn_once(&path, &message);
        }

        for (path, canonical) in matched {
            let Ok(Some((id, len))) = path_id(&canonical) else {
                continue;
            };
            if let Some(h) = self.harvesters.iter_mut().find(|h| h.id == id) {
                h.seen = true;
                if h.path != path && !matches!(path_id(&h.path), Ok(Some((now, _))) if now == id) {
                    // Renamed (rotated into another matched name): report it under that name.
                    h.path = path;
                }
                continue;
            }
            let Some(slot) = self.env.open_files.acquire() else {
                let cap = self.env.open_files.max;
                self.warn_once(
                    &path,
                    &format!(
                        "not reading {}: {cap} files are already open (raise [agent] max_open_files)",
                        path.display()
                    ),
                );
                continue;
            };
            let offset = self.initial_offset(&path, id, len);
            let assembler = self
                .multiline
                .is_some()
                .then(|| Assembler::new(self.max_line_bytes));
            match Harvester::open(&canonical, path.clone(), offset, slot, assembler) {
                Ok(h) => self.harvesters.push(h),
                Err(e) => self.warn_once(&path, &format!("{}: {e}", path.display())),
            }
        }
        self.first_scan = false;
    }

    fn initial_offset(&mut self, path: &Path, id: FileId, len: u64) -> u64 {
        let resume = |offset: u64| if offset <= len { offset } else { 0 };
        if let Some(offset) = self.retired.remove(&id) {
            return resume(offset);
        }
        if let Some(pos) = self.saved.values().find(|p| (p.dev, p.ino) == id) {
            return resume(pos.offset);
        }
        if self.saved.contains_key(path) {
            // A different file at a checkpointed path: rotated while the agent was stopped.
            return 0;
        }
        match (self.first_scan, self.start_at) {
            (true, StartAt::End) => len,
            // New since the agent started, or start_at = "beginning".
            _ => 0,
        }
    }

    fn to_events(&self, path: &Path, events: Vec<Assembled>, out: &mut Vec<crate::RawEvent>) {
        let path = path.to_string_lossy();
        for Assembled { bytes, truncated } in events {
            if bytes.is_empty() && !truncated {
                continue;
            }
            let mut ev = self.template.event(
                time::now_us(),
                Some(String::from_utf8_lossy(&bytes).into_owned()),
                Map::new(),
            );
            ev.attrs.insert("path".into(), Value::from(path.as_ref()));
            if truncated {
                ev.attrs.insert("truncated".into(), Value::Bool(true));
            }
            out.push(ev);
        }
    }
}

impl Harvester {
    fn open(
        canonical: &Path,
        path: PathBuf,
        offset: u64,
        slot: FileSlot,
        assembler: Option<Assembler>,
    ) -> io::Result<Self> {
        let mut file = File::open(canonical)?;
        file.seek(SeekFrom::Start(offset))?;
        Ok(Self {
            path,
            seen: true,
            closed: false,
            id: handle_id(&file)?,
            file,
            offset,
            read_pos: offset,
            partial: Vec::new(),
            partial_truncated: false,
            assembler,
            last_line: Instant::now(),
            _slot: slot,
        })
    }

    /// Read complete lines until EOF or until `out` holds `max` lines. Returns true at EOF.
    fn read_lines(
        &mut self,
        chunk: &mut [u8],
        max: usize,
        max_line_bytes: usize,
        out: &mut Vec<Line>,
    ) -> io::Result<bool> {
        loop {
            if out.len() >= max {
                return Ok(false);
            }
            let n = match self.file.read(chunk) {
                Ok(0) => return Ok(true),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            let mut start = 0;
            while start < n && out.len() < max {
                let rest = &chunk[start..n];
                match rest.iter().position(|&b| b == b'\n') {
                    Some(i) => {
                        self.push_partial(&rest[..i], max_line_bytes);
                        let mut bytes = std::mem::take(&mut self.partial);
                        if bytes.last() == Some(&b'\r') && !self.partial_truncated {
                            bytes.pop();
                        }
                        out.push(Line {
                            bytes,
                            truncated: std::mem::take(&mut self.partial_truncated),
                            start: self.offset,
                        });
                        start += i + 1;
                        self.read_pos += (i + 1) as u64;
                        self.offset = self.read_pos;
                    }
                    None => {
                        self.push_partial(rest, max_line_bytes);
                        self.read_pos += rest.len() as u64;
                        start = n;
                    }
                }
            }
            if start < n {
                // Hit `max` mid-chunk: rewind to the first unconsumed byte.
                self.file.seek(SeekFrom::Start(self.read_pos))?;
                return Ok(false);
            }
        }
    }

    fn push_partial(&mut self, bytes: &[u8], max_line_bytes: usize) {
        let room = max_line_bytes.saturating_sub(self.partial.len());
        if bytes.len() > room {
            self.partial_truncated = true;
        }
        self.partial
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    /// Hand over a partial last line of a file that will not grow any more.
    fn flush_partial(&mut self, out: &mut Vec<Line>) {
        if !self.partial.is_empty() || self.partial_truncated {
            out.push(Line {
                bytes: std::mem::take(&mut self.partial),
                truncated: std::mem::take(&mut self.partial_truncated),
                start: self.offset,
            });
        }
        self.offset = self.read_pos;
    }

    /// Read what is new, handling truncation; at EOF of a file no longer matched, finish
    /// and close. Returns the events in order.
    fn poll(
        &mut self,
        chunk: &mut [u8],
        max: usize,
        max_line_bytes: usize,
        multiline: Option<&Multiline>,
        out: &mut Vec<Assembled>,
    ) -> io::Result<()> {
        let mut lines = Vec::new();
        if self.file.metadata()?.len() < self.read_pos {
            // Truncated in place (copytruncate): finish what was pending, start again at 0.
            log::info!(
                "{} was truncated; reading from the start",
                self.path.display()
            );
            self.flush_partial(&mut lines);
            self.assemble(lines.drain(..), multiline, out);
            if let Some(a) = &mut self.assembler {
                a.flush(out);
            }
            self.file.seek(SeekFrom::Start(0))?;
            self.offset = 0;
            self.read_pos = 0;
        }
        let eof = self.read_lines(chunk, max, max_line_bytes, &mut lines)?;
        if !self.seen && eof {
            // Rotated away or deleted, and drained.
            self.flush_partial(&mut lines);
            self.closed = true;
        }
        self.assemble(lines.drain(..), multiline, out);
        if self.closed
            && let Some(a) = &mut self.assembler
        {
            a.flush(out);
        }
        Ok(())
    }

    fn assemble(
        &mut self,
        lines: impl Iterator<Item = Line>,
        multiline: Option<&Multiline>,
        out: &mut Vec<Assembled>,
    ) {
        for line in lines {
            self.last_line = Instant::now();
            match (multiline, &mut self.assembler) {
                (Some(ml), Some(a)) => a.push(ml, &line.bytes, line.truncated, line.start, out),
                _ => out.push(Assembled {
                    bytes: line.bytes,
                    truncated: line.truncated,
                }),
            }
        }
    }
}

impl Collector for FileTail {
    fn rule_id(&self) -> &str {
        &self.template.rule_id
    }

    fn start(&mut self, checkpoint: Option<Checkpoint>) -> Result<(), CollectorError> {
        self.saved = match checkpoint {
            Some(Checkpoint::File { files }) => files,
            _ => BTreeMap::new(),
        };
        self.harvesters.clear();
        self.retired.clear();
        self.first_scan = true;
        self.scan();
        self.next_scan = Instant::now() + self.scan_interval;
        Ok(())
    }

    fn poll(&mut self, max_events: usize, wait: Duration) -> Result<Batch, CollectorError> {
        let deadline = Instant::now() + wait;
        let mut events = Vec::new();
        let mut assembled = Vec::new();
        loop {
            if Instant::now() >= self.next_scan {
                self.scan();
                self.next_scan = Instant::now() + self.scan_interval;
            }
            for i in 0..self.harvesters.len() {
                if events.len() >= max_events {
                    break;
                }
                let h = &mut self.harvesters[i];
                h.poll(
                    &mut self.chunk,
                    max_events - events.len(),
                    self.max_line_bytes,
                    self.multiline.as_ref(),
                    &mut assembled,
                )
                .map_err(|e| CollectorError(format!("{}: {e}", h.path.display())))?;
                if h.last_line.elapsed() >= self.flush_after
                    && let Some(a) = &mut h.assembler
                {
                    a.flush(&mut assembled);
                }
                let path = h.path.clone();
                self.to_events(&path, std::mem::take(&mut assembled), &mut events);
            }
            for h in self.harvesters.iter().filter(|h| h.closed) {
                log::info!("{} was rotated or removed; done with it", h.path.display());
                self.retired.insert(h.id, h.read_pos);
            }
            self.harvesters.retain(|h| !h.closed);
            if self.retired.len() > MAX_RETIRED {
                self.retired.clear();
            }
            let now = Instant::now();
            if !events.is_empty() || now >= deadline {
                break;
            }
            thread::sleep(CHECK_INTERVAL.min(deadline - now));
        }
        Ok(Batch {
            events,
            checkpoint: Some(self.checkpoint()),
        })
    }
}

#[cfg(test)]
mod tests;
