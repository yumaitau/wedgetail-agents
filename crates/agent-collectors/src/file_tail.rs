//! Tail text files, following rotation (rename and create) and truncation (copytruncate).
//!
//! Each file's checkpoint is its identity (device and inode on Unix) plus the byte offset after
//! the last complete line handed to the pipeline. A partial last line is not sent until its
//! newline arrives, or until the file is rotated away.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use agent_config::StartAt;
use serde_json::{Map, Value};

use crate::{
    Batch, Checkpoint, Collector, CollectorError, EventTemplate, FilePosition, MAX_LINE_BYTES, time,
};

/// How often idle files are checked for new data, rotation and truncation.
const CHECK_INTERVAL: Duration = Duration::from_millis(250);
const READ_CHUNK: usize = 64 * 1024;

#[derive(Debug)]
pub struct FileTail {
    template: EventTemplate,
    start_at: StartAt,
    files: Vec<TailFile>,
    chunk: Vec<u8>,
}

#[derive(Debug)]
struct TailFile {
    path: PathBuf,
    open: Option<OpenFile>,
}

#[derive(Debug)]
struct OpenFile {
    file: File,
    id: (u64, u64),
    /// After the last complete line emitted: the checkpoint offset.
    offset: u64,
    /// After the last byte consumed (`offset` plus the partial line, including any bytes
    /// discarded from an over-long line).
    read_pos: u64,
    partial: Vec<u8>,
    partial_truncated: bool,
}

/// Identity and length of the file now at `path`; `None` if there is none.
#[cfg(unix)]
fn path_id(path: &Path) -> io::Result<Option<((u64, u64), u64)>> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(meta) => Ok(Some(((meta.dev(), meta.ino()), meta.len()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn handle_id(file: &File) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}

// Windows has no inode in std metadata; the volume serial and file index come from the handle.
#[cfg(windows)]
fn path_id(path: &Path) -> io::Result<Option<((u64, u64), u64)>> {
    match File::open(path) {
        Ok(file) => Ok(Some((handle_id(&file)?, file.metadata()?.len()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn handle_id(file: &File) -> io::Result<(u64, u64)> {
    crate::os::windows::file_id::file_id(file)
}

impl FileTail {
    pub fn new(template: EventTemplate, paths: Vec<PathBuf>, start_at: StartAt) -> Self {
        let files = paths
            .into_iter()
            .map(|path| TailFile { path, open: None })
            .collect();
        Self {
            template,
            start_at,
            files,
            chunk: vec![0; READ_CHUNK],
        }
    }

    fn checkpoint(&self) -> Checkpoint {
        let files = self
            .files
            .iter()
            .filter_map(|f| {
                let o = f.open.as_ref()?;
                Some((
                    f.path.clone(),
                    FilePosition {
                        dev: o.id.0,
                        ino: o.id.1,
                        offset: o.offset,
                    },
                ))
            })
            .collect();
        Checkpoint::File { files }
    }
}

impl OpenFile {
    fn open(path: &Path, offset: Option<u64>) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let offset = offset.unwrap_or(file.metadata()?.len());
        file.seek(SeekFrom::Start(offset))?;
        Ok(Self {
            id: handle_id(&file)?,
            file,
            offset,
            read_pos: offset,
            partial: Vec::new(),
            partial_truncated: false,
        })
    }

    /// Read complete lines until EOF or until `out` holds `max` lines. Returns true at EOF.
    fn read_lines(
        &mut self,
        chunk: &mut [u8],
        max: usize,
        out: &mut Vec<(Vec<u8>, bool)>,
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
                        self.push_partial(&rest[..i]);
                        let mut line = std::mem::take(&mut self.partial);
                        if line.last() == Some(&b'\r') && !self.partial_truncated {
                            line.pop();
                        }
                        out.push((line, std::mem::take(&mut self.partial_truncated)));
                        start += i + 1;
                        self.read_pos += (i + 1) as u64;
                        self.offset = self.read_pos;
                    }
                    None => {
                        self.push_partial(rest);
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

    fn push_partial(&mut self, bytes: &[u8]) {
        let room = MAX_LINE_BYTES.saturating_sub(self.partial.len());
        if bytes.len() > room {
            self.partial_truncated = true;
        }
        self.partial
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    /// Hand over a partial last line of a file that will not grow any more.
    fn flush_partial(&mut self, out: &mut Vec<(Vec<u8>, bool)>) {
        if !self.partial.is_empty() || self.partial_truncated {
            out.push((
                std::mem::take(&mut self.partial),
                std::mem::take(&mut self.partial_truncated),
            ));
        }
        self.offset = self.read_pos;
    }
}

impl TailFile {
    /// Read what is new, handling rotation and truncation. Lines are appended to `out`.
    fn poll(
        &mut self,
        chunk: &mut [u8],
        max: usize,
        out: &mut Vec<(Vec<u8>, bool)>,
    ) -> io::Result<()> {
        let current = path_id(&self.path)?;
        let Some(open) = &mut self.open else {
            // The file did not exist before; a new file is read from the start.
            if current.is_some() {
                self.open = Some(OpenFile::open(&self.path, Some(0))?);
                return self.poll(chunk, max, out);
            }
            return Ok(());
        };

        let rotated = current.is_some_and(|(id, _)| id != open.id);
        if !rotated && current.is_some_and(|(_, len)| len < open.read_pos) {
            // Truncated in place (copytruncate): start again from the top.
            log::info!(
                "{} was truncated; reading from the start",
                self.path.display()
            );
            *open = OpenFile::open(&self.path, Some(0))?;
        }

        let eof = open.read_lines(chunk, max, out)?;
        if rotated && eof && out.len() < max {
            // The old file is drained; switch to the new one at the path.
            open.flush_partial(out);
            log::info!(
                "{} was rotated; following the new file",
                self.path.display()
            );
            self.open = Some(OpenFile::open(&self.path, Some(0))?);
            if let Some(open) = &mut self.open {
                open.read_lines(chunk, max, out)?;
            }
        }
        Ok(())
    }
}

impl Collector for FileTail {
    fn rule_id(&self) -> &str {
        &self.template.rule_id
    }

    fn start(&mut self, checkpoint: Option<Checkpoint>) -> Result<(), CollectorError> {
        let saved = match checkpoint {
            Some(Checkpoint::File { files }) => files,
            _ => BTreeMap::new(),
        };
        for tail in &mut self.files {
            let path_err = |e: io::Error| CollectorError(format!("{}: {e}", tail.path.display()));
            let Some((id, len)) = path_id(&tail.path).map_err(path_err)? else {
                tail.open = None;
                continue;
            };
            let offset = match saved.get(&tail.path) {
                // Same file and still at least as long: resume.
                Some(pos) if (pos.dev, pos.ino) == id && pos.offset <= len => Some(pos.offset),
                // Rotated or truncated while the agent was stopped: the file is new to us.
                Some(_) => Some(0),
                None if self.start_at == StartAt::Beginning => Some(0),
                None => None,
            };
            tail.open = Some(
                OpenFile::open(&tail.path, offset)
                    .map_err(|e| CollectorError(format!("{}: {e}", tail.path.display())))?,
            );
        }
        Ok(())
    }

    fn poll(&mut self, max_events: usize, wait: Duration) -> Result<Batch, CollectorError> {
        let deadline = Instant::now() + wait;
        let mut lines: Vec<(Vec<u8>, bool)> = Vec::new();
        let mut events = Vec::new();
        loop {
            for tail in &mut self.files {
                if events.len() >= max_events {
                    break;
                }
                lines.clear();
                tail.poll(&mut self.chunk, max_events - events.len(), &mut lines)
                    .map_err(|e| CollectorError(format!("{}: {e}", tail.path.display())))?;
                let path = tail.path.to_string_lossy();
                for (line, truncated) in lines.drain(..) {
                    if line.is_empty() && !truncated {
                        continue;
                    }
                    let mut ev = self.template.event(
                        time::now_us(),
                        Some(String::from_utf8_lossy(&line).into_owned()),
                        Map::new(),
                    );
                    ev.attrs.insert("path".into(), Value::from(path.as_ref()));
                    if truncated {
                        ev.attrs.insert("truncated".into(), Value::Bool(true));
                    }
                    events.push(ev);
                }
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
mod tests {
    use std::io::Write;

    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("wt-tail-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("mkdir");
            Self(dir)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn append(path: &Path, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open");
        f.write_all(text.as_bytes()).expect("write");
    }

    fn tail(path: &Path, start_at: StartAt) -> FileTail {
        let template = EventTemplate::new("t", "file", None, &BTreeMap::new());
        FileTail::new(template, vec![path.to_path_buf()], start_at)
    }

    fn bodies(t: &mut FileTail) -> Vec<String> {
        let batch = t.poll(1000, Duration::ZERO).expect("poll");
        batch
            .events
            .into_iter()
            .map(|e| e.body.unwrap_or_default())
            .collect()
    }

    #[test]
    fn starts_at_end_by_default_and_reads_new_lines() {
        let dir = Dir::new("end");
        let path = dir.0.join("a.log");
        append(&path, "old\n");
        let mut t = tail(&path, StartAt::End);
        t.start(None).expect("start");
        assert!(bodies(&mut t).is_empty());
        append(&path, "one\r\ntwo\npart");
        assert_eq!(bodies(&mut t), ["one", "two"]);
        append(&path, "ial\n");
        assert_eq!(bodies(&mut t), ["partial"]);
    }

    #[test]
    fn beginning_and_resume_from_checkpoint() {
        let dir = Dir::new("resume");
        let path = dir.0.join("a.log");
        append(&path, "1\n2\n3");
        let mut t = tail(&path, StartAt::Beginning);
        t.start(None).expect("start");
        let batch = t.poll(10, Duration::ZERO).expect("poll");
        assert_eq!(batch.events.len(), 2);
        let cp = batch.checkpoint.expect("checkpoint");
        match &cp {
            Checkpoint::File { files } => assert_eq!(files[&path].offset, 4),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            batch.events[0].attrs["path"],
            path.to_string_lossy().as_ref()
        );

        // A new process resumes after the last complete line.
        drop(t);
        append(&path, "\n4\n");
        let mut t = tail(&path, StartAt::End);
        t.start(Some(cp)).expect("start");
        assert_eq!(bodies(&mut t), ["3", "4"]);
    }

    #[test]
    fn max_events_rewinds_and_continues() {
        let dir = Dir::new("max");
        let path = dir.0.join("a.log");
        let text: String = (0..100).map(|i| format!("line {i}\n")).collect();
        append(&path, &text);
        let mut t = tail(&path, StartAt::Beginning);
        t.start(None).expect("start");
        let mut all = Vec::new();
        loop {
            let batch = t.poll(7, Duration::ZERO).expect("poll");
            if batch.events.is_empty() {
                break;
            }
            assert!(batch.events.len() <= 7);
            all.extend(batch.events.into_iter().map(|e| e.body.unwrap_or_default()));
        }
        let want: Vec<String> = (0..100).map(|i| format!("line {i}")).collect();
        assert_eq!(all, want);
    }

    #[test]
    fn follows_rename_rotation_without_losing_lines() {
        let dir = Dir::new("rotate");
        let path = dir.0.join("a.log");
        append(&path, "");
        let mut t = tail(&path, StartAt::End);
        t.start(None).expect("start");
        append(&path, "before\nlast-old-no-newline");
        std::fs::rename(&path, dir.0.join("a.log.1")).expect("rename");
        append(&path, "after\n");
        assert_eq!(bodies(&mut t), ["before", "last-old-no-newline", "after"]);
        append(&path, "more\n");
        assert_eq!(bodies(&mut t), ["more"]);
    }

    #[test]
    fn handles_copytruncate() {
        let dir = Dir::new("truncate");
        let path = dir.0.join("a.log");
        append(&path, "");
        let mut t = tail(&path, StartAt::End);
        t.start(None).expect("start");
        append(&path, "a long line before truncation\n");
        assert_eq!(bodies(&mut t).len(), 1);
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("truncate");
        append(&path, "new\n");
        assert_eq!(bodies(&mut t), ["new"]);
    }

    #[test]
    fn missing_file_is_picked_up_when_created() {
        let dir = Dir::new("missing");
        let path = dir.0.join("later.log");
        let mut t = tail(&path, StartAt::End);
        t.start(None).expect("start");
        assert!(bodies(&mut t).is_empty());
        append(&path, "hello\n");
        assert_eq!(bodies(&mut t), ["hello"]);
    }

    #[test]
    fn over_long_and_binary_lines_are_bounded() {
        let dir = Dir::new("long");
        let path = dir.0.join("a.log");
        let mut f = File::create(&path).expect("create");
        f.write_all(&vec![b'x'; MAX_LINE_BYTES * 3]).expect("write");
        f.write_all(b"\n\xff\xfe\x00bin\nok\n").expect("write");
        drop(f);
        let mut t = tail(&path, StartAt::Beginning);
        t.start(None).expect("start");
        let batch = t.poll(10, Duration::ZERO).expect("poll");
        assert_eq!(batch.events.len(), 3);
        assert_eq!(
            batch.events[0].body.as_ref().map(String::len),
            Some(MAX_LINE_BYTES)
        );
        assert_eq!(batch.events[0].attrs["truncated"], true);
        assert_eq!(
            batch.events[1].body.as_deref(),
            Some("\u{fffd}\u{fffd}\0bin")
        );
        assert_eq!(batch.events[2].body.as_deref(), Some("ok"));
        match batch.checkpoint.expect("cp") {
            Checkpoint::File { files } => {
                assert_eq!(
                    files[&path].offset,
                    std::fs::metadata(&path).expect("meta").len()
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn poll_waits_for_new_data() {
        let dir = Dir::new("wait");
        let path = dir.0.join("a.log");
        append(&path, "");
        let mut t = tail(&path, StartAt::End);
        t.start(None).expect("start");
        let writer_path = path.clone();
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            append(&writer_path, "late\n");
        });
        let batch = t.poll(10, Duration::from_secs(5)).expect("poll");
        writer.join().expect("join");
        assert_eq!(batch.events.len(), 1);
    }
}
