//! Durable, bounded on-disk buffer between the collectors and the shipper.
//!
//! Layout in the buffer directory:
//! - `<id>.seg` segment files (16 hex digit ids), each a run of framed records:
//!   `u32 length (LE) | u32 CRC-32 (LE) | payload` where the payload is one NDJSON line.
//! - `meta.json`: a random nonce for this buffer, the ack cursor (first unacknowledged record)
//!   and the in-flight batch, if any. Written to a temporary file, fsynced and renamed.
//!
//! Guarantees:
//! - [`DiskBuffer::append`] returns only after the records are fsynced.
//! - A batch is recorded in `meta.json` before it is sent ([`DiskBuffer::begin`]), and the
//!   cursor moves past it only when the server acknowledges it ([`DiskBuffer::ack`]). After a
//!   crash the same records are sent again under the same batch id, so the server's
//!   idempotency store can drop the repeat: at most the unacknowledged batch is resent.
//! - When the buffer is over its cap, whole segments are dropped oldest first and the
//!   unacknowledged records in them are counted in [`DiskBuffer::dropped_full`].
//! - A torn record at the end of the newest segment (crash mid-write) is cut off on open.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const HEADER: u64 = 8;
const META: &str = "meta.json";
/// A record can never be larger than this; anything claiming more is corruption.
const MAX_RECORD: u32 = 16 * 1024 * 1024;

/// A point in the buffer: a segment and a byte offset within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Position {
    pub segment: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Inflight {
    id: String,
    end: Position,
    records: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Meta {
    nonce: String,
    cursor: Position,
    inflight: Option<Inflight>,
}

#[derive(Debug)]
struct Segment {
    id: u64,
    len: u64,
    /// Offsets where records start, so unacknowledged records can be counted after a cursor.
    starts: Vec<u64>,
}

impl Segment {
    fn records_from(&self, offset: u64) -> u64 {
        (self.starts.len() - self.starts.partition_point(|&s| s < offset)) as u64
    }
}

/// Records read from the cursor, ready to encode into a batch.
#[derive(Debug)]
pub struct Peeked {
    pub start: Position,
    pub lines: Vec<Vec<u8>>,
    /// `ends[i]` is the position just after `lines[i]`.
    pub ends: Vec<Position>,
    /// Set when these records are a batch that was in flight before a restart: it must be
    /// resent with this id.
    pub inflight_id: Option<String>,
}

#[derive(Debug)]
pub struct DiskBuffer {
    dir: PathBuf,
    max_bytes: u64,
    segment_max: u64,
    meta: Meta,
    segments: VecDeque<Segment>,
    writer: Option<BufWriter<File>>,
    dropped_full: u64,
}

fn segment_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id:016x}.seg"))
}

impl DiskBuffer {
    /// Open or create the buffer in `dir`, capped at `max_bytes`.
    pub fn open(dir: &Path, max_bytes: u64) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let meta = match fs::read(dir.join(META)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::other(format!("buffer meta.json: {e}")))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Meta {
                nonce: format!("{:016x}", fastrand::u64(..)),
                cursor: Position {
                    segment: 0,
                    offset: 0,
                },
                inflight: None,
            },
            Err(e) => return Err(e),
        };

        let mut ids = Vec::new();
        for entry in fs::read_dir(dir)? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            if let Some(hex) = name.strip_suffix(".seg")
                && hex.len() == 16
                && let Ok(id) = u64::from_str_radix(hex, 16)
            {
                ids.push(id);
            }
        }
        ids.sort_unstable();

        let mut segments = VecDeque::new();
        let last = ids.last().copied();
        for id in ids {
            segments.push_back(scan_segment(dir, id, Some(id) == last)?);
        }

        let mut buffer = Self {
            dir: dir.to_path_buf(),
            max_bytes,
            segment_max: (max_bytes / 16).clamp(1024 * 1024, 16 * 1024 * 1024),
            meta,
            segments,
            writer: None,
            dropped_full: 0,
        };
        buffer.normalise_cursor();
        buffer.save_meta()?;
        Ok(buffer)
    }

    /// Bytes on disk in segments.
    pub fn bytes(&self) -> u64 {
        self.segments.iter().map(|s| s.len).sum()
    }

    /// Records not yet acknowledged by the server.
    pub fn pending_records(&self) -> u64 {
        self.segments
            .iter()
            .map(|s| match s.id.cmp(&self.meta.cursor.segment) {
                std::cmp::Ordering::Less => 0,
                std::cmp::Ordering::Equal => s.records_from(self.meta.cursor.offset),
                std::cmp::Ordering::Greater => s.starts.len() as u64,
            })
            .sum()
    }

    /// Unacknowledged records dropped because the buffer was full, since open.
    pub fn dropped_full(&self) -> u64 {
        self.dropped_full
    }

    /// Append records and fsync. Then drop the oldest segments if over the cap.
    pub fn append<L: AsRef<[u8]>>(&mut self, lines: &[L]) -> io::Result<()> {
        if lines.is_empty() {
            return Ok(());
        }
        if self.writer.is_none()
            && let Some(tail) = self.segments.back()
        {
            // Reopened buffer: keep appending to the newest segment.
            let file = OpenOptions::new()
                .append(true)
                .open(segment_path(&self.dir, tail.id))?;
            self.writer = Some(BufWriter::with_capacity(64 * 1024, file));
        }
        for line in lines {
            let payload = line.as_ref();
            let len = u32::try_from(payload.len())
                .ok()
                .filter(|&l| l <= MAX_RECORD)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "record larger than the buffer allows",
                    )
                })?;
            let tail_full = self
                .segments
                .back()
                .is_none_or(|s| s.len > 0 && s.len + HEADER + u64::from(len) > self.segment_max);
            if tail_full {
                self.roll()?;
            }
            let (writer, tail) = match (self.writer.as_mut(), self.segments.back_mut()) {
                (Some(w), Some(t)) => (w, t),
                _ => return Err(io::Error::other("buffer has no open segment")),
            };
            writer.write_all(&len.to_le_bytes())?;
            writer.write_all(&crc32fast::hash(payload).to_le_bytes())?;
            writer.write_all(payload)?;
            tail.starts.push(tail.len);
            tail.len += HEADER + u64::from(len);
        }
        self.sync_writer()?;
        self.enforce_cap()
    }

    fn sync_writer(&mut self) -> io::Result<()> {
        if let Some(w) = self.writer.as_mut() {
            w.flush()?;
            w.get_ref().sync_data()?;
        }
        Ok(())
    }

    /// Start a new segment for appends.
    fn roll(&mut self) -> io::Result<()> {
        self.sync_writer()?;
        let id = self
            .segments
            .back()
            .map_or(self.meta.cursor.segment, |s| s.id + 1);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(segment_path(&self.dir, id))?;
        sync_dir(&self.dir)?;
        self.writer = Some(BufWriter::with_capacity(64 * 1024, file));
        self.segments.push_back(Segment {
            id,
            len: 0,
            starts: Vec::new(),
        });
        Ok(())
    }

    fn enforce_cap(&mut self) -> io::Result<()> {
        let mut changed = false;
        while self.bytes() > self.max_bytes && self.segments.len() > 1 {
            let Some(oldest) = self.segments.pop_front() else {
                break;
            };
            let unacked = match oldest.id.cmp(&self.meta.cursor.segment) {
                std::cmp::Ordering::Less => 0,
                std::cmp::Ordering::Equal => oldest.records_from(self.meta.cursor.offset),
                std::cmp::Ordering::Greater => oldest.starts.len() as u64,
            };
            self.dropped_full += unacked;
            fs::remove_file(segment_path(&self.dir, oldest.id))?;
            log::warn!("disk buffer full: dropped {unacked} unsent events");
            changed = true;
        }
        if changed {
            self.normalise_cursor();
            self.save_meta()?;
        }
        Ok(())
    }

    /// Keep the cursor inside the existing segments and drop an in-flight batch whose records
    /// are gone.
    fn normalise_cursor(&mut self) {
        let Some(first) = self.segments.front() else {
            // Empty buffer: the next segment starts at the cursor's segment id or later.
            self.meta.inflight = None;
            self.meta.cursor.offset = 0;
            return;
        };
        if self.meta.cursor.segment < first.id {
            self.meta.cursor = Position {
                segment: first.id,
                offset: 0,
            };
            self.meta.inflight = None;
        }
        if let Some(seg) = self
            .segments
            .iter()
            .find(|s| s.id == self.meta.cursor.segment)
            && self.meta.cursor.offset > seg.len
        {
            self.meta.cursor.offset = seg.len;
            self.meta.inflight = None;
        }
        if let Some(inflight) = &self.meta.inflight {
            let end_ok = self
                .segments
                .iter()
                .any(|s| s.id == inflight.end.segment && inflight.end.offset <= s.len);
            if !end_ok {
                self.meta.inflight = None;
            }
        }
    }

    fn save_meta(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec(&self.meta).map_err(io::Error::other)?;
        write_atomic(&self.dir, META, &bytes)
    }

    /// Read up to `max_records` records or `max_bytes` of payload from the cursor. If a batch
    /// was in flight, returns exactly that batch.
    pub fn peek(&self, max_records: usize, max_bytes: u64) -> io::Result<Peeked> {
        let (limit_records, inflight_id) = match &self.meta.inflight {
            Some(i) => (
                usize::try_from(i.records).unwrap_or(usize::MAX),
                Some(i.id.clone()),
            ),
            None => (max_records, None),
        };
        let start = self.meta.cursor;
        let mut lines = Vec::new();
        let mut ends = Vec::new();
        let mut total = 0u64;
        'segments: for seg in self.segments.iter().filter(|s| s.id >= start.segment) {
            let from = if seg.id == start.segment {
                start.offset
            } else {
                0
            };
            if from >= seg.len {
                continue;
            }
            let mut file = File::open(segment_path(&self.dir, seg.id))?;
            file.seek(SeekFrom::Start(from))?;
            let mut reader = io::BufReader::new(file.take(seg.len - from));
            let mut offset = from;
            while offset < seg.len && lines.len() < limit_records {
                let mut header = [0u8; 8];
                reader.read_exact(&mut header)?;
                let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
                let crc = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
                if inflight_id.is_none()
                    && !lines.is_empty()
                    && total + u64::from(len) + 1 > max_bytes
                {
                    break 'segments;
                }
                let mut payload = vec![0u8; len as usize];
                reader.read_exact(&mut payload)?;
                offset += HEADER + u64::from(len);
                if crc32fast::hash(&payload) != crc {
                    // Bit rot: skip the record rather than ship garbage.
                    log::warn!(
                        "disk buffer: skipped a corrupt record in segment {:016x}",
                        seg.id
                    );
                    continue;
                }
                total += u64::from(len) + 1;
                lines.push(payload);
                ends.push(Position {
                    segment: seg.id,
                    offset,
                });
            }
            if lines.len() >= limit_records {
                break;
            }
        }
        Ok(Peeked {
            start,
            lines,
            ends,
            inflight_id,
        })
    }

    /// Record that the first `records` peeked records are about to be sent, ending at `end`.
    /// Returns the batch id, or `None` if the cursor moved since the peek (records were dropped
    /// for space) and the caller should peek again.
    pub fn begin(
        &mut self,
        start: Position,
        records: usize,
        end: Position,
    ) -> io::Result<Option<String>> {
        if start != self.meta.cursor {
            return Ok(None);
        }
        if let Some(inflight) = &self.meta.inflight {
            if inflight.end == end {
                return Ok(Some(inflight.id.clone()));
            }
            // Limits changed since the restart; the old batch is replaced by a smaller one.
            log::warn!(
                "in-flight batch {} replaced after a restart with different limits",
                inflight.id
            );
        }
        let id = format!(
            "{}-{:x}-{:x}-{records}",
            self.meta.nonce, start.segment, start.offset
        );
        self.meta.inflight = Some(Inflight {
            id: id.clone(),
            end,
            records: records as u64,
        });
        self.save_meta()?;
        Ok(Some(id))
    }

    /// The server accepted (or permanently rejected) batch `id`: move the cursor past it and
    /// delete fully acknowledged segments.
    pub fn ack(&mut self, id: &str) -> io::Result<()> {
        let Some(inflight) = self.meta.inflight.take_if(|i| i.id == id) else {
            // The batch's records were dropped for space while it was being sent.
            return Ok(());
        };
        self.meta.cursor = inflight.end;
        // Move to the next segment when the cursor is at the end of a closed one.
        while let Some(seg) = self
            .segments
            .iter()
            .find(|s| s.id == self.meta.cursor.segment)
        {
            let is_tail = self.segments.back().is_some_and(|t| t.id == seg.id);
            if is_tail || self.meta.cursor.offset < seg.len {
                break;
            }
            self.meta.cursor = Position {
                segment: seg.id + 1,
                offset: 0,
            };
        }
        self.save_meta()?;
        while self
            .segments
            .front()
            .is_some_and(|s| s.id < self.meta.cursor.segment)
        {
            if let Some(seg) = self.segments.pop_front() {
                fs::remove_file(segment_path(&self.dir, seg.id))?;
            }
        }
        Ok(())
    }
}

/// Read a segment's record starts. A torn or corrupt tail on the newest segment is cut off;
/// on older segments it is ignored (they are never appended to again).
fn scan_segment(dir: &Path, id: u64, newest: bool) -> io::Result<Segment> {
    let path = segment_path(dir, id);
    let file = File::open(&path)?;
    let file_len = file.metadata()?.len();
    let mut reader = io::BufReader::new(file);
    let mut starts = Vec::new();
    let mut offset = 0u64;
    let mut header = [0u8; 8];
    while offset + HEADER <= file_len {
        reader.read_exact(&mut header)?;
        let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let crc = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if len > MAX_RECORD || offset + HEADER + u64::from(len) > file_len {
            break;
        }
        if newest {
            // Verify the newest segment fully: a crash can leave a record with a valid length
            // but unwritten payload.
            let mut payload = vec![0u8; len as usize];
            reader.read_exact(&mut payload)?;
            if crc32fast::hash(&payload) != crc {
                break;
            }
        } else {
            reader.seek_relative(i64::from(len))?;
        }
        starts.push(offset);
        offset += HEADER + u64::from(len);
    }
    if offset < file_len {
        log::warn!(
            "disk buffer: segment {id:016x} has {} bytes of torn data",
            file_len - offset
        );
        if newest {
            OpenOptions::new()
                .write(true)
                .open(&path)?
                .set_len(offset)?;
        }
    }
    Ok(Segment {
        id,
        len: offset,
        starts,
    })
}

/// Write `name` in `dir` via a temporary file, fsync and rename.
pub fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dir.join(name))?;
    sync_dir(dir)
}

/// Make a rename or create in `dir` durable. Windows has no directory fsync; NTFS journals the
/// metadata change.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) struct TempDir(pub PathBuf);

    impl TempDir {
        pub(crate) fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "wt-buf-{name}-{}-{}",
                std::process::id(),
                fastrand::u32(..)
            ));
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn lines(range: std::ops::Range<u32>) -> Vec<Vec<u8>> {
        range
            .map(|i| format!("{{\"n\":{i}}}").into_bytes())
            .collect()
    }

    fn take_batch(buf: &mut DiskBuffer, max: usize) -> (String, Vec<Vec<u8>>) {
        let peeked = buf.peek(max, u64::MAX).expect("peek");
        let n = peeked.lines.len();
        let end = *peeked.ends.last().expect("records");
        let id = buf
            .begin(peeked.start, n, end)
            .expect("begin")
            .expect("cursor unchanged");
        (id, peeked.lines)
    }

    #[test]
    fn survives_crash_without_clean_shutdown() {
        let dir = TempDir::new("crash");
        {
            let mut buf = DiskBuffer::open(&dir.0, 64 << 20).expect("open");
            buf.append(&lines(0..100)).expect("append");
            // Dropped without any shutdown call, as in a crash after fsync.
        }
        let buf = DiskBuffer::open(&dir.0, 64 << 20).expect("reopen");
        assert_eq!(buf.pending_records(), 100);
        let peeked = buf.peek(1000, u64::MAX).expect("peek");
        assert_eq!(peeked.lines, lines(0..100));
    }

    #[test]
    fn torn_tail_is_cut_and_appends_continue() {
        let dir = TempDir::new("torn");
        {
            let mut buf = DiskBuffer::open(&dir.0, 64 << 20).expect("open");
            buf.append(&lines(0..10)).expect("append");
        }
        // Simulate a crash mid-write: a header promising 100 bytes and 3 bytes of payload.
        let seg = segment_path(&dir.0, 0);
        let mut f = OpenOptions::new()
            .append(true)
            .open(&seg)
            .expect("open seg");
        f.write_all(&100u32.to_le_bytes()).expect("w");
        f.write_all(&0u32.to_le_bytes()).expect("w");
        f.write_all(b"abc").expect("w");
        drop(f);
        let mut buf = DiskBuffer::open(&dir.0, 64 << 20).expect("reopen");
        assert_eq!(buf.pending_records(), 10);
        buf.append(&lines(10..12)).expect("append");
        let peeked = buf.peek(1000, u64::MAX).expect("peek");
        assert_eq!(peeked.lines, lines(0..12));
    }

    #[test]
    fn restart_mid_batch_resends_only_the_unacked_batch_with_same_id() {
        let dir = TempDir::new("midbatch");
        let first_id;
        {
            let mut buf = DiskBuffer::open(&dir.0, 64 << 20).expect("open");
            buf.append(&lines(0..30)).expect("append");
            let (id, sent) = take_batch(&mut buf, 10);
            assert_eq!(sent, lines(0..10));
            buf.ack(&id).expect("ack");
            let (id, sent) = take_batch(&mut buf, 10);
            assert_eq!(sent, lines(10..20));
            first_id = id;
            // Killed after sending, before the ack arrived. More data arrives meanwhile.
            buf.append(&lines(30..35)).expect("append");
        }
        let mut buf = DiskBuffer::open(&dir.0, 64 << 20).expect("reopen");
        assert_eq!(buf.pending_records(), 25);
        // Even with a larger limit, the in-flight batch comes back exactly, with its id.
        let peeked = buf.peek(1000, u64::MAX).expect("peek");
        assert_eq!(peeked.inflight_id.as_deref(), Some(first_id.as_str()));
        assert_eq!(peeked.lines, lines(10..20));
        let (id, _) = take_batch(&mut buf, 1000);
        assert_eq!(id, first_id);
        buf.ack(&id).expect("ack");
        let (_, rest) = take_batch(&mut buf, 1000);
        assert_eq!(rest, lines(20..35));
    }

    #[test]
    fn overflow_drops_oldest_and_counts() {
        let dir = TempDir::new("overflow");
        // 16 MiB cap, 1 MiB segments. Each record is ~100 KiB.
        let mut buf = DiskBuffer::open(&dir.0, 16 << 20).expect("open");
        let record = vec![b'x'; 100 * 1024];
        for _ in 0..400 {
            buf.append(&[&record]).expect("append");
        }
        assert!(buf.bytes() <= 16 << 20, "{}", buf.bytes());
        assert!(buf.dropped_full() > 0);
        assert_eq!(buf.dropped_full() + buf.pending_records(), 400);
        // The surviving records are the newest ones, readable from the cursor.
        let peeked = buf.peek(10_000, u64::MAX).expect("peek");
        assert_eq!(peeked.lines.len() as u64, buf.pending_records());
        drop(buf);
        let buf = DiskBuffer::open(&dir.0, 16 << 20).expect("reopen");
        assert!(buf.pending_records() > 100);
    }

    #[test]
    fn overflow_during_inflight_does_not_move_cursor_backwards() {
        let dir = TempDir::new("overflow-inflight");
        let mut buf = DiskBuffer::open(&dir.0, 16 << 20).expect("open");
        let record = vec![b'x'; 100 * 1024];
        buf.append(&[&record]).expect("append");
        let (id, _) = take_batch(&mut buf, 1);
        for _ in 0..400 {
            buf.append(&[&record]).expect("append");
        }
        let before = buf.meta.cursor;
        buf.ack(&id).expect("ack of a dropped batch is a no-op");
        assert_eq!(buf.meta.cursor, before);
        assert!(buf.peek(1, u64::MAX).expect("peek").inflight_id.is_none());
    }

    #[test]
    fn ack_deletes_finished_segments_and_counts_stay_right() {
        let dir = TempDir::new("ack");
        let mut buf = DiskBuffer::open(&dir.0, 16 << 20).expect("open");
        let record = vec![b'y'; 300 * 1024];
        for _ in 0..10 {
            buf.append(&[&record]).expect("append");
        }
        let segs_before = buf.segments.len();
        assert!(segs_before > 2);
        loop {
            let peeked = buf.peek(3, u64::MAX).expect("peek");
            if peeked.lines.is_empty() {
                break;
            }
            let end = *peeked.ends.last().expect("end");
            let id = buf
                .begin(peeked.start, peeked.lines.len(), end)
                .expect("begin")
                .expect("id");
            buf.ack(&id).expect("ack");
        }
        assert_eq!(buf.pending_records(), 0);
        assert_eq!(buf.segments.len(), 1, "only the tail segment is kept");
        buf.append(&lines(0..2)).expect("append after drain");
        assert_eq!(buf.peek(10, u64::MAX).expect("peek").lines, lines(0..2));
    }

    #[test]
    fn peek_respects_byte_limit_but_returns_at_least_one() {
        let dir = TempDir::new("bytes");
        let mut buf = DiskBuffer::open(&dir.0, 16 << 20).expect("open");
        buf.append(&lines(0..100)).expect("append");
        let peeked = buf.peek(1000, 50).expect("peek");
        assert!(peeked.lines.len() < 10 && !peeked.lines.is_empty());
        let peeked = buf.peek(1000, 1).expect("peek");
        assert_eq!(peeked.lines.len(), 1);
    }

    #[test]
    fn corrupt_meta_is_an_error_not_silent_data_loss() {
        let dir = TempDir::new("meta");
        fs::create_dir_all(&dir.0).expect("mkdir");
        fs::write(dir.0.join(META), b"{not json").expect("write");
        assert!(DiskBuffer::open(&dir.0, 16 << 20).is_err());
    }

    #[test]
    fn batch_ids_are_valid_and_unique_per_buffer() {
        let a = TempDir::new("id-a");
        let b = TempDir::new("id-b");
        let mut ba = DiskBuffer::open(&a.0, 16 << 20).expect("open");
        let mut bb = DiskBuffer::open(&b.0, 16 << 20).expect("open");
        ba.append(&lines(0..1)).expect("append");
        bb.append(&lines(0..1)).expect("append");
        let (ida, _) = take_batch(&mut ba, 10);
        let (idb, _) = take_batch(&mut bb, 10);
        assert_ne!(ida, idb);
        for id in [ida, idb] {
            assert!(
                id.len() <= 64
                    && id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
                "{id}"
            );
        }
    }
}
