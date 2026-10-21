//! Multiline assembly: join continuation lines (stack traces, wrapped messages) into one
//! event, as configured by a rule's `multiline` table.
//!
//! A line is a *continuation* when it matches `pattern`, or when it does not and `negate` is
//! set. With `match = "after"` continuation lines join the line before them; with
//! `match = "before"` they join the next line that is not a continuation. An event is also
//! finished after `max_lines` lines, when it would exceed the rule's `max_line_bytes` (the
//! rest is cut and the event marked truncated), and by the collector when no line has
//! arrived for a while ([`FLUSH_AFTER`]).
//!
//! The assembler records the file offset where the pending event starts so the collector can
//! checkpoint there: after a restart the pending lines are read and joined again.

use std::time::Duration;

use crate::compile::{self, MAX_PATTERN_CHARS};
use crate::{MultilineConfig, MultilineMatch};

/// How long a pending event waits for more lines before it is sent anyway.
pub const FLUSH_AFTER: Duration = Duration::from_secs(3);
/// Upper bound for `max_lines`.
pub const MAX_LINES_LIMIT: u32 = 10_000;

/// A compiled `multiline` table.
#[derive(Debug, Clone)]
pub struct Multiline {
    pattern: regex::bytes::Regex,
    negate: bool,
    match_: MultilineMatch,
    max_lines: usize,
}

impl Multiline {
    pub fn new(config: &MultilineConfig) -> Result<Self, String> {
        if !(1..=MAX_LINES_LIMIT).contains(&config.max_lines) {
            return Err(format!(
                "multiline.max_lines must be between 1 and {MAX_LINES_LIMIT}"
            ));
        }
        Ok(Self {
            pattern: compile::bytes_regex("multiline.pattern", &config.pattern, MAX_PATTERN_CHARS)?,
            negate: config.negate,
            match_: config.match_,
            max_lines: config.max_lines as usize,
        })
    }

    fn is_continuation(&self, line: &[u8]) -> bool {
        self.pattern.is_match(line) != self.negate
    }
}

/// One finished event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assembled {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

/// Per-file assembly state.
#[derive(Debug)]
pub struct Assembler {
    max_bytes: usize,
    pending: Vec<u8>,
    lines: usize,
    truncated: bool,
    /// File offset of the first pending line.
    start: u64,
}

impl Assembler {
    /// `max_bytes` caps one assembled event (the rule's `max_line_bytes`).
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            pending: Vec::new(),
            lines: 0,
            truncated: false,
            start: 0,
        }
    }

    /// File offset where the pending (unfinished) event starts, if there is one.
    pub fn pending_start(&self) -> Option<u64> {
        (self.lines > 0).then_some(self.start)
    }

    /// Feed one line that starts at file offset `start`. Finished events go to `out`.
    pub fn push(
        &mut self,
        ml: &Multiline,
        line: &[u8],
        truncated: bool,
        start: u64,
        out: &mut Vec<Assembled>,
    ) {
        let continuation = ml.is_continuation(line);
        match ml.match_ {
            MultilineMatch::After => {
                if !continuation {
                    self.flush(out);
                }
                self.append(line, truncated, start);
            }
            MultilineMatch::Before => {
                self.append(line, truncated, start);
                if !continuation {
                    self.flush(out);
                }
            }
        }
        if self.lines >= ml.max_lines {
            self.flush(out);
        }
    }

    /// Finish the pending event, if any.
    pub fn flush(&mut self, out: &mut Vec<Assembled>) {
        if self.lines == 0 {
            return;
        }
        out.push(Assembled {
            bytes: std::mem::take(&mut self.pending),
            truncated: std::mem::take(&mut self.truncated),
        });
        self.lines = 0;
    }

    fn append(&mut self, line: &[u8], truncated: bool, start: u64) {
        if self.lines == 0 {
            self.start = start;
        } else if self.pending.len() < self.max_bytes {
            self.pending.push(b'\n');
        } else {
            self.truncated = true;
        }
        let room = self.max_bytes.saturating_sub(self.pending.len());
        if line.len() > room {
            self.truncated = true;
        }
        self.pending
            .extend_from_slice(&line[..line.len().min(room)]);
        self.truncated |= truncated;
        self.lines += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ml(toml_text: &str) -> Multiline {
        let config: MultilineConfig = toml::from_str(toml_text).expect("config");
        Multiline::new(&config).expect("multiline")
    }

    /// Feed lines (offsets are line numbers), then flush; returns the events.
    fn run(m: &Multiline, lines: &[&str], max_bytes: usize) -> Vec<String> {
        let mut a = Assembler::new(max_bytes);
        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            a.push(m, line.as_bytes(), false, i as u64, &mut out);
        }
        a.flush(&mut out);
        out.into_iter()
            .map(|e| String::from_utf8(e.bytes).expect("utf8"))
            .collect()
    }

    const TRACE: &[&str] = &[
        "2026-10-21 08:00:00 ERROR boom",
        "Traceback (most recent call last):",
        "  File \"app.py\", line 1",
        "2026-10-21 08:00:01 INFO ok",
    ];

    #[test]
    fn negate_after_joins_lines_without_a_timestamp() {
        let m = ml(r#"pattern = '^\d{4}-'
negate = true
match = "after""#);
        assert_eq!(
            run(&m, TRACE, 65536),
            [
                "2026-10-21 08:00:00 ERROR boom\nTraceback (most recent call last):\n  File \"app.py\", line 1",
                "2026-10-21 08:00:01 INFO ok"
            ]
        );
    }

    #[test]
    fn after_joins_indented_lines() {
        let m = ml(r"pattern = '^\s'");
        assert_eq!(
            run(&m, &["a", "  b", "  c", "d", "e", "  f"], 65536),
            ["a\n  b\n  c", "d", "e\n  f"]
        );
        // A continuation with nothing before it stands alone.
        assert_eq!(run(&m, &["  x", "y"], 65536), ["  x", "y"]);
    }

    #[test]
    fn before_joins_lines_ending_with_a_backslash() {
        let m = ml(r#"pattern = '\\$'
match = "before""#);
        assert_eq!(
            run(&m, &["one \\", "two \\", "three", "four"], 65536),
            ["one \\\ntwo \\\nthree", "four"]
        );
    }

    #[test]
    fn max_lines_and_max_bytes() {
        let m = ml(r#"pattern = '^\s'
max_lines = 2"#);
        assert_eq!(
            run(&m, &["a", " b", " c", " d"], 65536),
            ["a\n b", " c\n d"]
        );

        let m = ml(r"pattern = '^\s'");
        let mut a = Assembler::new(8);
        let mut out = Vec::new();
        for (i, line) in ["start", " more", " evenmore"].iter().enumerate() {
            a.push(&m, line.as_bytes(), false, i as u64, &mut out);
        }
        a.flush(&mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].bytes, b"start\n m");
        assert!(out[0].truncated);
    }

    #[test]
    fn pending_start_tracks_the_first_unfinished_line() {
        let m = ml(r"pattern = '^\s'");
        let mut a = Assembler::new(1024);
        let mut out = Vec::new();
        assert_eq!(a.pending_start(), None);
        a.push(&m, b"a", false, 10, &mut out);
        a.push(&m, b" b", false, 12, &mut out);
        assert_eq!(a.pending_start(), Some(10));
        a.push(&m, b"c", false, 15, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(a.pending_start(), Some(15));
        a.flush(&mut out);
        assert_eq!(a.pending_start(), None);
    }

    #[test]
    fn invalid_settings() {
        for bad in [
            "pattern = '('",
            "pattern = ''",
            "pattern = 'a'\nmax_lines = 0",
            "pattern = 'a'\nmax_lines = 10001",
        ] {
            let config: MultilineConfig = toml::from_str(bad).expect("parses");
            assert!(Multiline::new(&config).is_err(), "{bad}");
        }
        for bad in [
            "pattern = 'a'\nmatch = \"around\"",
            "negate = true",
            "pattern = 'a'\nx = 1",
        ] {
            assert!(toml::from_str::<MultilineConfig>(bad).is_err(), "{bad}");
        }
    }
}
