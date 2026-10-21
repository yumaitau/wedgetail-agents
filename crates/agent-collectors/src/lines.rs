//! Reading newline-delimited input without trusting its line lengths.

use std::io::{self, BufRead};

/// Read one line into `out` (without the `\n` or a trailing `\r`), keeping at most `max`
/// bytes and discarding the rest of an over-long line. Returns `None` at end of input, else
/// whether the line was truncated.
pub fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    out: &mut Vec<u8>,
    max: usize,
) -> io::Result<Option<bool>> {
    out.clear();
    let mut truncated = false;
    let mut read_any = false;
    loop {
        let buf = match reader.fill_buf() {
            Ok(buf) => buf,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf.is_empty() {
            return Ok(read_any.then_some(truncated));
        }
        read_any = true;
        let (chunk, used, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (&buf[..i], i + 1, true),
            None => (buf, buf.len(), false),
        };
        let room = max.saturating_sub(out.len());
        if chunk.len() > room {
            truncated = true;
        }
        out.extend_from_slice(&chunk[..chunk.len().min(room)]);
        reader.consume(used);
        if done {
            if out.last() == Some(&b'\r') && !truncated {
                out.pop();
            }
            return Ok(Some(truncated));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(input: &[u8], max: usize) -> Vec<(String, bool)> {
        let mut r = io::BufReader::with_capacity(4, input);
        let mut out = Vec::new();
        let mut lines = Vec::new();
        while let Some(t) = read_line_bounded(&mut r, &mut out, max).expect("read") {
            lines.push((String::from_utf8_lossy(&out).into_owned(), t));
        }
        lines
    }

    #[test]
    fn splits_and_truncates() {
        let got = all(b"one\r\ntwo\n0123456789abcdef\nlast", 8);
        assert_eq!(
            got,
            [
                ("one".to_owned(), false),
                ("two".to_owned(), false),
                ("01234567".to_owned(), true),
                ("last".to_owned(), false)
            ]
        );
        assert!(all(b"", 8).is_empty());
        assert_eq!(all(b"\n\n", 8).len(), 2);
    }

    #[test]
    fn huge_line_uses_bounded_memory() {
        let input = vec![b'x'; 10 * 1024 * 1024];
        let mut r = io::BufReader::new(&input[..]);
        let mut out = Vec::new();
        assert_eq!(
            read_line_bounded(&mut r, &mut out, 1024).expect("read"),
            Some(true)
        );
        assert_eq!(out.len(), 1024);
        assert!(out.capacity() < 64 * 1024);
    }
}
