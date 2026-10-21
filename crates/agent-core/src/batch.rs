//! Encoding buffered records into gzip NDJSON request bodies within the server limits.

use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;

/// Per-request limits. Defaults are the server's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchLimits {
    /// Largest gzip body (server: 1 MiB).
    pub max_compressed_bytes: usize,
    /// Largest body before compression (server: 8 MiB).
    pub max_uncompressed_bytes: usize,
    /// Most records (server: 5,000).
    pub max_records: usize,
}

impl From<&agent_config::Limits> for BatchLimits {
    fn from(l: &agent_config::Limits) -> Self {
        Self {
            max_compressed_bytes: usize::try_from(l.max_batch_bytes).unwrap_or(usize::MAX),
            max_uncompressed_bytes: usize::try_from(l.max_batch_uncompressed_bytes)
                .unwrap_or(usize::MAX),
            max_records: l.max_batch_records as usize,
        }
    }
}

impl Default for BatchLimits {
    fn default() -> Self {
        (&agent_config::Limits::default()).into()
    }
}

/// A request body holding the first `records` lines.
#[derive(Debug)]
pub struct Encoded {
    pub records: usize,
    pub body: Vec<u8>,
}

/// The first line cannot fit in a request on its own.
#[derive(Debug, PartialEq, Eq)]
pub struct Oversize;

/// Encode the longest prefix of `lines` that fits all three limits.
///
/// The record and uncompressed limits are exact. For the compressed limit the prefix is
/// encoded, and if too large, shrunk in proportion to the overshoot (with a margin) and
/// encoded again, which converges in one or two rounds for log data.
pub fn encode(lines: &[Vec<u8>], limits: &BatchLimits) -> Result<Encoded, Oversize> {
    let mut n = 0;
    let mut raw = 0usize;
    for line in lines.iter().take(limits.max_records) {
        if raw + line.len() + 1 > limits.max_uncompressed_bytes {
            break;
        }
        raw += line.len() + 1;
        n += 1;
    }
    if n == 0 {
        return Err(Oversize);
    }
    loop {
        let body = gzip(&lines[..n]);
        if body.len() <= limits.max_compressed_bytes {
            return Ok(Encoded { records: n, body });
        }
        if n == 1 {
            return Err(Oversize);
        }
        let scaled = (n as u128 * limits.max_compressed_bytes as u128 * 9 / 10 / body.len() as u128)
            as usize;
        n = scaled.clamp(1, n - 1);
    }
}

/// Gzip NDJSON: each line followed by `\n`.
pub fn gzip(lines: &[Vec<u8>]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    for line in lines {
        // Writing to a Vec cannot fail.
        let _ = enc.write_all(line);
        let _ = enc.write_all(b"\n");
    }
    enc.finish().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use flate2::read::GzDecoder;

    use super::*;

    fn gunzip(body: &[u8]) -> String {
        let mut out = String::new();
        GzDecoder::new(body)
            .read_to_string(&mut out)
            .expect("gunzip");
        out
    }

    fn small_lines(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| format!(r#"{{"v":1,"n":{i}}}"#).into_bytes())
            .collect()
    }

    /// Incompressible lines of `len` bytes (hex of a xorshift stream).
    fn random_lines(n: usize, len: usize) -> Vec<Vec<u8>> {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        (0..n)
            .map(|_| {
                (0..len)
                    .map(|_| {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        b"0123456789abcdef"[(x & 15) as usize]
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn splits_at_record_limit() {
        let lines = small_lines(5_001);
        let limits = BatchLimits::default();
        let first = encode(&lines, &limits).expect("fits");
        assert_eq!(first.records, 5_000);
        let rest = encode(&lines[first.records..], &limits).expect("fits");
        assert_eq!(rest.records, 1);
        let text = gunzip(&first.body);
        assert_eq!(text.lines().count(), 5_000);
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn splits_at_uncompressed_limit() {
        // Highly compressible lines: the 8 MiB raw limit binds before 1 MiB compressed.
        let lines: Vec<Vec<u8>> = (0..4_000).map(|_| vec![b'a'; 4 * 1024]).collect();
        let limits = BatchLimits::default();
        let first = encode(&lines, &limits).expect("fits");
        let raw: usize = lines[..first.records].iter().map(|l| l.len() + 1).sum();
        assert!(raw <= 8 * 1024 * 1024);
        assert!(raw + lines[first.records].len() + 1 > 8 * 1024 * 1024);
        assert!(first.body.len() < 1024 * 1024);
    }

    #[test]
    fn splits_at_compressed_limit() {
        let lines = random_lines(4_000, 1_000);
        let limits = BatchLimits::default();
        let mut offset = 0;
        let mut batches = 0;
        while offset < lines.len() {
            let enc = encode(&lines[offset..], &limits).expect("fits");
            assert!(enc.body.len() <= 1024 * 1024, "{}", enc.body.len());
            assert_eq!(gunzip(&enc.body).lines().count(), enc.records);
            offset += enc.records;
            batches += 1;
        }
        // ~4 MB of hex compresses about 2:1, so several requests, each reasonably full.
        assert!((2..=6).contains(&batches), "{batches}");
    }

    #[test]
    fn single_oversize_record_is_reported() {
        let limits = BatchLimits {
            max_compressed_bytes: 1024,
            max_uncompressed_bytes: 1 << 20,
            max_records: 10,
        };
        assert_eq!(
            encode(&random_lines(1, 4096), &limits).expect_err("oversize"),
            Oversize
        );
        let limits = BatchLimits {
            max_compressed_bytes: 1 << 20,
            max_uncompressed_bytes: 100,
            max_records: 10,
        };
        assert_eq!(
            encode(&random_lines(1, 200), &limits).expect_err("oversize"),
            Oversize
        );
        assert_eq!(encode(&[], &limits).expect_err("oversize"), Oversize);
    }
}
