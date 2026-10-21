//! Line parsers: turn a raw line into the event's `fields`.
//!
//! Every parser is linear in the input and bounded: lines are already cut to the rule's
//! `max_line_bytes`, and the parsers cap how many fields they produce. A line a parser does
//! not recognise returns `None`; the pipeline keeps the event with its `body` and marks
//! `attrs.parse_error`.
//!
//! Field names per parser are listed in `docs/rules.md` and pinned by the golden files in
//! `tests/parsers/`.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::ParserKind;
use crate::compile::{self, MAX_PARSER_REGEX_CHARS};

/// Most fields a `logfmt` line or CEF extension produces; the rest are ignored.
pub const MAX_FIELDS: usize = 256;

/// A ready-to-run parser.
#[derive(Debug, Clone)]
pub enum Parser {
    Raw,
    Json,
    SyslogRfc3164,
    SyslogRfc5424,
    Cef,
    Logfmt,
    Regex(Regex),
    NginxCombined,
    ApacheCombined,
}

impl Parser {
    /// Build the parser for `kind`. `regex` is required for, and only allowed with,
    /// [`ParserKind::Regex`].
    pub fn new(kind: ParserKind, regex: Option<&str>) -> Result<Self, String> {
        match (kind, regex) {
            (ParserKind::Regex, Some(pattern)) => {
                let re = compile::regex("regex", pattern, MAX_PARSER_REGEX_CHARS)?;
                if re.capture_names().flatten().next().is_none() {
                    return Err(
                        "regex: needs at least one named capture, for example (?P<user>\\S+)"
                            .into(),
                    );
                }
                Ok(Self::Regex(re))
            }
            (ParserKind::Regex, None) => Err("parser \"regex\" needs a regex".into()),
            (_, Some(_)) => Err("regex is only used with parser = \"regex\"".into()),
            (ParserKind::Raw, None) => Ok(Self::Raw),
            (ParserKind::Json, None) => Ok(Self::Json),
            (ParserKind::SyslogRfc3164, None) => Ok(Self::SyslogRfc3164),
            (ParserKind::SyslogRfc5424, None) => Ok(Self::SyslogRfc5424),
            (ParserKind::Cef, None) => Ok(Self::Cef),
            (ParserKind::Logfmt, None) => Ok(Self::Logfmt),
            (ParserKind::NginxCombined, None) => Ok(Self::NginxCombined),
            (ParserKind::ApacheCombined, None) => Ok(Self::ApacheCombined),
        }
    }

    pub fn is_raw(&self) -> bool {
        matches!(self, Self::Raw)
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Json => "json",
            Self::SyslogRfc3164 => "syslog_rfc3164",
            Self::SyslogRfc5424 => "syslog_rfc5424",
            Self::Cef => "cef",
            Self::Logfmt => "logfmt",
            Self::Regex(_) => "regex",
            Self::NginxCombined => "nginx_combined",
            Self::ApacheCombined => "apache_combined",
        }
    }

    /// Parse one line (or one assembled multiline event). `None` if it does not fit the
    /// format; `raw` always returns an empty map.
    pub fn parse(&self, line: &str) -> Option<Map<String, Value>> {
        match self {
            Self::Raw => Some(Map::new()),
            Self::Json => json(line),
            Self::SyslogRfc3164 => syslog_rfc3164(line),
            Self::SyslogRfc5424 => syslog_rfc5424(line),
            Self::Cef => cef(line),
            Self::Logfmt => logfmt(line),
            Self::Regex(re) => regex_captures(re, line),
            Self::NginxCombined => access_log(line, false),
            Self::ApacheCombined => access_log(line, true),
        }
    }
}

/// Compile one of the built-in expressions. They are constants covered by tests.
fn builtin(pattern: &str) -> Regex {
    #[allow(clippy::unwrap_used)]
    Regex::new(pattern).unwrap()
}

fn json(line: &str) -> Option<Map<String, Value>> {
    // serde_json limits nesting to 128 levels.
    match serde_json::from_str(line.trim()) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    }
}

fn put_str(fields: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() && value != "-" {
        fields.insert(key.to_owned(), Value::from(value));
    }
}

/// `<PRI>` as priority, facility and severity. PRI is at most 191.
fn put_pri(fields: &mut Map<String, Value>, pri: &str) -> Option<()> {
    let pri: u32 = pri.parse().ok().filter(|p| *p <= 191)?;
    fields.insert("priority".into(), pri.into());
    fields.insert("facility".into(), (pri / 8).into());
    fields.insert("severity".into(), (pri % 8).into());
    Some(())
}

static RFC3164: LazyLock<Regex> = LazyLock::new(|| {
    builtin(concat!(
        r"(?s)^(?:<(?P<pri>\d{1,3})>)?",
        r"(?P<timestamp>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}",
        r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2}))",
        r" +(?P<hostname>\S+) +(?P<rest>.*)$",
    ))
});

static SYSLOG_TAG: LazyLock<Regex> = LazyLock::new(|| {
    builtin(r"(?s)^(?P<app>[^\s\[\]:]{1,128})(?:\[(?P<pid>[^\]\s]{1,32})\])?: ?(?P<msg>.*)$")
});

/// BSD syslog as written to `/var/log/syslog`, `auth.log` and `secure`: optional `<PRI>`, a
/// `Mmm dd hh:mm:ss` or RFC 3339 time, host, then `tag[pid]: message`. A line without a tag
/// keeps everything after the host as `message`.
fn syslog_rfc3164(line: &str) -> Option<Map<String, Value>> {
    let caps = RFC3164.captures(line)?;
    let mut fields = Map::new();
    if let Some(pri) = caps.name("pri") {
        put_pri(&mut fields, pri.as_str())?;
    }
    put_str(&mut fields, "timestamp", &caps["timestamp"]);
    put_str(&mut fields, "hostname", &caps["hostname"]);
    let rest = &caps["rest"];
    match SYSLOG_TAG.captures(rest) {
        Some(tag) => {
            put_str(&mut fields, "app_name", &tag["app"]);
            if let Some(pid) = tag.name("pid") {
                put_str(&mut fields, "proc_id", pid.as_str());
            }
            fields.insert("message".into(), Value::from(&tag["msg"]));
        }
        None => {
            fields.insert("message".into(), Value::from(rest));
        }
    }
    Some(fields)
}

/// Split off the next space-separated token.
fn token(s: &str) -> Option<(&str, &str)> {
    let (tok, rest) = s.split_once(' ').unwrap_or((s, ""));
    (!tok.is_empty()).then_some((tok, rest))
}

/// RFC 5424: `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [MSG]`.
/// `-` (nil) values are left out. Structured data becomes
/// `structured_data: {sd_id: {param: value}}`.
fn syslog_rfc5424(line: &str) -> Option<Map<String, Value>> {
    let rest = line.strip_prefix('<')?;
    let (pri, rest) = rest.split_once('>')?;
    if pri.is_empty() || pri.len() > 3 || !pri.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut fields = Map::new();
    put_pri(&mut fields, pri)?;
    let (version, rest) = token(rest)?;
    let version: u32 = version
        .parse()
        .ok()
        .filter(|v| (1..=99).contains(v) && !version.starts_with('0'))?;
    fields.insert("version".into(), version.into());
    let mut rest = rest;
    for (name, max) in [
        ("timestamp", 64),
        ("hostname", 255),
        ("app_name", 48),
        ("proc_id", 128),
        ("msg_id", 32),
    ] {
        let (tok, r) = token(rest)?;
        if tok.len() > max {
            return None;
        }
        put_str(&mut fields, name, tok);
        rest = r;
    }
    let rest = if let Some(r) = rest.strip_prefix('-') {
        r
    } else {
        let (sd, r) = structured_data(rest)?;
        fields.insert("structured_data".into(), Value::Object(sd));
        r
    };
    match rest.strip_prefix(' ') {
        Some(msg) => {
            let msg = msg.strip_prefix('\u{feff}').unwrap_or(msg);
            fields.insert("message".into(), Value::from(msg));
        }
        None if rest.is_empty() => {}
        None => return None,
    }
    Some(fields)
}

/// One or more `[id name="value" ...]` elements. Returns the parsed elements and the rest.
fn structured_data(s: &str) -> Option<(Map<String, Value>, &str)> {
    let mut out = Map::new();
    let mut rest = s;
    while let Some(r) = rest.strip_prefix('[') {
        let end = r.find([' ', ']'])?;
        let id = &r[..end];
        if id.is_empty() || id.len() > 32 || id.contains(['=', '"']) {
            return None;
        }
        let mut params = Map::new();
        let mut r = &r[end..];
        loop {
            if let Some(after) = r.strip_prefix(']') {
                r = after;
                break;
            }
            r = r.strip_prefix(' ')?;
            let eq = r.find('=')?;
            let name = &r[..eq];
            if name.is_empty() || name.len() > 32 || name.contains([' ', ']', '"']) {
                return None;
            }
            let (value, after) = quoted(r[eq + 1..].strip_prefix('"')?, &['"', '\\', ']'])?;
            if params.len() < MAX_FIELDS {
                params.insert(name.to_owned(), Value::from(value));
            }
            r = after;
        }
        if out.len() < MAX_FIELDS {
            out.insert(id.to_owned(), Value::Object(params));
        }
        rest = r;
    }
    (!out.is_empty()).then_some((out, rest))
}

/// Read a quoted string body up to the closing `"`, undoing `\x` for the escapable characters
/// (other backslashes are kept). Returns the value and the text after the quote.
fn quoted<'a>(s: &'a str, escapable: &[char]) -> Option<(String, &'a str)> {
    let mut out = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, &s[i + 1..])),
            '\\' => match chars.next() {
                Some((_, n)) if escapable.contains(&n) => out.push(n),
                Some((_, n)) => {
                    out.push('\\');
                    out.push(n);
                }
                None => return None,
            },
            c => out.push(c),
        }
    }
    None
}

/// CEF: `CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension`, optionally
/// after a syslog header. Header fields unescape `\|` and `\\`; the extension's `key=value`
/// pairs go to `extensions` and unescape `\=`, `\\`, `\n` and `\r`.
fn cef(line: &str) -> Option<Map<String, Value>> {
    let start = line
        .match_indices("CEF:")
        .map(|(i, _)| i)
        .find(|&i| i == 0 || line[..i].ends_with([' ', '\t']))?;
    let mut rest = &line[start + 4..];
    let mut header = Vec::with_capacity(7);
    while header.len() < 7 {
        let mut value = String::new();
        let mut chars = rest.char_indices();
        let mut end = None;
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some((_, n @ ('|' | '\\'))) => value.push(n),
                    Some((_, n)) => {
                        value.push('\\');
                        value.push(n);
                    }
                    None => value.push('\\'),
                },
                '|' => {
                    end = Some(i);
                    break;
                }
                c => value.push(c),
            }
        }
        let end = end?;
        header.push(value);
        rest = &rest[end + 1..];
    }
    let names = [
        "cef_version",
        "device_vendor",
        "device_product",
        "device_version",
        "signature_id",
        "name",
        "severity",
    ];
    if !header[0].bytes().all(|b| b.is_ascii_digit()) || header[0].is_empty() {
        return None;
    }
    let mut fields = Map::new();
    for (name, value) in names.iter().zip(header) {
        fields.insert((*name).to_owned(), Value::from(value));
    }
    let extensions = cef_extensions(rest);
    if !extensions.is_empty() {
        fields.insert("extensions".into(), Value::Object(extensions));
    }
    Some(fields)
}

fn is_cef_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'[' | b']')
}

/// Extension keys are word characters followed by an unescaped `=` at the start or after a
/// space; a value runs to the next key.
fn cef_extensions(s: &str) -> Map<String, Value> {
    let bytes = s.as_bytes();
    // (key start, key end, value start)
    let mut keys = Vec::new();
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' => escaped = true,
            b'=' => {
                let mut k = i;
                while k > 0 && i - k < 64 && is_cef_key_byte(bytes[k - 1]) {
                    k -= 1;
                }
                if k < i && (k == 0 || bytes[k - 1] == b' ') {
                    keys.push((k, i, i + 1));
                }
            }
            _ => {}
        }
    }
    let mut out = Map::new();
    for (n, &(ks, ke, vs)) in keys.iter().enumerate() {
        if out.len() >= MAX_FIELDS {
            break;
        }
        let ve = keys.get(n + 1).map_or(bytes.len(), |next| next.0);
        let raw = s[vs..ve].trim_end_matches(' ');
        let mut value = String::with_capacity(raw.len());
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                value.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => value.push('\n'),
                Some('r') => value.push('\r'),
                Some(n @ ('=' | '\\' | '|')) => value.push(n),
                Some(n) => {
                    value.push('\\');
                    value.push(n);
                }
                None => value.push('\\'),
            }
        }
        out.insert(s[ks..ke].to_owned(), Value::from(value));
    }
    out
}

/// logfmt: `key=value`, `key="quoted \"value\""`, or a bare `key` (true). Fails on a pair
/// with an empty key or an unterminated quote.
fn logfmt(line: &str) -> Option<Map<String, Value>> {
    let mut fields = Map::new();
    let mut rest = line.trim_start();
    while !rest.is_empty() {
        let key_end = rest.find(['=', ' ', '\t']).unwrap_or(rest.len());
        let key = &rest[..key_end];
        if key.is_empty() || key.contains('"') {
            return None;
        }
        rest = &rest[key_end..];
        let value = if let Some(r) = rest.strip_prefix('=') {
            if let Some(q) = r.strip_prefix('"') {
                let (value, after) = quoted_logfmt(q)?;
                rest = after;
                Value::from(value)
            } else {
                let end = r.find([' ', '\t']).unwrap_or(r.len());
                rest = &r[end..];
                Value::from(&r[..end])
            }
        } else {
            Value::Bool(true)
        };
        if fields.len() < MAX_FIELDS {
            fields.insert(key.to_owned(), value);
        }
        rest = rest.trim_start();
    }
    (!fields.is_empty()).then_some(fields)
}

/// A logfmt quoted value with Go-style escapes (`\"`, `\\`, `\n`, `\t`, `\r`).
fn quoted_logfmt(s: &str) -> Option<(String, &str)> {
    let mut out = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, &s[i + 1..])),
            '\\' => match chars.next()? {
                (_, 'n') => out.push('\n'),
                (_, 't') => out.push('\t'),
                (_, 'r') => out.push('\r'),
                (_, n) => out.push(n),
            },
            c => out.push(c),
        }
    }
    None
}

fn regex_captures(re: &Regex, line: &str) -> Option<Map<String, Value>> {
    let caps = re.captures(line)?;
    let mut fields = Map::new();
    for name in re.capture_names().flatten() {
        if let Some(m) = caps.name(name) {
            fields.insert(name.to_owned(), Value::from(m.as_str()));
        }
    }
    Some(fields)
}

static ACCESS_LOG: LazyLock<Regex> = LazyLock::new(|| {
    builtin(concat!(
        r#"^(?P<remote_addr>\S+) (?P<ident>\S+) (?P<remote_user>\S+) "#,
        r#"\[(?P<time_local>[^\]]{1,64})\] "#,
        r#""(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\d+|-) "#,
        r#""(?P<referer>(?:[^"\\]|\\.)*)" "(?P<user_agent>(?:[^"\\]|\\.)*)""#,
    ))
});

/// nginx and Apache `combined` access logs. Fields: `remote_addr`, `ident` (Apache only),
/// `remote_user`, `time_local`, `request`, `method`, `path`, `protocol`, `status`,
/// `body_bytes_sent`, `http_referer`, `http_user_agent`. `-` values are left out. Anything
/// after the user agent (extra `log_format` fields) is ignored.
fn access_log(line: &str, apache: bool) -> Option<Map<String, Value>> {
    let caps = ACCESS_LOG.captures(line)?;
    let mut fields = Map::new();
    put_str(&mut fields, "remote_addr", &caps["remote_addr"]);
    if apache {
        put_str(&mut fields, "ident", &caps["ident"]);
    }
    put_str(&mut fields, "remote_user", &caps["remote_user"]);
    put_str(&mut fields, "time_local", &caps["time_local"]);
    let request = &caps["request"];
    put_str(&mut fields, "request", request);
    let parts: Vec<&str> = request.splitn(3, ' ').collect();
    if let [method, path, protocol] = parts[..] {
        put_str(&mut fields, "method", method);
        put_str(&mut fields, "path", path);
        put_str(&mut fields, "protocol", protocol);
    }
    let status: u16 = caps["status"].parse().ok()?;
    fields.insert("status".into(), status.into());
    if let Ok(bytes) = caps["bytes"].parse::<u64>() {
        fields.insert("body_bytes_sent".into(), bytes.into());
    }
    put_str(&mut fields, "http_referer", &caps["referer"]);
    put_str(&mut fields, "http_user_agent", &caps["user_agent"]);
    Some(fields)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse(kind: ParserKind, line: &str) -> Option<Value> {
        Parser::new(kind, None)
            .expect("parser")
            .parse(line)
            .map(Value::Object)
    }

    #[test]
    fn regex_parser_needs_named_captures() {
        assert!(Parser::new(ParserKind::Regex, None).is_err());
        assert!(Parser::new(ParserKind::Regex, Some("(a)")).is_err());
        assert!(Parser::new(ParserKind::Regex, Some("(?P<a>")).is_err());
        assert!(Parser::new(ParserKind::Json, Some("(?P<a>x)")).is_err());
        let p = Parser::new(
            ParserKind::Regex,
            Some(r"user=(?P<user>\w+)(?: id=(?P<id>\d+))?"),
        )
        .expect("parser");
        assert_eq!(
            p.parse("login user=alice").map(Value::Object),
            Some(json!({"user": "alice"}))
        );
        assert_eq!(p.parse("nothing"), None);
    }

    #[test]
    fn hostile_input_is_bounded() {
        let long = "a=1 ".repeat(10_000);
        let fields = parse(ParserKind::Logfmt, &long).expect("logfmt");
        assert!(fields.as_object().is_some_and(|m| m.len() == 1));
        let many: String = (0..1000).map(|i| format!(" k{i}=v")).collect();
        let fields = parse(ParserKind::Logfmt, &many).expect("logfmt");
        assert_eq!(fields.as_object().map(Map::len), Some(MAX_FIELDS));
        let cef_line = format!("CEF:0|a|b|c|d|e|f|{}", "x=".repeat(50_000));
        assert!(parse(ParserKind::Cef, &cef_line).is_some());
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        assert_eq!(parse(ParserKind::Json, &deep), None);
        assert_eq!(parse(ParserKind::SyslogRfc5424, &"[".repeat(10_000)), None);
        assert_eq!(
            parse(
                ParserKind::SyslogRfc5424,
                &format!("<1>1 - - - - - {}", "[a".repeat(5000))
            ),
            None
        );
        for kind in ParserKind::ALL.iter().filter(|k| **k != ParserKind::Regex) {
            for line in [
                "",
                "\0",
                "\u{fffd}\u{fffd}",
                "<999>",
                "CEF:",
                "\"",
                "=",
                "<",
            ] {
                // No panics; raw always parses.
                let _ = parse(*kind, line);
            }
        }
    }
}
