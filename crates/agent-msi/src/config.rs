//! Setting `[agent] endpoint` and `presets` in an existing `agent.toml` from the MSI
//! properties, keeping everything else in the file (comments, other settings, rules) as it is.
//!
//! The edit is line based: the installer only ever writes two keys, and the agent's own
//! `check-config` validates the result before it replaces the file.

/// The comment written above the keys the installer sets.
pub const MARKER: &str =
    "# Set by the Wedgetail Agent installer (ENDPOINT and PRESETS properties).";

/// A TOML basic string holding `value`.
pub fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The TOML value for the PRESETS property: `auto`, `none` (no presets) or a comma-separated
/// list of preset ids. `None` when the property is empty (leave `presets` as it is).
pub fn presets_value(property: &str) -> Result<Option<String>, String> {
    let property = property.trim();
    if property.is_empty() {
        return Ok(None);
    }
    if property.eq_ignore_ascii_case("auto") {
        return Ok(Some("\"auto\"".into()));
    }
    if property.eq_ignore_ascii_case("none") {
        return Ok(Some("[]".into()));
    }
    let mut ids = Vec::new();
    for id in property
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        let valid = id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'));
        if !valid || id.len() > 64 {
            return Err(format!(
                "PRESETS: {id:?} is not a preset id (expected auto, none or a comma-separated \
                 list such as windows-security,windows-powershell)"
            ));
        }
        ids.push(toml_string(id));
    }
    if ids.is_empty() {
        return Err("PRESETS: no preset ids".into());
    }
    Ok(Some(format!("[{}]", ids.join(", "))))
}

/// The header's table name for `[name]`, `None` for an array of tables (`[[name]]`) or a line
/// that is not a header.
fn table_name(trimmed: &str) -> Option<&str> {
    if trimmed.starts_with("[[") {
        return None;
    }
    let rest = trimmed.strip_prefix('[')?;
    let end = rest.find(']')?;
    Some(rest[..end].trim())
}

/// The bare key of a `key = value` line, if any.
fn line_key(trimmed: &str) -> Option<&str> {
    let (key, _) = trimmed.split_once('=')?;
    let key = key.trim();
    (!key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    .then_some(key)
}

/// Unclosed `[` minus `]` on a line, outside strings and comments: how far a multi-line array
/// value is from its end.
fn bracket_depth(line: &str) -> i32 {
    let mut depth = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in line.chars() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '#' => break,
                '[' => depth += 1,
                ']' => depth -= 1,
                _ => {}
            },
        }
    }
    depth
}

/// `original` with `keys` (name, TOML value) set in its `[agent]` table: earlier values of
/// those keys in `[agent]` (and the deprecated top-level `endpoint`) are removed and the new
/// ones written right after the `[agent]` header. Without an `[agent]` table one is added
/// before the first table. Line endings follow the file; applying the same keys twice gives
/// the same file.
pub fn set_agent_keys(original: &str, keys: &[(&str, String)]) -> String {
    let newline = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let new_lines: Vec<String> = std::iter::once(MARKER.to_owned())
        .chain(keys.iter().map(|(k, v)| format!("{k} = {v}")))
        .collect();

    #[derive(PartialEq)]
    enum Section {
        Top,
        Agent,
        Other,
    }
    let mut section = Section::Top;
    let mut out: Vec<String> = Vec::new();
    let mut first_header: Option<usize> = None;
    let mut inserted = false;
    // Lines of a removed multi-line value still to skip.
    let mut skip_depth = 0;

    for line in original.lines() {
        if skip_depth > 0 {
            skip_depth += bracket_depth(line);
            continue;
        }
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            first_header.get_or_insert(out.len());
            section = match table_name(trimmed) {
                Some("agent") => Section::Agent,
                _ => Section::Other,
            };
            out.push(line.to_owned());
            if section == Section::Agent && !inserted {
                out.extend(new_lines.iter().cloned());
                inserted = true;
            }
            continue;
        }
        if section != Section::Other {
            if trimmed == MARKER {
                continue;
            }
            if let Some(key) = line_key(trimmed)
                && keys.iter().any(|(k, _)| *k == key)
            {
                skip_depth = bracket_depth(trimmed).max(0);
                continue;
            }
        }
        out.push(line.to_owned());
    }

    if !inserted {
        let mut block = vec!["[agent]".to_owned()];
        block.extend(new_lines);
        match first_header {
            Some(at) => {
                block.push(String::new());
                out.splice(at..at, block);
            }
            None => {
                if out.last().is_some_and(|l| !l.trim().is_empty()) {
                    out.push(String::new());
                }
                out.extend(block);
            }
        }
    }
    let mut text = out.join(newline);
    text.push_str(newline);
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACKAGED: &str = include_str!("../../../packaging/common/agent.toml");

    fn agent_table(text: &str) -> toml::Table {
        let parsed: toml::Table = toml::from_str(text).expect("valid TOML");
        parsed["agent"].as_table().expect("[agent]").clone()
    }

    fn keys(endpoint: &str, presets: Option<&str>) -> Vec<(&'static str, String)> {
        let mut keys = vec![("endpoint", toml_string(endpoint))];
        if let Some(p) = presets {
            keys.push((
                "presets",
                presets_value(p).expect("valid").expect("not empty"),
            ));
        }
        keys
    }

    #[test]
    fn packaged_file_gets_endpoint_and_presets() {
        let out = set_agent_keys(
            PACKAGED,
            &keys(
                "https://ingest.example.com/",
                Some("windows-security,windows-sysmon"),
            ),
        );
        let agent = agent_table(&out);
        assert_eq!(
            agent["endpoint"].as_str(),
            Some("https://ingest.example.com/")
        );
        let presets: Vec<_> = agent["presets"]
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(presets, ["windows-security", "windows-sysmon"]);
        assert_eq!(agent["buffer_max_mb"].as_integer(), Some(256));
        // Comments and the rest of the file are kept.
        assert!(out.contains("# Your own rules."));
        assert_eq!(out.matches("presets =").count(), 1);
    }

    #[test]
    fn applying_twice_is_the_same_as_once() {
        let k = keys("https://a.example.com", Some("auto"));
        let once = set_agent_keys(PACKAGED, &k);
        assert_eq!(set_agent_keys(&once, &k), once);
        // A new endpoint replaces the old one.
        let again = set_agent_keys(&once, &keys("https://b.example.com", None));
        assert_eq!(
            agent_table(&again)["endpoint"].as_str(),
            Some("https://b.example.com")
        );
        assert_eq!(
            again
                .lines()
                .filter(|l| l.starts_with("endpoint ="))
                .count(),
            1
        );
        assert_eq!(again.matches(MARKER).count(), 1);
        // presets was not given this time, so the earlier value stays.
        assert_eq!(agent_table(&again)["presets"].as_str(), Some("auto"));
    }

    #[test]
    fn multi_line_values_and_the_top_level_endpoint_are_replaced() {
        let text = "endpoint = \"https://old.example.com\"\n\
                    [agent]\n\
                    presets = [\n  \"linux-core\", # [x]\n  \"linux-auditd\",\n]\n\
                    buffer_max_mb = 64\n\
                    [[rule]]\nid = \"app\"\ntype = \"wineventlog\"\nchannel = \"Application\"\n\
                    endpoint = \"not touched outside [agent]\"\n";
        let out = set_agent_keys(text, &keys("https://new.example.com", Some("none")));
        let parsed: toml::Table = toml::from_str(&out).expect("valid TOML");
        assert!(!parsed.contains_key("endpoint"));
        let agent = parsed["agent"].as_table().expect("[agent]");
        assert_eq!(agent["endpoint"].as_str(), Some("https://new.example.com"));
        assert_eq!(agent["presets"].as_array().map(Vec::len), Some(0));
        assert_eq!(agent["buffer_max_mb"].as_integer(), Some(64));
        assert!(out.contains("endpoint = \"not touched outside [agent]\""));
    }

    #[test]
    fn agent_table_is_added_when_missing() {
        let text = "schema_version = 1\n\n[[rule]]\nid = \"app\"\ntype = \"wineventlog\"\nchannel = \"Application\"\n";
        let out = set_agent_keys(text, &keys("https://x.example.com", None));
        assert!(out.starts_with("schema_version = 1\n\n[agent]\n"));
        assert_eq!(
            agent_table(&out)["endpoint"].as_str(),
            Some("https://x.example.com")
        );
        let parsed: toml::Table = toml::from_str(&out).expect("valid TOML");
        assert_eq!(parsed["rule"].as_array().map(Vec::len), Some(1));

        let out = set_agent_keys("", &keys("https://x.example.com", None));
        assert_eq!(
            agent_table(&out)["endpoint"].as_str(),
            Some("https://x.example.com")
        );
        let out = set_agent_keys("schema_version = 1", &keys("https://x.example.com", None));
        assert_eq!(
            agent_table(&out)["endpoint"].as_str(),
            Some("https://x.example.com")
        );
    }

    #[test]
    fn crlf_line_endings_are_kept() {
        let text = "schema_version = 1\r\n[agent]\r\nendpoint = \"https://old\"\r\n";
        let out = set_agent_keys(text, &keys("https://new.example.com", None));
        assert!(!out.replace("\r\n", "").contains('\n'));
        assert_eq!(
            agent_table(&out)["endpoint"].as_str(),
            Some("https://new.example.com")
        );
    }

    #[test]
    fn strings_are_escaped() {
        assert_eq!(toml_string(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(toml_string("a\nb\u{1}"), "\"a\\nb\\u0001\"");
        let out = set_agent_keys("", &[("endpoint", toml_string("https://x\"\n[agent]"))]);
        assert_eq!(
            agent_table(&out)["endpoint"].as_str(),
            Some("https://x\"\n[agent]")
        );
    }

    #[test]
    fn presets_property() {
        assert_eq!(presets_value("").expect("ok"), None);
        assert_eq!(
            presets_value(" AUTO ").expect("ok").as_deref(),
            Some("\"auto\"")
        );
        assert_eq!(presets_value("none").expect("ok").as_deref(), Some("[]"));
        assert_eq!(
            presets_value("windows-security, auto,")
                .expect("ok")
                .as_deref(),
            Some("[\"windows-security\", \"auto\"]")
        );
        assert!(presets_value("windows security").is_err());
        assert!(presets_value("a\"]").is_err());
        assert!(presets_value(",").is_err());
    }
}
