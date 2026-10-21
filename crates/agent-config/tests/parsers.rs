//! Golden-file tests for every parser.
//!
//! `tests/parsers/<parser>.log` holds input lines; `<parser>.golden.ndjson` holds, for each
//! input line, the parsed `fields` as JSON or `null` when the parser does not recognise the
//! line. Regenerate after an intended change with
//! `UPDATE_GOLDEN=1 cargo test -p agent-config --test parsers` and review the diff.

use std::path::Path;

use agent_config::{Parser, ParserKind};
use serde_json::Value;

/// The expression used for `regex.log`.
const REGEX: &str = r"^(?P<ts>\S+) (?P<level>[A-Z]+) \[(?P<thread>[^\]]+)\] (?P<message>.*)$";

#[test]
fn golden_files() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/parsers");
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    let mut failures = Vec::new();
    for kind in ParserKind::ALL {
        let name = kind.name();
        let regex = (*kind == ParserKind::Regex).then_some(REGEX);
        let parser = Parser::new(*kind, regex).expect("parser");
        let input = std::fs::read_to_string(dir.join(format!("{name}.log")))
            .unwrap_or_else(|e| panic!("{name}.log: {e}"));
        let mut out = String::new();
        let mut parsed = 0;
        for line in input.lines() {
            let fields = parser.parse(line).map(Value::Object);
            parsed += usize::from(fields.is_some());
            out.push_str(&serde_json::to_string(&fields).expect("json"));
            out.push('\n');
        }
        assert!(parsed > 0, "{name}: no line parsed");
        let golden = dir.join(format!("{name}.golden.ndjson"));
        if update {
            std::fs::write(&golden, &out).expect("write golden");
        }
        let want = std::fs::read_to_string(&golden)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        if want != out {
            failures.push(format!("{name}:\n--- want\n{want}--- got\n{out}"));
        }
    }
    assert!(
        failures.is_empty(),
        "golden files differ (UPDATE_GOLDEN=1 to regenerate):\n{}",
        failures.join("\n")
    );
}
