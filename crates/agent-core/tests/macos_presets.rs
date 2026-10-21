//! Golden-file tests for the macOS presets: fixture input goes through the preset rule's
//! collector parsing and the rule pipeline, and must produce exactly the wire NDJSON in
//! `presets/macos/fixtures/expected/<scenario>.ndjson`.
//!
//! Fixtures (`presets/macos/fixtures`, all sanitised: fictional users, hosts, addresses and
//! identifiers):
//! - `unified/<scenario>.ndjson`: `log stream --style ndjson` lines;
//! - `install.log`, `system.log`: file lines;
//! - `bsm/praudit.xml`: `praudit -x -r` output (see the macos_bsm tests).
//!
//! Event times of file rules are the read time; the tests pin them to a fixed value.
//! Regenerate after an intended change with
//! `UPDATE_GOLDEN=1 cargo test -p agent-core --test macos_presets` and review the diff.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agent_collectors::{CollectorEnv, RawEvent, macos_bsm, macos_unified};
use agent_config::{Rule, StartAt};
use agent_core::{Processor, RuleProcessor, Verdict};
use serde::Deserialize;

/// 2026-10-21T08:00:00Z, the time given to file events.
const FILE_TS_US: u64 = 1_792_569_600_000_000;

/// The five scenarios the issue asks for, plus the other unified rules, and their rule.
const UNIFIED: &[(&str, &str)] = &[
    ("failed-sudo", "macos-core.auth"),
    ("ssh-login", "macos-core.auth"),
    ("screen-sharing", "macos-core.auth"),
    ("login-item", "macos-core.persistence"),
    ("gatekeeper-block", "macos-core.gatekeeper"),
];

#[derive(Deserialize)]
struct RuleFile {
    rule: Vec<Rule>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> PathBuf {
    root().join("presets/macos/fixtures")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn preset_rules(name: &str) -> Vec<Rule> {
    let text = read(&root().join(format!("presets/macos/{name}.toml")));
    toml::from_str::<RuleFile>(&text).expect("preset").rule
}

fn rule<'a>(rules: &'a [Rule], id: &str) -> &'a Rule {
    rules
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no rule {id}"))
}

fn wire(processor: &mut RuleProcessor, events: Vec<RawEvent>) -> String {
    let mut out = String::new();
    for event in events {
        if let Verdict::Keep(event) = processor.process(event) {
            out.push_str(&String::from_utf8(event.to_wire_line()).expect("utf8"));
            out.push('\n');
        }
    }
    out
}

/// Read a fixture file with the preset's own `file` rule, from the start.
fn tail(rule: &Rule, fixture: &str, real_path: &str) -> Vec<RawEvent> {
    let dir =
        std::env::temp_dir().join(format!("wt-macos-presets-{}-{fixture}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join(fixture);
    std::fs::write(&path, read(&fixtures().join(fixture))).expect("copy");
    let want = read(&fixtures().join(fixture))
        .lines()
        .filter(|l| !l.starts_with(char::is_whitespace))
        .count();
    let mut rule = rule.clone();
    rule.paths = vec![path];
    rule.start_at = StartAt::Beginning;
    let mut collector =
        agent_collectors::from_rule(&rule, &CollectorEnv::default()).expect("collector");
    collector.start(None).expect("start");
    let mut events = Vec::new();
    // The last multiline event is sent after 3 s without a new line.
    let deadline = Instant::now() + Duration::from_secs(15);
    while events.len() < want && Instant::now() < deadline {
        let batch = collector
            .poll(1000, Duration::from_millis(500))
            .expect("poll");
        events.extend(batch.events);
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(events.len(), want, "{fixture}: events read");
    for e in &mut events {
        e.ts_us = FILE_TS_US;
        e.attrs.insert("path".into(), real_path.into());
    }
    events
}

#[test]
fn golden_files() {
    let core = preset_rules("macos-core");
    let audit = preset_rules("macos-audit");
    let all: Vec<Rule> = core.iter().chain(&audit).cloned().collect();
    let mut processor = RuleProcessor::new(&all).expect("rules");
    let mut outputs: Vec<(String, String)> = Vec::new();

    for (scenario, rule_id) in UNIFIED {
        let template = agent_collectors::EventTemplate::from_rule(rule(&core, rule_id));
        let input = read(&fixtures().join(format!("unified/{scenario}.ndjson")));
        let events = input
            .lines()
            .map(|l| macos_unified::parse_line(l.as_bytes()).expect("fixture line parses"))
            .map(|e| template.event(e.ts_us, None, e.fields))
            .collect();
        outputs.push((scenario.to_string(), wire(&mut processor, events)));
    }

    let install = tail(
        rule(&core, "macos-core.install"),
        "install.log",
        "/var/log/install.log",
    );
    outputs.push(("install".into(), wire(&mut processor, install)));
    let syslog = tail(
        rule(&core, "macos-core.syslog"),
        "system.log",
        "/var/log/system.log",
    );
    outputs.push(("syslog".into(), wire(&mut processor, syslog)));

    let trail = rule(&audit, "macos-audit.trail");
    let template = agent_collectors::EventTemplate::from_rule(trail);
    let table = macos_bsm::EventTable::parse(&read(&fixtures().join("bsm/audit_event")));
    let parsed = macos_bsm::parse_praudit(
        &read(&fixtures().join("bsm/praudit.xml")),
        &table,
        &trail.classes,
    );
    let events = parsed
        .records
        .into_iter()
        .map(|r| {
            let mut e = template.event(r.ts_us, None, r.fields);
            e.attrs.insert(
                "path".into(),
                "/var/audit/20261021080000.not_terminated".into(),
            );
            e
        })
        .collect();
    outputs.push(("bsm".into(), wire(&mut processor, events)));

    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    let mut failures = Vec::new();
    for (name, got) in &outputs {
        assert!(!got.is_empty(), "{name}: no event");
        let golden = fixtures().join(format!("expected/{name}.ndjson"));
        if update {
            std::fs::write(&golden, got).expect("write golden");
        }
        let want = std::fs::read_to_string(&golden)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        if &want != got {
            failures.push(format!("{name}:\n--- want\n{want}--- got\n{got}"));
        }
    }
    assert!(
        failures.is_empty(),
        "golden files differ (UPDATE_GOLDEN=1 to regenerate):\n{}",
        failures.join("\n")
    );
}

/// Every unified rule's predicate is accepted by the real `log` (macOS only).
#[cfg(target_os = "macos")]
#[test]
fn predicates_are_valid() {
    use std::process::{Command, Stdio};
    // `log show` takes seconds to open the store: run them all at once.
    let children: Vec<_> = preset_rules("macos-core")
        .into_iter()
        .filter_map(|r| {
            let predicate = r.predicate.clone()?;
            let child = Command::new("/usr/bin/log")
                .args(["show", "--last", "1s", "--style", "ndjson", "--predicate"])
                .arg(predicate)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("log show");
            Some((r.id, child))
        })
        .collect();
    assert!(!children.is_empty());
    for (id, child) in children {
        let out = child.wait_with_output().expect("log show");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && !stderr.contains("predicate"),
            "{id}: {stderr}"
        );
    }
}
