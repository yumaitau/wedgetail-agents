//! Golden tests for the Linux presets. Every rule of `linux-core`, `linux-auditd` and
//! `linux-containers` reads its raw samples from `presets/linux/fixtures/` through the
//! collector it runs on a host (file tail, utmp records, audit assembly, lastlog summary, or
//! journal entries as `journalctl -o json` prints them, filtered by the rule's matches) and
//! the rule pipeline (filters, redaction, parser). The v1 wire lines it would send are
//! compared with `presets/linux/fixtures/golden/<rule id>.ndjson`.
//!
//! Two values are fixed so the files are stable: `attrs.path` is the path on a real host
//! (the fixture is read from a temporary copy), and `ts` of text lines and lastlog summaries,
//! which is the time the agent read them, is `2026-10-21T08:00:00Z`. utmp records, audit
//! events and journal entries keep their own time.
//!
//! Regenerate after an intended change with
//! `UPDATE_GOLDEN=1 cargo test -p agent-core --test linux_presets` and review the diff.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_collectors::file_tail::{FileSpec, FileTail};
use agent_collectors::lastlog::Lastlog;
use agent_collectors::utmp::Layout;
use agent_collectors::{Collector, CollectorEnv, EventTemplate, RawEvent, journald};
use agent_config::{AgentConfig, FileFormat, Rule, RuleKind, StartAt, presets};
use agent_core::{Processor, RuleProcessor, Verdict};

/// `ts` of events whose time is the time they were read.
const READ_TS_US: u64 = 1_792_569_600_000_000;

/// `(fixture file, the path it lives at on a host)`.
type Files = &'static [(&'static str, &'static str)];

const AUTH_FILES: Files = &[
    ("auth.log", "/var/log/auth.log"),
    ("secure", "/var/log/secure"),
];
const MESSAGES: Files = &[("messages", "/var/log/messages")];

/// Every preset rule and where its samples come from; `None` means `journal.json`.
const CASES: &[(&str, Option<Files>)] = &[
    ("linux-core.sshd", Some(AUTH_FILES)),
    ("linux-core.sshd.journald", None),
    ("linux-core.sshd.messages", Some(MESSAGES)),
    ("linux-core.auth", Some(AUTH_FILES)),
    ("linux-core.auth.journald", None),
    ("linux-core.auth.messages", Some(MESSAGES)),
    ("linux-core.kernel", None),
    ("linux-core.kernel.messages", Some(MESSAGES)),
    ("linux-core.cron", Some(&[("cron", "/var/log/cron")])),
    ("linux-core.cron.journald", None),
    ("linux-core.cron.messages", Some(MESSAGES)),
    ("linux-core.timers", None),
    ("linux-core.firewall", None),
    (
        "linux-core.dpkg",
        Some(&[("dpkg.log", "/var/log/dpkg.log")]),
    ),
    (
        "linux-core.apt",
        Some(&[("apt-history.log", "/var/log/apt/history.log")]),
    ),
    (
        "linux-core.dnf",
        Some(&[("dnf.rpm.log", "/var/log/dnf.rpm.log")]),
    ),
    ("linux-core.yum", Some(&[("yum.log", "/var/log/yum.log")])),
    (
        "linux-core.zypp",
        Some(&[("zypp-history", "/var/log/zypp/history")]),
    ),
    ("linux-core.wtmp", Some(&[("wtmp", "/var/log/wtmp")])),
    ("linux-core.btmp", Some(&[("btmp", "/var/log/btmp")])),
    (
        "linux-core.lastlog",
        Some(&[("lastlog", "/var/log/lastlog")]),
    ),
    (
        "linux-auditd.audit",
        Some(&[("audit.log", "/var/log/audit/audit.log")]),
    ),
    ("linux-containers.docker", None),
    ("linux-containers.containerd", None),
    ("linux-containers.kubelet", None),
    (
        "linux-containers.k8s-audit",
        Some(&[("k8s-audit.log", "/var/log/kubernetes/audit/audit.log")]),
    ),
];

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../presets/linux/fixtures")
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn linux_rules() -> Vec<Rule> {
    let main = "[agent]\nendpoint = \"https://ingest.example.com\"\npresets = [\"linux-core\", \"linux-auditd\", \"linux-containers\"]\n";
    let config = AgentConfig::from_sources(
        Path::new("agent.toml"),
        main,
        &[],
        presets::BUILTIN,
        "linux",
        None,
    )
    .unwrap_or_else(|e| panic!("linux presets: {e}"));
    config.rules
}

/// Whether a journal entry passes `journalctl` matches: the same field is ORed, different
/// fields are ANDed.
fn journal_matches(rule: &Rule, fields: &serde_json::Map<String, serde_json::Value>) -> bool {
    let matches = rule.journal_matches();
    let mut by_field: Vec<(&str, Vec<&str>)> = Vec::new();
    for m in &matches {
        let (field, value) = m.split_once('=').expect("FIELD=value");
        match by_field.iter_mut().find(|(f, _)| *f == field) {
            Some((_, values)) => values.push(value),
            None => by_field.push((field, vec![value])),
        }
    }
    by_field.iter().all(|(field, values)| {
        fields
            .get(*field)
            .and_then(|v| v.as_str())
            .is_some_and(|v| values.contains(&v))
    })
}

fn journal_events(rule: &Rule) -> Vec<RawEvent> {
    let template = EventTemplate::from_rule(rule);
    let text = std::fs::read_to_string(fixtures().join("journal.json")).expect("journal.json");
    text.lines()
        .map(|line| journald::parse_line(line.as_bytes()).expect("journal entry"))
        .filter(|entry| journal_matches(rule, &entry.fields))
        .map(|entry| template.event(entry.ts_us, None, entry.fields))
        .collect()
}

fn file_events(rule: &Rule, fixture: &str, host_path: &str) -> Vec<RawEvent> {
    let dir = TempDir(std::env::temp_dir().join(format!(
        "wt-golden-{}-{}-{fixture}",
        rule.id,
        std::process::id()
    )));
    let _ = std::fs::remove_dir_all(&dir.0);
    std::fs::create_dir_all(&dir.0).expect("mkdir");
    // Named as on a host: utmp records take their `log` from the file name.
    let name = Path::new(host_path).file_name().expect("file name");
    let path = dir.0.join(name);
    std::fs::copy(fixtures().join(fixture), &path).expect("copy fixture");

    let template = EventTemplate::from_rule(rule);
    let mut collector: Box<dyn Collector> = if rule.format == FileFormat::Lastlog {
        Box::new(
            Lastlog::new(template, path.clone(), CollectorEnv::default())
                .with_passwd(fixtures().join("passwd"))
                .with_layout(Layout::X86_64),
        )
    } else {
        let mut spec = FileSpec::from_rule(rule);
        spec.paths = vec![path.clone()];
        spec.start_at = StartAt::Beginning;
        // The binary fixtures are the x86_64 layout (aarch64 copies are unit-tested).
        spec.utmp_layout = Layout::X86_64;
        Box::new(FileTail::new(template, spec, CollectorEnv::default()).expect("tail"))
    };
    collector.start(None).expect("start");
    let mut events = collector.poll(10_000, Duration::ZERO).expect("poll").events;
    // Rotating the file away finishes pending multiline entries and audit events.
    std::fs::remove_file(&path).expect("remove");
    events.extend(collector.poll(10_000, Duration::ZERO).expect("poll").events);
    let temp = path.to_string_lossy().into_owned();
    for ev in &mut events {
        if ev.attrs.get("path").and_then(|p| p.as_str()) == Some(temp.as_str()) {
            ev.attrs.insert("path".into(), host_path.into());
        }
        if matches!(rule.format, FileFormat::Lines | FileFormat::Lastlog) {
            ev.ts_us = READ_TS_US;
        }
    }
    events
}

#[test]
fn every_linux_preset_rule_matches_its_golden_file() {
    let rules = linux_rules();
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    let golden_dir = fixtures().join("golden");
    let mut failures = Vec::new();

    for rule in &rules {
        assert!(
            CASES.iter().any(|(id, _)| *id == rule.id),
            "{}: add fixtures and a case for it",
            rule.id
        );
    }
    for (id, files) in CASES {
        let mut rule = rules
            .iter()
            .find(|r| r.id == *id)
            .unwrap_or_else(|| panic!("no rule {id}"))
            .clone();
        // Host checks may switch a rule off on the machine running the test.
        rule.enabled = true;
        let raw = match files {
            None => {
                assert_eq!(rule.kind, RuleKind::Journald, "{id}");
                journal_events(&rule)
            }
            Some(files) => files
                .iter()
                .flat_map(|(fixture, host)| file_events(&rule, fixture, host))
                .collect(),
        };
        let mut processor = RuleProcessor::new(std::slice::from_ref(&rule)).expect("rule pipeline");
        let mut out = String::new();
        for ev in raw {
            if let Verdict::Keep(ev) = processor.process(ev) {
                assert!(
                    !ev.attrs.contains_key("parse_error"),
                    "{id}: parse error on {:?}",
                    ev.body
                );
                out.push_str(&String::from_utf8(ev.to_wire_line()).expect("utf8"));
                out.push('\n');
            }
        }
        assert!(!out.is_empty(), "{id}: no event from its fixtures");
        let golden = golden_dir.join(format!("{id}.ndjson"));
        if update {
            std::fs::create_dir_all(&golden_dir).expect("mkdir golden");
            std::fs::write(&golden, &out).expect("write golden");
        }
        let want = std::fs::read_to_string(&golden).unwrap_or_default();
        if want != out {
            failures.push(format!("{id}:\n--- want\n{want}--- got\n{out}"));
        }
    }
    assert!(
        failures.is_empty(),
        "golden files differ (UPDATE_GOLDEN=1 to regenerate):\n{}",
        failures.join("\n")
    );
}
