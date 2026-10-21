//! Golden-file tests for the Windows presets, on every OS.
//!
//! `presets/windows/fixtures/<preset>/*.xml` hold rendered events (as `EvtRenderEventXml`
//! returns them). Each one must be selected by exactly one rule of its preset (channel and
//! event id), every rule must have at least one fixture, and the wire lines the agent sends
//! for them, in file name order and after script block reassembly, must equal
//! `<preset>/expected.ndjson`. Regenerate after an intended change with
//! `UPDATE_GOLDEN=1 cargo test -p agent-collectors --test windows_presets` and review the diff.
//!
//! The `fields` of each expected line is exactly a record for a Wedgetail endpoint rule
//! fixture (`{"connector": "endpoint-windows", "format": "windows", "records": [...]}`).

use std::path::{Path, PathBuf};
use std::time::Instant;

use agent_collectors::wineventlog::script_block::ScriptBlocks;
use agent_collectors::wineventlog::{event_xml_to_wef, wef_time_us};
use agent_collectors::{EventTemplate, RawEvent};
use agent_config::presets::BUILTIN;
use agent_config::{AgentConfig, Rule};
use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../presets/windows/fixtures")
}

fn preset_rules(id: &str) -> Vec<Rule> {
    let main = format!("[agent]\nendpoint = \"https://ingest.example.com\"\npresets = [{id:?}]\n");
    let config = AgentConfig::from_sources(
        Path::new("agent.toml"),
        &main,
        &[],
        BUILTIN,
        "windows",
        None,
    )
    .unwrap_or_else(|e| panic!("{id}: {e}"));
    config.rules
}

fn selects(rule: &Rule, channel: &str, id: u64) -> bool {
    rule.channel.as_deref() == Some(channel)
        && match &rule.xpath {
            Some(x) => x.contains(&format!("EventID={id})")),
            None => rule.event_ids.is_empty() || rule.event_ids.iter().any(|&e| u64::from(e) == id),
        }
}

#[test]
fn windows_preset_fixtures_match_golden_files() {
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    let mut failures = Vec::new();
    let presets: Vec<_> = BUILTIN.iter().filter(|p| p.os == "windows").collect();
    assert!(!presets.is_empty());
    for preset in presets {
        let rules = preset_rules(preset.id);
        let dir = fixtures_dir().join(preset.id);
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .map(|e| e.expect("entry").path())
            .filter(|p| p.extension().is_some_and(|x| x == "xml"))
            .collect();
        files.sort();
        assert!(!files.is_empty(), "{}: no fixtures", preset.id);

        let mut blocks = ScriptBlocks::default();
        let mut events: Vec<RawEvent> = Vec::new();
        let mut covered = Vec::new();
        for file in &files {
            let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("?");
            let xml = std::fs::read_to_string(file).expect("read");
            let wef = event_xml_to_wef(&xml).unwrap_or_else(|e| panic!("{name}: {e}"));
            let system = &wef["System"];
            let channel = system["Channel"].as_str().expect("Channel");
            let id = system["EventID"].as_u64().expect("numeric EventID");
            // What the Wedgetail windows normaliser needs.
            assert!(system["Computer"].is_string(), "{name}");
            assert!(system["Provider"]["Name"].is_string(), "{name}");
            assert!(system["EventRecordID"].is_u64(), "{name}");
            let ts = wef_time_us(&wef).unwrap_or_else(|| panic!("{name}: TimeCreated"));
            let matching: Vec<&Rule> = rules.iter().filter(|r| selects(r, channel, id)).collect();
            assert_eq!(
                matching.len(),
                1,
                "{name}: {channel} {id} should be selected by exactly one {} rule",
                preset.id
            );
            covered.push(matching[0].id.clone());
            let event = EventTemplate::from_rule(matching[0]).event(ts, None, wef);
            events.extend(blocks.push(event, Instant::now()));
        }
        assert!(
            blocks.is_idle(),
            "{}: script block parts left over",
            preset.id
        );
        for rule in &rules {
            assert!(
                covered.contains(&rule.id),
                "{}: no fixture for rule {}",
                preset.id,
                rule.id
            );
        }

        let mut out = String::new();
        for event in &events {
            out.push_str(std::str::from_utf8(&event.to_wire_line()).expect("utf8"));
            out.push('\n');
        }
        let golden = dir.join("expected.ndjson");
        if update {
            std::fs::write(&golden, &out).expect("write golden");
        }
        let want = std::fs::read_to_string(&golden).unwrap_or_default();
        if want != out {
            failures.push(format!("{}:\n--- want\n{want}--- got\n{out}", preset.id));
        }
        for line in out.lines() {
            let v: Value = serde_json::from_str(line).expect("json");
            assert_eq!(v["source_type"], "windows.eventlog");
            assert_eq!(v["body"], Value::Null);
        }
    }
    assert!(
        failures.is_empty(),
        "golden files differ (UPDATE_GOLDEN=1 to regenerate):\n{}",
        failures.join("\n")
    );
}

/// Every Windows preset rule's query is within the XPath limits, and lists no id twice.
#[test]
fn windows_preset_queries() {
    for preset in BUILTIN.iter().filter(|p| p.os == "windows") {
        for rule in preset_rules(preset.id) {
            let channel = rule.channel.as_deref().expect("channel");
            let query = agent_collectors::wineventlog::build_xpath(
                channel,
                &rule.event_ids,
                rule.xpath.as_deref(),
            );
            let mut ids = rule.event_ids.clone();
            ids.sort_unstable();
            ids.dedup();
            assert_eq!(ids.len(), rule.event_ids.len(), "{}: repeated id", rule.id);
            if rule.xpath.is_none() {
                assert!(!rule.event_ids.is_empty(), "{}: no event ids", rule.id);
                assert!(
                    rule.event_ids.len() <= agent_collectors::wineventlog::MAX_IDS_PER_SELECT,
                    "{}: split the rule instead of relying on a structured query",
                    rule.id
                );
                assert!(query.starts_with("*[System[("), "{}: {query}", rule.id);
            }
        }
    }
}
