//! Fixtures in `presets/macos/fixtures/bsm`: `trail.bsm` is a hand-built trail of ten records
//! (fictional users, hosts and addresses): failed authentication, sudo with a wrong password,
//! sudo success with its command line, an OpenSSH login, a loginwindow login and logout, a
//! user created, an `execve`, a file read (class `fr`) and an event number missing from the
//! event table. `praudit.xml` is `praudit -x -r trail.bsm` from macOS 26.6; the macOS tests
//! run the real `praudit` again and compare. `audit_event` is a subset of the macOS file.

use serde_json::{Value, json};

use super::*;

const TRAIL: &[u8] = include_bytes!("../../../../presets/macos/fixtures/bsm/trail.bsm");
const XML: &str = include_str!("../../../../presets/macos/fixtures/bsm/praudit.xml");
const AUDIT_EVENT: &str = include_str!("../../../../presets/macos/fixtures/bsm/audit_event");

fn preset_classes() -> Vec<String> {
    ["lo", "aa", "ad", "ex"].map(String::from).to_vec()
}

#[test]
fn frames_whole_records() {
    let f = frame_records(TRAIL, usize::MAX);
    assert_eq!(f.records, 10);
    assert_eq!((f.consumed, f.skipped), (TRAIL.len(), 0));
    assert_eq!(f.data, TRAIL);
    // The cap stops at a record boundary.
    let f = frame_records(TRAIL, 3);
    assert_eq!(f.records, 3);
    assert_eq!(f.consumed, f.data.len());
    assert_eq!(frame_records(&TRAIL[f.consumed..], usize::MAX).records, 7);
}

#[test]
fn partial_record_waits_for_the_rest() {
    let all = frame_records(TRAIL, usize::MAX);
    let first = frame_records(TRAIL, 1).consumed;
    for cut in [1, 3, 5, first - 1] {
        let f = frame_records(&TRAIL[..cut], usize::MAX);
        assert_eq!(
            (f.records, f.consumed, f.skipped),
            (0, 0, 0),
            "cut at {cut}"
        );
    }
    let f = frame_records(&TRAIL[..TRAIL.len() - 2], usize::MAX);
    assert_eq!(f.records, 9);
    assert!(f.consumed < all.consumed);
    assert_eq!(f.skipped, 0);
}

#[test]
fn garbage_is_skipped_to_the_next_record() {
    let mut buf = b"\x00\x99junk\x14\x00\x00\x00\x02".to_vec();
    let junk = buf.len();
    buf.extend_from_slice(TRAIL);
    let f = frame_records(&buf, usize::MAX);
    assert_eq!((f.records, f.skipped, f.consumed), (10, junk, buf.len()));
    assert_eq!(f.data, TRAIL);

    // A header whose trailer does not match is not a record.
    let first = frame_records(TRAIL, 1).consumed;
    let mut bad = TRAIL.to_vec();
    bad[first - 1] ^= 0xff;
    let f = frame_records(&bad, usize::MAX);
    assert_eq!(f.records, 9);
    assert_eq!(f.skipped, first);

    // An absurd length is not waited for, nor one longer than a record can be but shorter
    // than the collector's read.
    let f = frame_records(b"\x14\xff\xff\xff\xff\x0b\x00\x00", usize::MAX);
    assert_eq!((f.records, f.skipped, f.consumed), (0, 8, 8));
    let mut buf = vec![0x14];
    buf.extend_from_slice(&(300u32 * 1024).to_be_bytes());
    buf.extend_from_slice(TRAIL);
    let f = frame_records(&buf, usize::MAX);
    assert_eq!((f.records, f.skipped), (10, 5));
}

#[test]
fn trail_names() {
    assert_eq!(
        trail_start("20261021080000.not_terminated"),
        Some("20261021080000")
    );
    assert_eq!(
        trail_start("20261021080000.20261021090000"),
        Some("20261021080000")
    );
    for other in [
        "current",
        "crash.20261021080000",
        "2026.not_terminated",
        "x.y",
        "",
    ] {
        assert_eq!(trail_start(other), None, "{other}");
    }
    let names: Vec<String> = [
        "current",
        "20261021100000.not_terminated",
        "20261021080000.20261021090000",
        "20261021090000.20261021100000",
    ]
    .map(String::from)
    .to_vec();
    assert_eq!(
        next_trail(&names, "20261021080000"),
        Some("20261021090000.20261021100000")
    );
    assert_eq!(
        next_trail(&names, "20261021090000"),
        Some("20261021100000.not_terminated")
    );
    assert_eq!(next_trail(&names, "20261021100000"), None);
}

#[test]
fn event_table() {
    let t = EventTable::parse(AUDIT_EVENT);
    assert_eq!(t.len(), AUDIT_EVENT.lines().count());
    assert_eq!(
        t.0[&23],
        ("AUE_EXECVE".to_owned(), vec!["pc".into(), "ex".into()])
    );
    let t = EventTable::parse("# comment\n\nx:AUE_x:x:lo\n1:AUE_short\n2:AUE_two:two(2):lo, aa\n");
    assert_eq!(t.len(), 1);
    assert_eq!(t.0[&2].1, ["lo", "aa"]);
}

#[test]
fn converts_praudit_xml() {
    let table = EventTable::parse(AUDIT_EVENT);
    let parsed = parse_praudit(XML, &table, &preset_classes());
    assert_eq!(parsed.errors, 0);
    // The file read (`fr`) and the unknown event are outside lo, aa, ad and ex.
    assert_eq!(parsed.filtered, 2);
    let events: Vec<&str> = parsed
        .records
        .iter()
        .map(|r| r.fields["event"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        events,
        [
            "AUE_auth_user",
            "AUE_sudo",
            "AUE_sudo",
            "AUE_openssh",
            "AUE_lw_login",
            "AUE_logout",
            "AUE_create_user",
            "AUE_EXECVE"
        ]
    );
    let failed = &parsed.records[0];
    assert_eq!(failed.ts_us, 1_792_569_601_120_000);
    assert_eq!(
        Value::Object(failed.fields.clone()),
        json!({
            "event": "AUE_auth_user",
            "event_id": 45023,
            "classes": ["aa"],
            "modifier": 0,
            "subject": {"audit_uid": "-1", "uid": "0", "gid": "20", "ruid": "0", "rgid": "20",
                        "pid": "412", "sid": "100004", "tid": "0 0.0.0.0"},
            "text": ["Verify password for record type Users 'alice' node '/Local/Default'"],
            "return": {"errval": "255", "retval": "5000"}
        })
    );
    let sudo = &parsed.records[2].fields;
    assert_eq!(sudo["exec_args"], json!(["sudo", "/usr/bin/whoami"]));
    let ssh = &parsed.records[3].fields;
    assert_eq!(ssh["subject"]["tid"], "52113 192.0.2.10");
    let exec = &parsed.records[7].fields;
    assert_eq!(exec["path"], json!(["/bin/sh"]));
    assert_eq!(exec["attribute"][0]["mode"], "100755");
    assert_eq!(exec["classes"], json!(["pc", "ex"]));

    // No class filter: everything, and unknown events by number.
    let all = parse_praudit(XML, &table, &[]);
    assert_eq!((all.records.len(), all.filtered), (10, 0));
    assert_eq!(all.records[9].fields["event"], "65000");
    assert_eq!(all.records[9].fields["classes"], json!([]));
}

fn doc(records: &str) -> String {
    format!("<?xml version='1.0' encoding='UTF-8'?>\n<audit>\n{records}\n</audit>\n")
}

const HEAD: &str =
    r#"<record version="11" event="45028" modifier="0" time="1792569600" msec="5" >"#;

#[test]
fn hostile_xml() {
    let table = EventTable::parse(AUDIT_EVENT);
    // Escaped markup, control characters and lossy-decoded bytes stay text.
    let xml = doc(&format!(
        "{HEAD}<text>a&lt;/text&gt;&lt;/record&gt; &amp;amp; &#x41; &bogus; \u{1}\u{fffd}\nend</text></record>"
    ));
    let p = parse_praudit(&xml, &table, &[]);
    assert_eq!((p.records.len(), p.errors), (1, 0));
    assert_eq!(
        p.records[0].fields["text"],
        json!(["a</text></record> &amp; A  \u{1}\u{fffd}\nend"])
    );

    // praudit leaves a record it cannot decode unclosed: earlier records are kept.
    let xml = doc(&format!(
        "{HEAD}<text>ok</text></record>\n<record version=\"153\" event=\"1\" time=\"9\" >"
    ));
    let p = parse_praudit(&xml, &table, &[]);
    assert_eq!((p.records.len(), p.errors), (1, 1));

    // No time, a bad time, no event: counted, not sent.
    let xml = doc(concat!(
        r#"<record version="11" event="45028" modifier="0" ><text>x</text></record>"#,
        r#"<record version="11" event="45028" time="soon" ></record>"#,
        r#"<record version="11" time="1" ></record>"#,
    ));
    let p = parse_praudit(&xml, &table, &[]);
    assert_eq!((p.records.len(), p.errors), (0, 3));

    // Environment variables: names only, values never leave the host.
    let xml = doc(&format!(
        "{HEAD}<exec_env><env>AWS_SECRET_ACCESS_KEY=abc123</env><env>PATH=/usr/bin</env><env>BARE</env></exec_env></record>"
    ));
    let p = parse_praudit(&xml, &table, &[]);
    assert_eq!(
        p.records[0].fields["exec_env"],
        json!(["AWS_SECRET_ACCESS_KEY", "PATH", "BARE"])
    );

    // DOCTYPE (entity expansion) is refused.
    let p = parse_praudit(
        "<?xml version='1.0'?><!DOCTYPE a [<!ENTITY x 'y'>]><audit></audit>",
        &table,
        &[],
    );
    assert_eq!((p.records.len(), p.errors), (0, 1));

    // Not XML at all, and empty output.
    for junk in ["", "garbage", "<audit><record", "</audit></audit>"] {
        assert!(
            parse_praudit(junk, &table, &[]).records.is_empty(),
            "{junk}"
        );
    }
}

#[test]
fn huge_records_are_cut_not_dropped() {
    let table = EventTable::parse(AUDIT_EVENT);
    let arg = "x".repeat(1000);
    let args: String = (0..5000).map(|_| format!("<arg>{arg}</arg>")).collect();
    let texts: String = (0..400).map(|i| format!("<text>t{i}</text>")).collect();
    let xml = doc(&format!(
        "{HEAD}<exec_args>{args}</exec_args>{texts}<text>{}</text></record>",
        "y".repeat(MAX_LINE_BYTES * 3)
    ));
    let p = parse_praudit(&xml, &table, &[]);
    assert_eq!(p.records.len(), 1);
    let r = &p.records[0];
    assert!(r.truncated);
    let size = serde_json::to_vec(&r.fields).map(|v| v.len()).unwrap_or(0);
    assert!(size < 200 * 1024, "{size} bytes");
    assert!(
        r.fields["exec_args"]
            .as_array()
            .is_some_and(|a| a.len() <= MAX_ARGS)
    );
    assert!(
        r.fields["text"]
            .as_array()
            .is_some_and(|a| a.len() < MAX_TOKENS)
    );

    // Many records in one document are fine.
    let many: String = (0..20_000)
        .map(|_| format!("{HEAD}<text>x</text></record>\n"))
        .collect();
    let p = parse_praudit(&doc(&many), &table, &preset_classes());
    assert_eq!((p.records.len(), p.errors), (20_000, 0));
}

/// Runs the real `praudit` and, through the collector, a trail directory with rotation.
#[cfg(target_os = "macos")]
mod os_tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::*;
    use crate::{Checkpoint, Collector, EventTemplate};

    fn praudit(data: &[u8]) -> String {
        let mut child = Command::new("/usr/sbin/praudit")
            .args(["-x", "-r"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("praudit");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(data)
            .expect("write");
        let out = child.wait_with_output().expect("output");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn real_praudit_matches_the_fixture() {
        let table = EventTable::parse(AUDIT_EVENT);
        let fixture = parse_praudit(XML, &table, &[]);
        let live = parse_praudit(&praudit(TRAIL), &table, &[]);
        assert_eq!(live.errors, 0);
        assert_eq!(live.records, fixture.records);
    }

    fn records(range: std::ops::Range<usize>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = TRAIL;
        for i in 0..10 {
            let f = frame_records(rest, 1);
            if range.contains(&i) {
                out.extend_from_slice(&f.data);
            }
            rest = &rest[f.consumed..];
        }
        out
    }

    fn append(path: &Path, data: &[u8]) {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open")
            .write_all(data)
            .expect("append");
    }

    fn link(dir: &Path, target: &str) {
        let current = dir.join("current");
        let _ = fs::remove_file(&current);
        std::os::unix::fs::symlink(dir.join(target), current).expect("symlink");
    }

    fn drain(c: &mut BsmTrail) -> (Vec<u64>, Option<Checkpoint>) {
        let mut ids = Vec::new();
        let mut checkpoint = None;
        for _ in 0..4 {
            let batch = c.poll(100, Duration::from_millis(100)).expect("poll");
            ids.extend(
                batch
                    .events
                    .iter()
                    .filter_map(|e| e.fields["event_id"].as_u64()),
            );
            checkpoint = batch.checkpoint.or(checkpoint);
        }
        (ids, checkpoint)
    }

    #[test]
    fn follows_the_trail_across_restart_and_rotation() {
        let dir = std::env::temp_dir().join(format!("wt-bsm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let events = dir.join("audit_event");
        fs::write(&events, AUDIT_EVENT).expect("events");
        let first = dir.join("20261021080000.not_terminated");
        append(&first, &records(0..2));
        link(&dir, "20261021080000.not_terminated");

        let template = EventTemplate::new("macos-audit.trail", "macos.bsm", None, &BTreeMap::new());
        let new = || {
            BsmTrail::with_paths(
                template.clone(),
                preset_classes(),
                dir.clone(),
                events.clone(),
            )
        };
        // No checkpoint: starts at the end, so the two existing records are not sent.
        let mut c = new();
        c.start(None).expect("start");
        assert!(drain(&mut c).0.is_empty());
        append(&first, &records(2..4));
        let (ids, checkpoint) = drain(&mut c);
        assert_eq!(ids, [45028, 32800]);
        drop(c);

        // While stopped: more records, then auditd rotates twice.
        append(&first, &records(4..5));
        fs::rename(&first, dir.join("20261021080000.20261021090000")).expect("rename");
        let second = dir.join("20261021090000.not_terminated");
        append(&second, &records(5..7));
        fs::rename(&second, dir.join("20261021090000.20261021100000")).expect("rename");
        append(&dir.join("20261021100000.not_terminated"), &records(7..10));
        link(&dir, "20261021100000.not_terminated");

        let mut c = new();
        c.start(checkpoint).expect("restart");
        let (ids, checkpoint) = drain(&mut c);
        // The rest of the old trail, the whole middle one, then the current one (the file
        // read and the unknown event are filtered out).
        assert_eq!(ids, [45021, 6153, 6207, 23]);
        match checkpoint {
            Some(Checkpoint::File { files }) => {
                let (path, pos) = files.into_iter().next().expect("position");
                assert!(path.ends_with("20261021100000.not_terminated"), "{path:?}");
                assert_eq!(pos.offset, records(7..10).len() as u64);
            }
            other => panic!("checkpoint {other:?}"),
        }

        // Records written to the old trail just before a switch are still read.
        let third = dir.join("20261021100000.not_terminated");
        append(&third, &records(1..2));
        fs::rename(&third, dir.join("20261021100000.20261021110000")).expect("rename");
        append(&dir.join("20261021110000.not_terminated"), &records(3..4));
        link(&dir, "20261021110000.not_terminated");
        assert_eq!(drain(&mut c).0, [45028, 32800]);

        // auditd stopped: `current` is gone.
        fs::remove_file(dir.join("current")).expect("unlink");
        let mut c = new();
        let err = c.start(None).expect_err("no trail");
        assert!(err.0.contains("no active audit trail"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
