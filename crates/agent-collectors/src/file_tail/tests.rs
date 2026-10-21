use std::io::Write;

use super::*;

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("wt-tail-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        Self(dir)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn append(path: &Path, text: &str) {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open");
    f.write_all(text.as_bytes()).expect("write");
}

fn template() -> EventTemplate {
    EventTemplate::new("t", "file", None, &BTreeMap::new())
}

fn tail_spec(spec: FileSpec, env: CollectorEnv) -> FileTail {
    let mut t = FileTail::new(template(), spec, env).expect("tail");
    // Expand globs on every poll so tests need not wait.
    t.scan_interval = Duration::ZERO;
    t
}

fn tail(path: &Path, start_at: StartAt) -> FileTail {
    tail_spec(
        FileSpec::new(vec![path.to_path_buf()], start_at),
        CollectorEnv::default(),
    )
}

fn bodies(t: &mut FileTail) -> Vec<String> {
    let batch = t.poll(1000, Duration::ZERO).expect("poll");
    batch
        .events
        .into_iter()
        .map(|e| e.body.unwrap_or_default())
        .collect()
}

fn paths_of(t: &mut FileTail) -> Vec<(String, String)> {
    let batch = t.poll(1000, Duration::ZERO).expect("poll");
    batch
        .events
        .into_iter()
        .map(|e| {
            let path = Path::new(e.attrs["path"].as_str().unwrap_or_default())
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            (path, e.body.unwrap_or_default())
        })
        .collect()
}

#[test]
fn starts_at_end_by_default_and_reads_new_lines() {
    let dir = Dir::new("end");
    let path = dir.0.join("a.log");
    append(&path, "old\n");
    let mut t = tail(&path, StartAt::End);
    t.start(None).expect("start");
    assert!(bodies(&mut t).is_empty());
    append(&path, "one\r\ntwo\npart");
    assert_eq!(bodies(&mut t), ["one", "two"]);
    append(&path, "ial\n");
    assert_eq!(bodies(&mut t), ["partial"]);
}

#[test]
fn beginning_and_resume_from_checkpoint() {
    let dir = Dir::new("resume");
    let path = dir.0.join("a.log");
    append(&path, "1\n2\n3");
    let mut t = tail(&path, StartAt::Beginning);
    t.start(None).expect("start");
    let batch = t.poll(10, Duration::ZERO).expect("poll");
    assert_eq!(batch.events.len(), 2);
    let cp = batch.checkpoint.expect("checkpoint");
    match &cp {
        Checkpoint::File { files } => assert_eq!(files[&path].offset, 4),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        batch.events[0].attrs["path"],
        path.to_string_lossy().as_ref()
    );

    // A new process resumes after the last complete line.
    drop(t);
    append(&path, "\n4\n");
    let mut t = tail(&path, StartAt::End);
    t.start(Some(cp)).expect("start");
    assert_eq!(bodies(&mut t), ["3", "4"]);
}

#[test]
fn max_events_rewinds_and_continues() {
    let dir = Dir::new("max");
    let path = dir.0.join("a.log");
    let text: String = (0..100).map(|i| format!("line {i}\n")).collect();
    append(&path, &text);
    let mut t = tail(&path, StartAt::Beginning);
    t.start(None).expect("start");
    let mut all = Vec::new();
    loop {
        let batch = t.poll(7, Duration::ZERO).expect("poll");
        if batch.events.is_empty() {
            break;
        }
        assert!(batch.events.len() <= 7);
        all.extend(batch.events.into_iter().map(|e| e.body.unwrap_or_default()));
    }
    let want: Vec<String> = (0..100).map(|i| format!("line {i}")).collect();
    assert_eq!(all, want);
}

#[test]
fn follows_rename_rotation_without_losing_lines() {
    let dir = Dir::new("rotate");
    let path = dir.0.join("a.log");
    append(&path, "");
    let mut t = tail(&path, StartAt::End);
    t.start(None).expect("start");
    append(&path, "before\nlast-old-no-newline");
    std::fs::rename(&path, dir.0.join("a.log.1")).expect("rename");
    append(&path, "after\n");
    assert_eq!(bodies(&mut t), ["before", "last-old-no-newline", "after"]);
    append(&path, "more\n");
    assert_eq!(bodies(&mut t), ["more"]);
}

#[test]
fn handles_copytruncate() {
    let dir = Dir::new("truncate");
    let path = dir.0.join("a.log");
    append(&path, "");
    let mut t = tail(&path, StartAt::End);
    t.start(None).expect("start");
    append(&path, "a long line before truncation\n");
    assert_eq!(bodies(&mut t).len(), 1);
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("truncate");
    append(&path, "new\n");
    assert_eq!(bodies(&mut t), ["new"]);
}

#[test]
fn missing_file_is_picked_up_when_created() {
    let dir = Dir::new("missing");
    let path = dir.0.join("later.log");
    let mut t = tail(&path, StartAt::End);
    t.start(None).expect("start");
    assert!(bodies(&mut t).is_empty());
    append(&path, "hello\n");
    assert_eq!(bodies(&mut t), ["hello"]);
}

#[test]
fn over_long_and_binary_lines_are_bounded() {
    let dir = Dir::new("long");
    let path = dir.0.join("a.log");
    let max = agent_config::DEFAULT_MAX_LINE_BYTES as usize;
    let mut f = File::create(&path).expect("create");
    f.write_all(&vec![b'x'; max * 3]).expect("write");
    f.write_all(b"\n\xff\xfe\x00bin\nok\n").expect("write");
    drop(f);
    let mut t = tail(&path, StartAt::Beginning);
    t.start(None).expect("start");
    let batch = t.poll(10, Duration::ZERO).expect("poll");
    assert_eq!(batch.events.len(), 3);
    assert_eq!(batch.events[0].body.as_ref().map(String::len), Some(max));
    assert_eq!(batch.events[0].attrs["truncated"], true);
    assert_eq!(
        batch.events[1].body.as_deref(),
        Some("\u{fffd}\u{fffd}\0bin")
    );
    assert_eq!(batch.events[2].body.as_deref(), Some("ok"));
    match batch.checkpoint.expect("cp") {
        Checkpoint::File { files } => {
            assert_eq!(
                files[&path].offset,
                std::fs::metadata(&path).expect("meta").len()
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn max_line_bytes_per_rule() {
    let dir = Dir::new("maxline");
    let path = dir.0.join("a.log");
    append(&path, &format!("{}\nshort\n", "y".repeat(1000)));
    let mut spec = FileSpec::new(vec![path.clone()], StartAt::Beginning);
    spec.max_line_bytes = 256;
    let mut t = tail_spec(spec, CollectorEnv::default());
    t.start(None).expect("start");
    let batch = t.poll(10, Duration::ZERO).expect("poll");
    assert_eq!(batch.events[0].body.as_ref().map(String::len), Some(256));
    assert_eq!(batch.events[0].attrs["truncated"], true);
    assert_eq!(batch.events[1].body.as_deref(), Some("short"));
}

#[test]
fn poll_waits_for_new_data() {
    let dir = Dir::new("wait");
    let path = dir.0.join("a.log");
    append(&path, "");
    let mut t = tail(&path, StartAt::End);
    t.start(None).expect("start");
    let writer_path = path.clone();
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        append(&writer_path, "late\n");
    });
    let batch = t.poll(10, Duration::from_secs(5)).expect("poll");
    writer.join().expect("join");
    assert_eq!(batch.events.len(), 1);
}

#[test]
fn globs_with_exclude_and_new_files() {
    let dir = Dir::new("glob");
    let logs = dir.0.join("logs");
    std::fs::create_dir_all(logs.join("sub")).expect("mkdir");
    append(&logs.join("a.log"), "a-old\n");
    append(&logs.join("b.log"), "b-old\n");
    append(&logs.join("old.log.gz"), "zipped\n");
    append(&logs.join("skip-me.log"), "skipped\n");
    append(&logs.join("sub/c.log"), "c-old\n");
    let mut spec = FileSpec::new(vec![logs.join("*.log*")], StartAt::Beginning);
    spec.exclude = vec![
        "*.gz".into(),
        logs.join("skip-*").to_string_lossy().into_owned(),
    ];
    let mut t = tail_spec(spec, CollectorEnv::default());
    t.start(None).expect("start");
    let mut got = paths_of(&mut t);
    got.sort();
    // `*` does not cross directories; excluded names are skipped.
    assert_eq!(
        got,
        [
            ("a.log".to_owned(), "a-old".to_owned()),
            ("b.log".to_owned(), "b-old".to_owned())
        ]
    );
    // A file created later is read from its start, even with start_at = "end".
    append(&logs.join("new.log"), "n1\n");
    assert_eq!(paths_of(&mut t), [("new.log".to_owned(), "n1".to_owned())]);

    let mut recursive = tail_spec(
        FileSpec::new(vec![logs.join("**").join("*.log")], StartAt::Beginning),
        CollectorEnv::default(),
    );
    recursive.start(None).expect("start");
    let mut names: Vec<String> = paths_of(&mut recursive)
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    names.sort();
    assert_eq!(names, ["a.log", "b.log", "c.log", "new.log", "skip-me.log"]);
}

#[test]
fn glob_rotation_is_not_read_twice() {
    let dir = Dir::new("globrotate");
    let path = dir.0.join("app.log");
    append(&path, "");
    // Matches both the live file and its rotated copies.
    let mut t = tail_spec(
        FileSpec::new(vec![dir.0.join("app.log*")], StartAt::End),
        CollectorEnv::default(),
    );
    t.start(None).expect("start");
    append(&path, "one\n");
    assert_eq!(bodies(&mut t), ["one"]);
    append(&path, "two\n");
    std::fs::rename(&path, dir.0.join("app.log.1")).expect("rename");
    append(&path, "three\n");
    let mut got = bodies(&mut t);
    got.sort();
    assert_eq!(got, ["three", "two"]);
    for _ in 0..3 {
        assert!(bodies(&mut t).is_empty(), "duplicates");
    }
    append(&dir.0.join("app.log.1"), "late write to the old file\n");
    assert_eq!(bodies(&mut t), ["late write to the old file"]);
    match t.checkpoint() {
        Checkpoint::File { files } => {
            let names: Vec<_> = files.keys().filter_map(|p| p.file_name()).collect();
            assert_eq!(names.len(), 2, "{files:?}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn open_files_are_capped_across_rules() {
    let dir = Dir::new("cap");
    for i in 0..5 {
        append(&dir.0.join(format!("{i}.log")), &format!("{i}\n"));
    }
    let env = CollectorEnv::new(Vec::new(), 3);
    let mut a = tail_spec(
        FileSpec::new(vec![dir.0.join("[01].log")], StartAt::Beginning),
        env.clone(),
    );
    let mut b = tail_spec(
        FileSpec::new(vec![dir.0.join("[234].log")], StartAt::Beginning),
        env.clone(),
    );
    a.start(None).expect("start");
    b.start(None).expect("start");
    assert_eq!(bodies(&mut a).len(), 2);
    assert_eq!(bodies(&mut b).len(), 1);
    assert_eq!(env.open_files.in_use(), 3);
    drop(a);
    assert_eq!(env.open_files.in_use(), 1);
    // Freed slots are used on the next scan.
    assert_eq!(bodies(&mut b).len(), 2);
    assert_eq!(env.open_files.in_use(), 3);
}

#[test]
fn protected_dirs_are_never_read() {
    let dir = Dir::new("protected");
    let state = dir.0.join("state");
    std::fs::create_dir_all(&state).expect("mkdir");
    append(&state.join("credential"), "wgh_secret\n");
    append(&dir.0.join("app.log"), "fine\n");
    let env = CollectorEnv::new(vec![state.clone()], 100);
    let mut t = tail_spec(
        FileSpec::new(vec![dir.0.join("**").join("*")], StartAt::Beginning),
        env,
    );
    t.start(None).expect("start");
    assert_eq!(bodies(&mut t), ["fine"]);
}

#[cfg(unix)]
#[test]
fn symlinks_outside_the_root_are_refused() {
    let dir = Dir::new("symlink");
    let logs = dir.0.join("logs");
    std::fs::create_dir_all(&logs).expect("mkdir");
    append(&dir.0.join("secret.txt"), "top secret\n");
    append(&logs.join("real.log"), "real\n");
    std::os::unix::fs::symlink(dir.0.join("secret.txt"), logs.join("evil.log")).expect("link");
    std::os::unix::fs::symlink(logs.join("real.log"), logs.join("current.log")).expect("link");
    let mut t = tail_spec(
        FileSpec::new(
            vec![logs.join("*.log"), logs.join("evil.log")],
            StartAt::Beginning,
        ),
        CollectorEnv::default(),
    );
    t.start(None).expect("start");
    // current.log and real.log are the same file: read once.
    assert_eq!(bodies(&mut t), ["real"]);
}

fn multiline_spec(path: &Path, toml_text: &str) -> FileSpec {
    let mut spec = FileSpec::new(vec![path.to_path_buf()], StartAt::Beginning);
    spec.multiline = Some(toml::from_str(toml_text).expect("multiline"));
    spec
}

#[test]
fn multiline_joins_and_checkpoints_at_the_pending_event() {
    let dir = Dir::new("multiline");
    let path = dir.0.join("app.log");
    append(
        &path,
        "2026-10-21 ERROR boom\nTraceback:\n  at x\n2026-10-21 INFO next\n  cont\n",
    );
    let spec = multiline_spec(&path, "pattern = '^\\d{4}-'\nnegate = true");
    let mut t = tail_spec(spec.clone(), CollectorEnv::default());
    t.start(None).expect("start");
    let batch = t.poll(100, Duration::ZERO).expect("poll");
    let got: Vec<_> = batch.events.iter().filter_map(|e| e.body.clone()).collect();
    assert_eq!(got, ["2026-10-21 ERROR boom\nTraceback:\n  at x"]);
    // The INFO event is still pending: the checkpoint points at its first line.
    let cp = batch.checkpoint.expect("checkpoint");
    let pending_at = "2026-10-21 ERROR boom\nTraceback:\n  at x\n".len() as u64;
    match &cp {
        Checkpoint::File { files } => assert_eq!(files[&path].offset, pending_at),
        other => panic!("{other:?}"),
    }

    // After a restart the pending event is read and joined again.
    drop(t);
    append(&path, "2026-10-21 INFO third\n");
    let mut t = tail_spec(spec, CollectorEnv::default());
    t.start(Some(cp)).expect("start");
    assert_eq!(bodies(&mut t), ["2026-10-21 INFO next\n  cont"]);

    // A pending event is sent once no line has arrived for a while.
    t.flush_after = Duration::from_millis(50);
    thread::sleep(Duration::from_millis(80));
    assert_eq!(bodies(&mut t), ["2026-10-21 INFO third"]);
}

#[test]
fn from_rule_builds_a_file_tail() {
    let dir = Dir::new("rule");
    let path = dir.0.join("x.log");
    append(&path, "");
    let rule: Rule = toml::from_str(&format!(
        "id = \"r\"\ntype = \"file\"\npaths = [{:?}]\nmax_line_bytes = 512\nmultiline = {{ pattern = '^\\s' }}",
        path.to_string_lossy()
    ))
    .expect("rule");
    let spec = FileSpec::from_rule(&rule);
    assert_eq!(spec.max_line_bytes, 512);
    assert!(spec.multiline.is_some());
    assert!(crate::from_rule(&rule, &CollectorEnv::default()).is_ok());
}

fn format_spec(path: &Path, format: FileFormat) -> FileSpec {
    let mut spec = FileSpec::new(vec![path.to_path_buf()], StartAt::Beginning);
    spec.format = format;
    spec
}

#[test]
fn auditd_format_merges_records_and_checkpoints_pending_events() {
    let dir = Dir::new("auditd");
    let path = dir.0.join("audit.log");
    let first = "type=SYSCALL msg=audit(1792569600.123:10): syscall=59 comm=\"id\"\ntype=PROCTITLE msg=audit(1792569600.123:10): proctitle=6964\n";
    append(
        &path,
        &format!(
            "{first}type=SYSCALL msg=audit(1792569600.200:11): syscall=2\ntype=EOE msg=audit(1792569600.123:10): \n"
        ),
    );
    let spec = format_spec(&path, FileFormat::Auditd);
    let mut t = tail_spec(spec.clone(), CollectorEnv::default());
    t.start(None).expect("start");
    let batch = t.poll(100, Duration::ZERO).expect("poll");
    assert_eq!(batch.events.len(), 1);
    let ev = &batch.events[0];
    assert_eq!(ev.ts_us, 1_792_569_600_123_000);
    assert!(ev.body.is_none());
    assert_eq!(ev.fields["serial"], 10);
    assert_eq!(ev.fields["records"][1]["proctitle"], "id");
    assert_eq!(
        ev.attrs["path"],
        Value::from(path.to_string_lossy().as_ref())
    );
    // Serial 11 is still open: the checkpoint is at its first record.
    let cp = batch.checkpoint.expect("checkpoint");
    match &cp {
        Checkpoint::File { files } => assert_eq!(files[&path].offset, first.len() as u64),
        other => panic!("{other:?}"),
    }
    // After a restart it is read again and finished by its EOE.
    drop(t);
    append(&path, "type=EOE msg=audit(1792569600.200:11): \n");
    let mut t = tail_spec(spec, CollectorEnv::default());
    t.start(Some(cp)).expect("start");
    let batch = t.poll(100, Duration::ZERO).expect("poll");
    let serials: Vec<_> = batch
        .events
        .iter()
        .map(|e| e.fields["serial"].clone())
        .collect();
    // Serial 10's EOE is read again without its records and ignored: 10 is not sent twice.
    assert_eq!(serials, [11]);
}

#[test]
fn utmp_format_reads_whole_records() {
    let dir = Dir::new("utmp");
    let path = dir.0.join("wtmp");
    let rec = |user: &str, sec: i32| {
        let mut r = vec![0u8; 384];
        r[0..2].copy_from_slice(&7i16.to_le_bytes());
        r[44..44 + user.len()].copy_from_slice(user.as_bytes());
        r[340..344].copy_from_slice(&sec.to_le_bytes());
        r
    };
    let mut data = rec("alice", 1_792_569_600);
    data.extend(rec("bob", 1_792_569_660));
    let third = rec("carol", 1_792_569_720);
    data.extend_from_slice(&third[..100]);
    std::fs::write(&path, &data).expect("write");

    // start_at = "end" on a file that is not a whole number of records starts at a boundary.
    let mut end = FileSpec::new(vec![path.clone()], StartAt::End);
    end.format = FileFormat::Utmp;
    end.utmp_layout = utmp::Layout::X86_64;
    let mut t = tail_spec(end, CollectorEnv::default());
    t.start(None).expect("start");
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .and_then(|mut f| f.write_all(&third[100..]))
        .expect("append");
    let users: Vec<_> = t
        .poll(100, Duration::ZERO)
        .expect("poll")
        .events
        .iter()
        .map(|e| e.fields["user"].clone())
        .collect();
    assert_eq!(users, ["carol"]);

    let mut spec = format_spec(&path, FileFormat::Utmp);
    spec.utmp_layout = utmp::Layout::X86_64;
    let mut t = tail_spec(spec, CollectorEnv::default());
    t.start(None).expect("start");
    let batch = t.poll(100, Duration::ZERO).expect("poll");
    let got: Vec<_> = batch
        .events
        .iter()
        .map(|e| {
            (
                e.fields["user"].clone(),
                e.fields["log"].clone(),
                e.ts_us,
                e.body.is_none(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                Value::from("alice"),
                Value::from("wtmp"),
                1_792_569_600_000_000,
                true
            ),
            (
                Value::from("bob"),
                Value::from("wtmp"),
                1_792_569_660_000_000,
                true
            ),
            (
                Value::from("carol"),
                Value::from("wtmp"),
                1_792_569_720_000_000,
                true
            ),
        ]
    );
    match batch.checkpoint.expect("checkpoint") {
        Checkpoint::File { files } => assert_eq!(files[&path].offset, 3 * 384),
        other => panic!("{other:?}"),
    }
}
