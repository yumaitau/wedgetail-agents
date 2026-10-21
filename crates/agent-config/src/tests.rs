use super::*;
use crate::presets::tests::TEST_REGISTRY;

fn base() -> String {
    "[agent]\nendpoint = \"https://ingest.example.com/\"\npresets = []\n".to_owned()
}

/// An absolute path on this OS.
fn abs(p: &str) -> String {
    if cfg!(windows) {
        format!("C:{}", p.replace('/', "\\"))
    } else {
        p.to_owned()
    }
}

fn load_text(text: &str) -> Result<AgentConfig, ConfigError> {
    AgentConfig::from_sources(Path::new("agent.toml"), text, &[], &[], "linux", None)
}

fn parse_ok(extra: &str) -> AgentConfig {
    match load_text(&(base() + extra)) {
        Ok(config) => config,
        Err(e) => panic!("{extra}\n{e}"),
    }
}

fn parse_err(extra: &str) -> String {
    match load_text(&(base() + extra)) {
        Ok(_) => panic!("should be invalid: {extra}"),
        Err(e) => e.to_string(),
    }
}

fn file_rule(extra: &str) -> String {
    format!(
        "[[rule]]\nid = \"r\"\ntype = \"file\"\npaths = ['{}']\n{extra}\n",
        abs("/var/log/app/*.log")
    )
}

fn typed_rule(kind: &str, extra: &str) -> String {
    match kind {
        "file" => file_rule(extra),
        "wineventlog" => {
            format!(
                "[[rule]]\nid = \"r\"\ntype = \"wineventlog\"\nchannel = \"Security\"\n{extra}\n"
            )
        }
        _ => format!("[[rule]]\nid = \"r\"\ntype = \"{kind}\"\n{extra}\n"),
    }
}

#[test]
fn defaults() {
    let config = parse_ok("");
    assert_eq!(config.endpoint_base(), "https://ingest.example.com");
    assert_eq!(config.buffer.max_mb, 256);
    assert_eq!(config.limits.max_batch_bytes, 1024 * 1024);
    assert_eq!(config.limits.max_batch_records, 5000);
    assert_eq!(config.limits.max_requests_per_minute, 120);
    assert_eq!(config.heartbeat.interval_s, 60);
    assert_eq!(config.state_dir, paths::default_state_dir());
    assert_eq!(config.max_open_files, 1000);
    let parsed =
        AgentConfig::parse("[agent]\nendpoint = \"https://x.example.com\"\n").expect("parse");
    assert_eq!(parsed.preset_selection, ["auto"]);
}

#[test]
fn agent_section_and_legacy_flat_settings() {
    let config = load_text(&format!(
        "schema_version = 1\nbuffer = {{ max_mb = 64 }}\n{}[limits]\nmax_batch_records = 100\n[heartbeat]\ninterval_s = 30\n{}",
        base(),
        typed_rule("journald", "")
    ))
    .expect("config");
    assert_eq!(config.buffer.max_mb, 64);
    assert_eq!(config.limits.max_batch_records, 100);
    assert_eq!(config.heartbeat.interval_s, 30);

    let legacy = load_text("endpoint = \"https://ingest.example.com\"\nstate_dir = \"/tmp/wt\"\n[agent]\npresets = []\n[buffer]\nmax_mb = 32\n").expect("legacy");
    assert_eq!(legacy.endpoint, "https://ingest.example.com");
    assert_eq!(legacy.buffer.max_mb, 32);
    assert_eq!(legacy.state_dir, PathBuf::from("/tmp/wt"));

    let full = load_text("[agent]\nendpoint = \"https://ingest.example.com\"\nstate_dir = \"/tmp/wt2\"\nbuffer_max_mb = 512\npresets = []\nmax_open_files = 50\n").expect("agent");
    assert_eq!(full.buffer.max_mb, 512);
    assert_eq!(full.state_dir, PathBuf::from("/tmp/wt2"));
    assert_eq!(full.max_open_files, 50);

    for (text, want) in [
        (
            "endpoint = \"https://a.example.com\"\n[agent]\nendpoint = \"https://b.example.com\"\n",
            "agent.toml:1: endpoint is set twice",
        ),
        (
            "[agent]\nendpoint = \"https://a.example.com\"\nbuffer_max_mb = 64\n[buffer]\nmax_mb = 64\n",
            "set twice",
        ),
        ("[agent]\npresets = []\n", "endpoint is required"),
        (
            "[agent]\nendpoint = \"http://a.example.com\"\npresets = []\n",
            "agent.toml:2: endpoint must start with https://",
        ),
        (
            "[agent]\nendpoint = \"https://a.example.com\"\nbuffer_max_mb = 8\npresets = []\n",
            "agent.toml:3: buffer_max_mb must be between 16 and 65536",
        ),
        (
            "[agent]\nendpoint = \"https://a.example.com\"\nmax_open_files = 0\npresets = []\n",
            "agent.toml:3: max_open_files",
        ),
        (
            "[agent]\nendpoint = \"https://a.example.com\"\ncolour = 1\n",
            "agent.toml:3: unknown field `colour`",
        ),
        (
            "schema_version = 2\n[agent]\nendpoint = \"https://a.example.com\"\n",
            "agent.toml:1: schema_version 2 is not supported",
        ),
        ("schema_version = \"1\"\n", "agent.toml:1"),
        (
            "[agent]\nendpoint = \"https://a.example.com\"\npresets = 3\n",
            "agent.toml:3",
        ),
        (
            "[agent]\nendpoint = \"https://a.example.com\"\npresets = []\ndisable_rules = [\"Bad Id\"]\n",
            "agent.toml:4: disable_rules",
        ),
    ] {
        let err = load_text(text).expect_err(text).to_string();
        assert!(err.contains(want), "{text:?}\n{err}");
    }
}

#[test]
fn rejects_plain_http_and_odd_endpoints() {
    for endpoint in [
        "http://ingest.example.com",
        "https://",
        "https://user:pw@ingest.example.com",
        "https://ingest.example.com/?x=1",
        "https://ingest.example.com/#x",
        "https://ingest example.com",
        "ftp://ingest.example.com",
    ] {
        assert!(validate_endpoint(endpoint).is_err(), "{endpoint}");
    }
    assert!(validate_endpoint("https://ingest-01.example.net").is_ok());
    assert!(validate_endpoint("https://ingest.example.com:8443/base").is_ok());
}

#[test]
fn rejects_limits_above_server() {
    assert!(parse_err("[limits]\nmax_batch_records = 5001").contains("max_batch_records"));
    assert!(parse_err("[limits]\nmax_batch_bytes = 2097152").contains("max_batch_bytes"));
    assert!(
        parse_err("[limits]\nmax_requests_per_minute = 121").contains("max_requests_per_minute")
    );
    assert!(parse_err("[heartbeat]\ninterval_s = 1").contains("agent.toml:4: heartbeat"));
}

/// Every rule field with values that must load.
#[test]
fn every_rule_field_accepts_valid_values() {
    let cases: &[(&str, &str)] = &[
        ("file", "enabled = false"),
        ("file", "source_type = \"web.nginx-access_1\""),
        ("file", "source_label = \"web/nginx\""),
        ("file", "tags = { env = \"prod\", app = \"shop\" }"),
        ("file", "include_match = ['\\s(4|5)\\d\\d\\s']"),
        ("file", "exclude_match = ['/healthz', 'kube-probe']"),
        (
            "file",
            "redact = [{ pattern = 'password=\\S+', replace = \"password=[REDACTED]\" }]",
        ),
        ("file", "redact = [{ pattern = 'secret' }]"),
        ("file", "sample_rate = 1.0"),
        ("file", "sample_rate = 0.001"),
        (
            "file",
            "rate_limit = { events_per_second = 500, burst = 2000 }",
        ),
        ("file", "rate_limit = { events_per_second = 1 }"),
        ("file", "exclude = ['*.gz', '/var/log/app/old-*.log']"),
        ("file", "start_at = \"beginning\""),
        ("file", "start_at = \"end\""),
        (
            "file",
            "multiline = { pattern = '^\\d{4}-', negate = true, match = \"after\", max_lines = 500 }",
        ),
        (
            "file",
            "multiline = { pattern = '^\\s', match = \"before\" }",
        ),
        ("file", "parser = \"raw\""),
        ("file", "parser = \"json\""),
        ("file", "parser = \"syslog_rfc3164\""),
        ("file", "parser = \"syslog_rfc5424\""),
        ("file", "parser = \"cef\""),
        ("file", "parser = \"logfmt\""),
        ("file", "parser = \"nginx_combined\""),
        ("file", "parser = \"apache_combined\""),
        (
            "file",
            "parser = \"regex\"\nregex = '^(?P<level>\\w+) (?P<msg>.*)$'",
        ),
        ("file", "max_line_bytes = 256"),
        ("file", "max_line_bytes = 1048576"),
        ("journald", ""),
        (
            "journald",
            "matches = [\"_SYSTEMD_UNIT=ssh.service\", \"PRIORITY=3\"]",
        ),
        (
            "journald",
            "units = [\"myapp.service\", \"cron\", \"getty@tty1.service\"]",
        ),
        ("journald", "priority_max = 0"),
        ("journald", "priority_max = 7"),
        ("wineventlog", ""),
        ("wineventlog", "event_ids = [1149, 4624]"),
        ("wineventlog", "xpath = \"*[System[(EventID=4624)]]\""),
        ("macos_unified", ""),
        ("macos_unified", "predicate = 'process == \"sshd\"'"),
        ("macos_unified", "level = \"info\""),
        ("macos_unified", "level = \"default\""),
        ("macos_unified", "level = \"debug\""),
        ("journald", "include_match = ['sshd']\nsample_rate = 0.5"),
    ];
    for (kind, extra) in cases {
        let config = parse_ok(&typed_rule(kind, extra));
        assert_eq!(config.rules.len(), 1, "{extra}");
    }
    let config = parse_ok(&file_rule("rate_limit = { events_per_second = 10 }"));
    assert_eq!(config.rules[0].rate_limit.map(|r| r.burst()), Some(10));
    let config = parse_ok(&typed_rule(
        "journald",
        "units = [\"cron\", \"a.socket\"]\nmatches = [\"PRIORITY=3\"]",
    ));
    assert_eq!(
        config.rules[0].journal_matches(),
        [
            "_SYSTEMD_UNIT=cron.service",
            "_SYSTEMD_UNIT=a.socket",
            "PRIORITY=3"
        ]
    );
}

/// Every rule field with values that must be refused, and the message that says why.
#[test]
fn every_rule_field_rejects_invalid_values() {
    let cases: &[(&str, &str, &str)] = &[
        ("file", "enabled = \"yes\"", "invalid type"),
        ("file", "source_type = \"a b\"", "source_type"),
        ("file", "source_label = \"\"", "source_label"),
        ("file", "source_label = \"a\\u0007\"", "source_label"),
        ("file", "tags = { \"\" = \"x\" }", "tags"),
        ("file", "tags = { env = 1 }", "invalid type"),
        ("file", "include_match = ['(']", "include_match"),
        ("file", "include_match = 'x'", "invalid type"),
        ("file", "exclude_match = ['(?=x)']", "exclude_match"),
        ("file", "redact = [{ pattern = '[' }]", "redact"),
        (
            "file",
            "redact = [{ replace = 'x' }]",
            "missing field `pattern`",
        ),
        (
            "file",
            "redact = [{ pattern = 'x', with = 'y' }]",
            "unknown field `with`",
        ),
        ("file", "sample_rate = 0.0", "sample_rate"),
        ("file", "sample_rate = 1.5", "sample_rate"),
        ("file", "sample_rate = -1.0", "sample_rate"),
        ("file", "sample_rate = nan", "sample_rate"),
        (
            "file",
            "rate_limit = { events_per_second = 0 }",
            "events_per_second",
        ),
        (
            "file",
            "rate_limit = { events_per_second = 5, burst = 0 }",
            "burst",
        ),
        (
            "file",
            "rate_limit = { burst = 5 }",
            "missing field `events_per_second`",
        ),
        ("file", "exclude = ['[']", "exclude"),
        ("file", "exclude = ['']", "exclude"),
        ("file", "start_at = \"middle\"", "unknown variant `middle`"),
        ("file", "multiline = { pattern = '(' }", "multiline.pattern"),
        (
            "file",
            "multiline = { pattern = 'a', max_lines = 0 }",
            "max_lines",
        ),
        (
            "file",
            "multiline = { pattern = 'a', match = \"around\" }",
            "unknown variant",
        ),
        (
            "file",
            "multiline = { negate = true }",
            "missing field `pattern`",
        ),
        ("file", "parser = \"xml\"", "unknown variant `xml`"),
        ("file", "parser = \"regex\"", "needs a regex"),
        (
            "file",
            "parser = \"regex\"\nregex = '(\\w+)'",
            "named capture",
        ),
        ("file", "parser = \"regex\"\nregex = '(?P<a>'", "regex"),
        (
            "file",
            "parser = \"json\"\nregex = '(?P<a>x)'",
            "only used with parser",
        ),
        ("file", "max_line_bytes = 255", "max_line_bytes"),
        ("file", "max_line_bytes = 1048577", "max_line_bytes"),
        (
            "file",
            "channel = \"Security\"",
            "channel is for type \"wineventlog\"",
        ),
        ("file", "units = [\"x\"]", "units is for type \"journald\""),
        (
            "file",
            "predicate = 'x'",
            "predicate is for type \"macos_unified\"",
        ),
        ("journald", "matches = [\"unit\"]", "FIELD=value"),
        ("journald", "matches = [\"_unit=x\"]", "FIELD=value"),
        ("journald", "units = [\"-x\"]", "systemd unit"),
        ("journald", "units = [\"a b\"]", "systemd unit"),
        ("journald", "priority_max = 8", "priority_max"),
        ("journald", "priority_max = -1", "invalid value"),
        ("journald", "paths = ['/x']", "paths is for type \"file\""),
        (
            "journald",
            "parser = \"json\"",
            "parser is for type \"file\"",
        ),
        (
            "journald",
            "max_line_bytes = 1024",
            "max_line_bytes is for type \"file\"",
        ),
        (
            "journald",
            "level = \"info\"",
            "level is for type \"macos_unified\"",
        ),
        ("wineventlog", "event_ids = [0]", "event_ids"),
        ("wineventlog", "event_ids = [70000]", "event_ids"),
        ("wineventlog", "xpath = \"\"", "xpath"),
        (
            "wineventlog",
            "start_at = \"beginning\"",
            "start_at is for type \"file\"",
        ),
        ("macos_unified", "predicate = ''", "predicate"),
        (
            "macos_unified",
            "level = \"error\"",
            "unknown variant `error`",
        ),
        (
            "macos_unified",
            "priority_max = 3",
            "priority_max is for type \"journald\"",
        ),
    ];
    for (kind, extra, want) in cases {
        let got = parse_err(&typed_rule(kind, extra));
        assert!(got.contains(want), "{kind} {extra:?}: {got}");
        // Every message points at a line.
        assert!(got.starts_with("agent.toml:"), "{kind} {extra:?}: {got}");
    }
}

#[test]
fn rule_ids_types_and_paths() {
    let bad = [
        (
            "[[rule]]\nid = \"Bad\"\ntype = \"journald\"",
            "id must match",
        ),
        ("[[rule]]\nid = \"\"\ntype = \"journald\"", "id must match"),
        (
            &format!("[[rule]]\nid = \"{}\"\ntype = \"journald\"", "a".repeat(65)),
            "id must match",
        ),
        (
            "[[rule]]\nid = \"a\"\ntype = \"syslog\"",
            "unknown variant `syslog`",
        ),
        ("[[rule]]\nid = \"a\"\ntype = \"command\"", "not supported"),
        ("[[rule]]\ntype = \"journald\"", "missing field `id`"),
        ("[[rule]]\nid = \"a\"", "missing field `type`"),
        ("[[rule]]\nid = \"a\"\ntype = \"file\"", "at least one path"),
        (
            "[[rule]]\nid = \"a\"\ntype = \"file\"\npaths = [\"rel/x\"]",
            "absolute",
        ),
        (
            &format!(
                "[[rule]]\nid = \"a\"\ntype = \"file\"\npaths = ['{}']",
                abs("/var/log/../../etc/shadow")
            ),
            ". or ..",
        ),
        (
            &format!(
                "[[rule]]\nid = \"a\"\ntype = \"file\"\npaths = ['{}']",
                abs("/var/log/[.log")
            ),
            "valid glob",
        ),
        (
            "[[rule]]\nid = \"a\"\ntype = \"journald\"\n[[rule]]\nid = \"a\"\ntype = \"journald\"",
            "agent.toml:7: rule id \"a\" is used more than once (first defined at agent.toml:4)",
        ),
    ];
    for (extra, want) in bad {
        let got = parse_err(extra);
        assert!(got.contains(want), "{extra:?}: {got}");
    }
    for id in ["a", "nginx-access", "linux-core.kernel", "0_x"] {
        assert!(is_valid_rule_id(id), "{id}");
    }
}

#[test]
fn rules_cannot_read_the_agents_own_files() {
    let state = abs("/var/lib/wedgetail-agent");
    let text = format!(
        "[agent]\nendpoint = \"https://ingest.example.com\"\nstate_dir = '{state}'\npresets = []\n"
    );
    for path in ["/credential", "/*", "/buffer/**/*.seg"] {
        let path = format!("{state}{}", abs(path).trim_start_matches("C:"));
        let err = load_text(&format!(
            "{text}[[rule]]\nid = \"a\"\ntype = \"file\"\npaths = ['{path}']\n"
        ))
        .expect_err(&path)
        .to_string();
        assert!(err.contains("agent's own files"), "{path}: {err}");
    }
    let err = AgentConfig::from_sources(
        Path::new("agent.toml"),
        &format!(
            "[agent]\nendpoint = \"https://ingest.example.com\"\npresets = []\n[[rule]]\nid = \"a\"\ntype = \"file\"\npaths = ['{}']\n",
            abs("/etc/wedgetail-agent/rules.d/*.toml")
        ),
        &[],
        &[],
        "linux",
        Some(PathBuf::from(abs("/etc/wedgetail-agent"))),
    )
    .expect_err("config dir")
    .to_string();
    assert!(err.contains("agent's own files"), "{err}");
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("wt-config-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rules.d")).expect("mkdir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn load_merges_rules_d_in_name_order() {
    let dir = TempDir::new("order");
    let dir = &dir.0;
    std::fs::write(
        dir.join("agent.toml"),
        base() + "[[rule]]\nid = \"a\"\ntype = \"journald\"\n",
    )
    .expect("write");
    std::fs::write(
        dir.join("rules.d").join("20-c.toml"),
        "schema_version = 1\n[[rule]]\nid = \"c\"\ntype = \"journald\"\n",
    )
    .expect("write");
    std::fs::write(
        dir.join("rules.d").join("10-b.toml"),
        "[[rule]]\nid = \"b\"\ntype = \"journald\"\n",
    )
    .expect("write");
    std::fs::write(
        dir.join("rules.d").join("9-z.toml"),
        "[[rule]]\nid = \"z\"\ntype = \"journald\"\n",
    )
    .expect("write");
    std::fs::write(dir.join("rules.d").join("notes.txt"), "ignored").expect("write");
    let config = AgentConfig::load(&dir.join("agent.toml")).expect("loads");
    let ids: Vec<_> = config.rules.iter().map(|r| r.id.as_str()).collect();
    // Byte-wise order: "10-b" < "20-c" < "9-z".
    assert_eq!(ids, ["a", "b", "c", "z"]);
    assert_eq!(config.rules[1].origin.as_ref().map(|o| o.line), Some(1));
    assert_eq!(config.config_dir.as_deref(), Some(dir.as_path()));

    std::fs::write(
        dir.join("rules.d").join("30-bad.toml"),
        "\n[[rule]]\nid = \"d\"\n",
    )
    .expect("write");
    std::fs::write(
        dir.join("rules.d").join("40-dup.toml"),
        "\n\n[[rule]]\nid = \"b\"\ntype = \"journald\"\n",
    )
    .expect("write");
    std::fs::write(
        dir.join("rules.d").join("50-settings.toml"),
        "[agent]\nendpoint = \"https://other.example.com\"\n",
    )
    .expect("write");
    let err = AgentConfig::load(&dir.join("agent.toml")).expect_err("bad files");
    let text = err.to_string();
    let bad = dir.join("rules.d").join("30-bad.toml");
    assert!(
        text.contains(&format!("{}:2: missing field `type`", bad.display())),
        "{text}"
    );
    let dup = dir.join("rules.d").join("40-dup.toml");
    let first = dir.join("rules.d").join("10-b.toml");
    assert!(
        text.contains(&format!(
            "{}:3: rule id \"b\" is used more than once (first defined at {}:1)",
            dup.display(),
            first.display()
        )),
        "{text}"
    );
    assert!(
        text.contains("agent settings belong in agent.toml"),
        "{text}"
    );
    assert_eq!(err.problems.len(), 3, "{text}");
}

#[test]
fn presets_load_first_and_rules_can_be_disabled() {
    let main = "[agent]\nendpoint = \"https://ingest.example.com\"\npresets = [\"auto\", \"linux-extra\"]\ndisable_rules = [\"linux-core.kernel\", \"mine\", \"windows-security.log\"]\n[[rule]]\nid = \"mine\"\ntype = \"journald\"\n";
    let config = AgentConfig::from_sources(
        Path::new("agent.toml"),
        main,
        &[],
        TEST_REGISTRY,
        "linux",
        None,
    )
    .expect("config");
    assert_eq!(
        config.presets,
        ["linux-core", "linux-auditd", "linux-extra"]
    );
    let rules: Vec<(&str, bool)> = config
        .rules
        .iter()
        .map(|r| (r.id.as_str(), r.enabled))
        .collect();
    assert_eq!(
        rules,
        [
            ("linux-core.journal", true),
            ("linux-core.kernel", false),
            ("linux-auditd.log", true),
            ("linux-extra.x", true),
            ("mine", false),
        ]
    );
    assert_eq!(
        config.rules[1].origin.as_ref().map(ToString::to_string),
        Some("preset:linux-core:5".to_owned())
    );
    assert_eq!(config.warnings.len(), 1, "{:?}", config.warnings);

    // Presets are on by default, and a user rule cannot reuse a preset rule id.
    let main = "[agent]\nendpoint = \"https://ingest.example.com\"\n[[rule]]\nid = \"linux-core.kernel\"\ntype = \"journald\"\n";
    let err = AgentConfig::from_sources(
        Path::new("agent.toml"),
        main,
        &[],
        TEST_REGISTRY,
        "linux",
        None,
    )
    .expect_err("duplicate")
    .to_string();
    assert!(
        err.contains("first defined at preset:linux-core:5"),
        "{err}"
    );

    let main = "[agent]\nendpoint = \"https://ingest.example.com\"\npresets = [\"linux-cor\"]\n";
    let err = AgentConfig::from_sources(
        Path::new("agent.toml"),
        main,
        &[],
        TEST_REGISTRY,
        "linux",
        None,
    )
    .expect_err("unknown")
    .to_string();
    assert!(
        err.contains("agent.toml:3: presets: unknown preset \"linux-cor\""),
        "{err}"
    );

    let config = AgentConfig::from_sources(
        Path::new("agent.toml"),
        "[agent]\nendpoint = \"https://ingest.example.com\"\npresets = \"auto\"\n",
        &[],
        TEST_REGISTRY,
        "windows",
        None,
    )
    .expect("windows");
    assert_eq!(config.presets, ["windows-security"]);
}

static BAD_PRESETS: &[Preset] = &[Preset {
    id: "linux-bad",
    os: "linux",
    auto: presets::Auto::Default,
    toml: "[[rule]]\nid = \"other.x\"\ntype = \"journald\"\n[agent]\nendpoint = \"https://x.example.com\"\n",
}];

#[test]
fn presets_must_namespace_ids_and_hold_only_rules() {
    let err = AgentConfig::from_sources(
        Path::new("agent.toml"),
        &base().replace("presets = []", "presets = \"auto\""),
        &[],
        BAD_PRESETS,
        "linux",
        None,
    )
    .expect_err("bad preset")
    .to_string();
    assert!(err.contains("must start with \"linux-bad.\""), "{err}");
    assert!(
        err.contains("preset:linux-bad:4: agent settings belong in agent.toml"),
        "{err}"
    );
}

#[test]
fn errors_render_one_per_line_with_file_and_line() {
    let err = parse_err(&format!(
        "{}{}",
        typed_rule("journald", "priority_max = 9"),
        "[[rule]]\nid = \"two\"\ntype = \"file\"\nsample_rate = 2.0\n"
    ));
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(lines.len(), 3, "{err}");
    assert!(
        lines[0].starts_with("agent.toml:4: rule \"r\": priority_max"),
        "{err}"
    );
    assert!(
        lines[1].starts_with("agent.toml:8: rule \"two\": sample_rate"),
        "{err}"
    );
    assert!(
        lines[2].starts_with("agent.toml:8: rule \"two\": type \"file\" needs"),
        "{err}"
    );
}

/// `schema/rules.v1.json` is generated from these types. Regenerate with
/// `UPDATE_SCHEMA=1 cargo test -p agent-config schema`.
#[test]
fn json_schema_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schema/rules.v1.json");
    let want = json_schema();
    if std::env::var_os("UPDATE_SCHEMA").is_some() {
        std::fs::write(&path, &want).expect("write schema");
    }
    let have = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        have == want,
        "{} is stale: run `UPDATE_SCHEMA=1 cargo test -p agent-config schema` and commit it",
        path.display()
    );
    let schema: serde_json::Value = serde_json::from_str(&want).expect("json");
    let rule = &schema["$defs"]["Rule"]["properties"];
    for field in [
        "id",
        "type",
        "paths",
        "exclude",
        "start_at",
        "multiline",
        "parser",
        "regex",
        "source_label",
        "tags",
        "include_match",
        "exclude_match",
        "redact",
        "sample_rate",
        "rate_limit",
        "max_line_bytes",
        "channel",
        "event_ids",
        "xpath",
        "predicate",
        "level",
        "units",
        "priority_max",
    ] {
        assert!(rule.get(field).is_some(), "schema has no rule.{field}");
    }
    assert!(rule.get("origin").is_none());
    let agent = &schema["$defs"]["AgentSection"]["properties"];
    for field in [
        "endpoint",
        "buffer_max_mb",
        "presets",
        "disable_rules",
        "max_open_files",
    ] {
        assert!(agent.get(field).is_some(), "schema has no agent.{field}");
    }
}

/// The packaged example config and the docs examples load.
#[test]
fn shipped_examples_load() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let example =
        std::fs::read_to_string(root.join("packaging/common/agent.toml")).expect("example");
    // The example leaves the endpoint commented out until the operator sets it.
    let text = example.replace(
        "# endpoint = \"https://<your ingest URL>\"",
        "endpoint = \"https://ingest.example.com\"",
    );
    let config = AgentConfig::from_sources(Path::new("agent.toml"), &text, &[], &[], "linux", None);
    if let Err(e) = config {
        panic!("packaging/common/agent.toml: {e}");
    }
}
