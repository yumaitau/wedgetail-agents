//! Per-rule checks the types cannot express. Each returns every problem it finds.

use std::path::{Path, PathBuf};

use crate::compile::CompiledRule;
use crate::multiline::Multiline;
use crate::{FileFormat, ParserKind, Rule, RuleKind, StartAt, is_valid_rule_id, paths};

/// Most entries in `paths`, `exclude`, `units`.
const MAX_PATHS: usize = 64;

pub(crate) fn rule(rule: &Rule, protected: &[PathBuf]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut err = |m: String| errors.push(m);
    if !is_valid_rule_id(&rule.id) {
        err("id must match [a-z0-9][a-z0-9._-]{0,63}".into());
    }
    if let Some(st) = &rule.source_type
        && (st.is_empty()
            || st.len() > 64
            || !st
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
    {
        err("source_type must be 1-64 characters of [A-Za-z0-9._-]".into());
    }
    if rule
        .source_label
        .as_ref()
        .is_some_and(|l| l.is_empty() || l.len() > 256 || l.chars().any(char::is_control))
    {
        err("source_label must be 1-256 characters with no control characters".into());
    }
    if rule.tags.len() > 32
        || rule.tags.iter().any(|(k, v)| {
            k.is_empty()
                || k.len() > 64
                || v.len() > 256
                || k.chars().chain(v.chars()).any(char::is_control)
        })
    {
        err(
            "tags: at most 32, keys 1-64 characters, values up to 256, no control characters"
                .into(),
        );
    }
    if !(rule.sample_rate.is_finite() && rule.sample_rate > 0.0 && rule.sample_rate <= 1.0) {
        err(format!(
            "sample_rate must be greater than 0 and at most 1, got {}",
            rule.sample_rate
        ));
    }
    if let Some(rl) = &rule.rate_limit {
        if !(1..=1_000_000).contains(&rl.events_per_second) {
            err("rate_limit.events_per_second must be between 1 and 1000000".into());
        }
        if rl.burst.is_some_and(|b| !(1..=10_000_000).contains(&b)) {
            err("rate_limit.burst must be between 1 and 10000000".into());
        }
    }
    if rule.redact.iter().any(|r| r.replace.len() > 256) {
        err("redact: replace is at most 256 characters".into());
    }
    // include_match, exclude_match, redact and parser/regex.
    if let Err(e) = CompiledRule::new(rule) {
        err(e);
    }

    let file_only = [
        ("paths", !rule.paths.is_empty()),
        ("exclude", !rule.exclude.is_empty()),
        ("format", rule.format != FileFormat::Lines),
        ("start_at", rule.start_at != StartAt::End),
        ("multiline", rule.multiline.is_some()),
        (
            "parser",
            rule.parser != ParserKind::Raw || rule.regex.is_some(),
        ),
        ("max_line_bytes", rule.max_line_bytes.is_some()),
    ];
    let journald_only = [
        ("matches", !rule.matches.is_empty()),
        ("units", !rule.units.is_empty()),
        ("priority_max", rule.priority_max.is_some()),
    ];
    let wineventlog_only = [
        ("channel", rule.channel.is_some()),
        ("event_ids", !rule.event_ids.is_empty()),
        ("xpath", rule.xpath.is_some()),
    ];
    let macos_only = [
        ("predicate", rule.predicate.is_some()),
        ("level", rule.level.is_some()),
    ];
    let bsm_only = [
        ("classes", !rule.classes.is_empty()),
        ("exclude_events", !rule.exclude_events.is_empty()),
    ];
    for (kind, fields) in [
        (RuleKind::File, &file_only[..]),
        (RuleKind::Journald, &journald_only[..]),
        (RuleKind::Wineventlog, &wineventlog_only[..]),
        (RuleKind::MacosUnified, &macos_only[..]),
        (RuleKind::MacosBsm, &bsm_only[..]),
    ] {
        if kind == rule.kind {
            continue;
        }
        for (name, set) in fields {
            if *set {
                err(format!(
                    "{name} is for type \"{}\" rules, not \"{}\"",
                    kind.name(),
                    rule.kind.name()
                ));
            }
        }
    }

    match rule.kind {
        RuleKind::File => file(rule, protected, &mut err),
        RuleKind::Journald => journald(rule, &mut err),
        RuleKind::Wineventlog => wineventlog(rule, &mut err),
        RuleKind::MacosUnified => {
            if rule
                .predicate
                .as_ref()
                .is_some_and(|p| p.is_empty() || p.len() > 4096 || p.contains('\0'))
            {
                err("predicate must be 1-4096 characters".into());
            }
        }
        RuleKind::MacosBsm => {
            if rule.classes.len() > 32 {
                err("classes: at most 32".into());
            }
            for class in &rule.classes {
                let valid = (1..=16).contains(&class.len())
                    && class
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
                if !valid {
                    err(format!(
                        "classes: {class:?} is not an audit class name (lo, aa, ad, ex, ...)"
                    ));
                }
            }
            if rule.exclude_events.len() > 256 {
                err("exclude_events: at most 256".into());
            }
            for event in &rule.exclude_events {
                let valid = (1..=64).contains(&event.len())
                    && event
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_');
                if !valid {
                    err(format!(
                        "exclude_events: {event:?} is not an audit event name (AUE_...)"
                    ));
                }
            }
        }
    }
    errors
}

fn file(rule: &Rule, protected: &[PathBuf], err: &mut impl FnMut(String)) {
    if rule.paths.is_empty() {
        err("type \"file\" needs at least one path".into());
    }
    if rule.paths.len() > MAX_PATHS || rule.exclude.len() > MAX_PATHS {
        err(format!(
            "at most {MAX_PATHS} paths and {MAX_PATHS} exclude patterns"
        ));
    }
    for path in &rule.paths {
        let shown = path.display();
        let Some(text) = path.to_str() else {
            err(format!("path {shown} is not valid UTF-8"));
            continue;
        };
        if !path.is_absolute() {
            err(format!("path {shown} must be absolute"));
            continue;
        }
        if text.len() > 4096 || text.contains('\0') {
            err(format!("path {shown} is too long"));
            continue;
        }
        if paths::has_dot_components(path) {
            err(format!("path {shown} must not contain . or .. components"));
            continue;
        }
        if paths::has_glob(text)
            && let Err(e) = glob::Pattern::new(text)
        {
            err(format!("path {shown} is not a valid glob: {e}"));
            continue;
        }
        if let Some(dir) = protects(path, protected) {
            err(format!(
                "path {shown} is inside {}, which holds the agent's own files",
                dir.display()
            ));
        }
    }
    for pattern in &rule.exclude {
        if pattern.is_empty() || pattern.len() > 4096 {
            err("exclude patterns must be 1-4096 characters".into());
        } else if let Err(e) = glob::Pattern::new(pattern) {
            err(format!("exclude {pattern:?} is not a valid glob: {e}"));
        }
    }
    if rule.format == FileFormat::Lastlog
        && (rule.paths.len() != 1
            || rule
                .paths
                .iter()
                .any(|p| paths::has_glob(&p.to_string_lossy())))
    {
        err("format = \"lastlog\" reads exactly one file: one path, no globs".into());
    }
    if rule.format != FileFormat::Lines {
        let lines_only = [
            ("multiline", rule.multiline.is_some()),
            (
                "parser",
                rule.parser != ParserKind::Raw || rule.regex.is_some(),
            ),
            (
                "max_line_bytes",
                rule.max_line_bytes.is_some() && rule.format != FileFormat::Auditd,
            ),
        ];
        for (name, set) in lines_only {
            if set {
                err(format!(
                    "{name} does not apply to format = \"{}\"",
                    rule.format.name()
                ));
            }
        }
    }
    if let Some(m) = &rule.multiline
        && let Err(e) = Multiline::new(m)
    {
        err(e);
    }
    if rule
        .max_line_bytes
        .is_some_and(|n| !(256..=1024 * 1024).contains(&n))
    {
        err("max_line_bytes must be between 256 and 1048576".into());
    }
}

/// The protected directory a path (or its glob root) lies in, comparing both as written and
/// canonicalised.
fn protects<'a>(path: &Path, protected: &'a [PathBuf]) -> Option<&'a PathBuf> {
    let root = paths::glob_root(path);
    let candidates = [
        path.to_path_buf(),
        root.clone(),
        paths::canonical_or_same(&root),
    ];
    protected.iter().find(|dir| {
        let canonical = paths::canonical_or_same(dir);
        candidates
            .iter()
            .any(|c| paths::is_within(c, dir) || paths::is_within(c, &canonical))
    })
}

fn journald(rule: &Rule, err: &mut impl FnMut(String)) {
    if let Some(m) = rule.matches.iter().find(|m| !is_valid_journal_match(m)) {
        err(format!(
            "journald match {m:?} must be FIELD=value with FIELD in [A-Z0-9_]"
        ));
    }
    if rule.units.len() > MAX_PATHS {
        err(format!("at most {MAX_PATHS} units"));
    }
    if let Some(u) = rule.units.iter().find(|u| !is_valid_unit(u)) {
        err(format!(
            "unit {u:?} must be a systemd unit name such as ssh.service"
        ));
    }
    if rule.priority_max.is_some_and(|p| p > 7) {
        err("priority_max must be between 0 (emerg) and 7 (debug)".into());
    }
}

fn wineventlog(rule: &Rule, err: &mut impl FnMut(String)) {
    let channel = rule.channel.as_deref().unwrap_or("");
    if channel.is_empty() || channel.len() > 256 || channel.chars().any(char::is_control) {
        err("type \"wineventlog\" needs a channel of 1-256 characters".into());
    }
    if rule
        .xpath
        .as_ref()
        .is_some_and(|x| x.is_empty() || x.len() > 4096 || x.contains('\0'))
    {
        err("xpath must be 1-4096 characters".into());
    }
    if rule.event_ids.iter().any(|&id| id == 0 || id > 65_535) || rule.event_ids.len() > 256 {
        err("event_ids must be 1-65535, at most 256 of them".into());
    }
}

fn is_valid_journal_match(m: &str) -> bool {
    let Some((field, value)) = m.split_once('=') else {
        return false;
    };
    !field.is_empty()
        && field.len() <= 64
        && field
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && value.len() <= 1024
        && !value.contains('\0')
}

/// systemd unit names: `[A-Za-z0-9:_.\\@-]`, not starting with `-` (so never an option).
fn is_valid_unit(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 256
        && !u.starts_with(['-', '.'])
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":_.\\@-".contains(&b))
}
