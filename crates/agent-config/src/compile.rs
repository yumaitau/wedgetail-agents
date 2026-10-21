//! Rule regular expressions compiled once: include and exclude matching, redaction and the
//! parser. The `regex` crate runs in time linear in the input (no backtracking), and the
//! compiled size of every expression is capped, so a rule cannot make the agent hang or
//! balloon.

use regex::{NoExpand, Regex, RegexBuilder, RegexSet, RegexSetBuilder};

use crate::{Parser, Rule};

/// Longest pattern accepted for `include_match`, `exclude_match`, `redact` and `multiline`.
pub const MAX_PATTERN_CHARS: usize = 1024;
/// Longest `regex` parser expression.
pub const MAX_PARSER_REGEX_CHARS: usize = 4096;
/// Most entries in each of `include_match`, `exclude_match` and `redact`.
pub const MAX_PATTERNS: usize = 32;
/// Cap on one compiled expression (bytes of program).
const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// Cap on the lazy DFA cache of one expression.
const REGEX_DFA_LIMIT: usize = 2 << 20;

/// Compile `pattern` with the size caps. `what` names the setting in errors.
pub fn regex(what: &str, pattern: &str, max_chars: usize) -> Result<Regex, String> {
    check_len(what, pattern, max_chars)?;
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_LIMIT)
        .build()
        .map_err(|e| format!("{what}: {}", one_line(&e.to_string())))
}

/// [`regex`] for byte input (multiline matching runs before lines are decoded).
pub fn bytes_regex(
    what: &str,
    pattern: &str,
    max_chars: usize,
) -> Result<regex::bytes::Regex, String> {
    check_len(what, pattern, max_chars)?;
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_LIMIT)
        .build()
        .map_err(|e| format!("{what}: {}", one_line(&e.to_string())))
}

fn regex_set(what: &str, patterns: &[String]) -> Result<Option<RegexSet>, String> {
    if patterns.is_empty() {
        return Ok(None);
    }
    if patterns.len() > MAX_PATTERNS {
        return Err(format!("{what}: at most {MAX_PATTERNS} patterns"));
    }
    for p in patterns {
        // Compiled one by one first so an error names the bad pattern.
        regex(what, p, MAX_PATTERN_CHARS)?;
    }
    RegexSetBuilder::new(patterns)
        .size_limit(REGEX_SIZE_LIMIT * 4)
        .dfa_size_limit(REGEX_DFA_LIMIT * 2)
        .build()
        .map(Some)
        .map_err(|e| format!("{what}: {}", one_line(&e.to_string())))
}

fn check_len(what: &str, pattern: &str, max_chars: usize) -> Result<(), String> {
    if pattern.is_empty() {
        return Err(format!("{what}: the pattern is empty"));
    }
    if pattern.chars().count() > max_chars {
        return Err(format!(
            "{what}: the pattern is longer than {max_chars} characters"
        ));
    }
    Ok(())
}

/// regex errors draw a caret diagram over several lines; keep the last line, which says what
/// is wrong.
fn one_line(error: &str) -> String {
    error
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or(error)
        .trim()
        .trim_start_matches("error: ")
        .to_owned()
}

/// The parts of a rule that run on every event, compiled.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    include: Option<RegexSet>,
    exclude: Option<RegexSet>,
    redact: Vec<(Regex, String)>,
    pub parser: Parser,
}

impl CompiledRule {
    pub fn new(rule: &Rule) -> Result<Self, String> {
        let redact = rule
            .redact
            .iter()
            .map(|r| {
                Ok((
                    regex("redact", &r.pattern, MAX_PATTERN_CHARS)?,
                    r.replace.clone(),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        if redact.len() > MAX_PATTERNS {
            return Err(format!("redact: at most {MAX_PATTERNS} entries"));
        }
        Ok(Self {
            include: regex_set("include_match", &rule.include_match)?,
            exclude: regex_set("exclude_match", &rule.exclude_match)?,
            redact,
            parser: Parser::new(rule.parser, rule.regex.as_deref())?,
        })
    }

    /// Whether an event with this text passes `include_match` and `exclude_match`.
    pub fn keeps(&self, text: &str) -> bool {
        self.include.as_ref().is_none_or(|set| set.is_match(text))
            && self.exclude.as_ref().is_none_or(|set| !set.is_match(text))
    }

    /// Whether `include_match` or `exclude_match` is set.
    pub fn has_filters(&self) -> bool {
        self.include.is_some() || self.exclude.is_some()
    }

    pub fn has_redactions(&self) -> bool {
        !self.redact.is_empty()
    }

    /// Apply every redaction in order. Returns `None` when nothing matched.
    pub fn redact(&self, text: &str) -> Option<String> {
        let mut out: Option<String> = None;
        for (re, replace) in &self.redact {
            let current = out.as_deref().unwrap_or(text);
            if re.is_match(current) {
                out = Some(re.replace_all(current, NoExpand(replace)).into_owned());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(extra: &str) -> Rule {
        toml::from_str(&format!("id = \"r\"\ntype = \"file\"\n{extra}")).expect("rule")
    }

    #[test]
    fn include_and_exclude() {
        let c = CompiledRule::new(&rule(
            r#"include_match = ['\s(4|5)\d\d\s', 'ERROR']
exclude_match = ['/healthz']"#,
        ))
        .expect("compile");
        assert!(c.keeps("GET /shop 500 12"));
        assert!(c.keeps("ERROR disk full"));
        assert!(!c.keeps("GET /shop 200 12"));
        assert!(!c.keeps("GET /healthz 503 1"));
        let all = CompiledRule::new(&rule("")).expect("compile");
        assert!(all.keeps("anything"));
    }

    #[test]
    fn redaction_is_literal_and_ordered() {
        let c = CompiledRule::new(&rule(
            r#"redact = [
  { pattern = 'password=\S+', replace = "password=[REDACTED]" },
  { pattern = '\b\d{4}-\d{4}-\d{4}-\d{4}\b' },
  { pattern = 'token=(\w+)', replace = "token=$1" },
]"#,
        ))
        .expect("compile");
        assert_eq!(
            c.redact("login password=hunter2 card 4111-1111-1111-1111 token=abc"),
            Some("login password=[REDACTED] card [REDACTED] token=$1".into())
        );
        assert_eq!(c.redact("nothing here"), None);
    }

    #[test]
    fn bad_patterns_are_rejected_with_the_setting_name() {
        for (extra, want) in [
            ("include_match = ['(']", "include_match"),
            ("exclude_match = ['[z-a]']", "exclude_match"),
            ("redact = [{ pattern = '' }]", "empty"),
            ("redact = [{ pattern = '(?<n>a' }]", "redact"),
            // Look-around and backreferences are not supported by a linear-time engine.
            ("include_match = ['(?=a)']", "include_match"),
            ("include_match = ['(a)\\1']", "include_match"),
        ] {
            let err = CompiledRule::new(&rule(extra)).expect_err(extra);
            assert!(err.contains(want), "{extra}: {err}");
            assert!(!err.contains('\n'), "{err}");
        }
        let long = format!("include_match = ['{}']", "a".repeat(MAX_PATTERN_CHARS + 1));
        assert!(CompiledRule::new(&rule(&long)).is_err());
        let many = format!(
            "include_match = [{}]",
            vec!["'a'"; MAX_PATTERNS + 1].join(",")
        );
        assert!(CompiledRule::new(&rule(&many)).is_err());
        // A huge repetition blows the compiled size cap rather than memory.
        let huge = "include_match = ['(\\w{1000}){1000}']";
        assert!(CompiledRule::new(&rule(huge)).is_err());
    }

    #[test]
    fn pathological_input_is_linear() {
        // (a+)+$ backtracks exponentially in other engines.
        let c = CompiledRule::new(&rule("include_match = ['(a+)+$']")).expect("compile");
        let input = format!("{}!", "a".repeat(100_000));
        let start = std::time::Instant::now();
        assert!(!c.keeps(&input));
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
}
