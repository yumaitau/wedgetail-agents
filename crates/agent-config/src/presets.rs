//! Built-in presets: curated rule files compiled into the agent.
//!
//! A preset is an ordinary rule file (schema 1, only `[[rule]]` tables) under
//! `presets/<os>/<id>.toml` at the repository root, registered in [`BUILTIN`]. Every rule id in
//! a preset starts with `<preset id>.` (for example `linux-core.sshd`) so operators can switch
//! single rules off with `[agent] disable_rules`.
//!
//! `[agent] presets` selects them: a list of preset ids, `"auto"` (the default), or a list
//! that includes `"auto"` plus opt-in presets. `"auto"` picks, for the running OS, every
//! preset whose [`Auto`] is [`Auto::Default`], and every [`Auto::Detect`] preset whose
//! detection function returns true.
//!
//! To add a preset (tickets #242 to #244):
//!
//! ```text
//! Preset {
//!     id: "linux-auditd",
//!     os: "linux",
//!     auto: Auto::Detect(detect::auditd),
//!     toml: include_str!("../../../presets/linux/linux-auditd.toml"),
//! },
//! ```
//!
//! The tests in this module load every registered preset, so a broken preset fails CI.

/// The value in `presets` that selects presets by detection.
pub const AUTO: &str = "auto";

/// Whether `"auto"` selects a preset.
#[derive(Debug, Clone, Copy)]
pub enum Auto {
    /// Selected on every host of its OS.
    Default,
    /// Selected when the function returns true. It runs once per (re)load and must be cheap
    /// and side-effect free: check that a file, directory or channel exists.
    Detect(fn() -> bool),
    /// Only when named in `presets`.
    OptIn,
}

/// One built-in preset.
#[derive(Debug, Clone, Copy)]
pub struct Preset {
    /// `[a-z0-9-]`, prefixed with the OS family: `linux-core`, `windows-security`,
    /// `macos-core`.
    pub id: &'static str,
    /// `std::env::consts::OS` value: `linux`, `windows` or `macos`.
    pub os: &'static str,
    pub auto: Auto,
    /// The rule file, usually `include_str!`.
    pub toml: &'static str,
}

/// Every preset compiled into this agent. Empty until the per-OS preset tickets land.
pub static BUILTIN: &[Preset] = &[];

/// The result of resolving a `presets` selection.
#[derive(Debug, Default)]
pub struct Selection<'a> {
    /// Presets to load, in registry order.
    pub presets: Vec<&'a Preset>,
    /// Ids that name no preset (configuration errors).
    pub errors: Vec<String>,
    /// Presets named for another OS (skipped).
    pub warnings: Vec<String>,
}

/// Resolve `selection` against `registry` for `os`.
pub fn select<'a>(selection: &[String], registry: &'a [Preset], os: &str) -> Selection<'a> {
    let mut out = Selection::default();
    let auto = selection.iter().any(|s| s == AUTO);
    for name in selection.iter().filter(|s| *s != AUTO) {
        match registry.iter().find(|p| p.id == name) {
            None => {
                let available: Vec<&str> = registry
                    .iter()
                    .filter(|p| p.os == os)
                    .map(|p| p.id)
                    .collect();
                let available = if available.is_empty() {
                    "none".to_owned()
                } else {
                    available.join(", ")
                };
                out.errors.push(format!(
                    "presets: unknown preset {name:?} (\"auto\" or one of: {available})"
                ));
            }
            Some(p) if p.os != os => out.warnings.push(format!(
                "presets: {name:?} is a {} preset; skipped on {os}",
                p.os
            )),
            Some(_) => {}
        }
    }
    for preset in registry.iter().filter(|p| p.os == os) {
        let named = selection.iter().any(|s| s == preset.id);
        let detected = auto
            && match preset.auto {
                Auto::Default => true,
                Auto::Detect(detect) => detect(),
                Auto::OptIn => false,
            };
        if named || detected {
            out.presets.push(preset);
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn yes() -> bool {
        true
    }

    fn no() -> bool {
        false
    }

    pub static TEST_REGISTRY: &[Preset] = &[
        Preset {
            id: "linux-core",
            os: "linux",
            auto: Auto::Default,
            toml: "[[rule]]\nid = \"linux-core.journal\"\ntype = \"journald\"\n\n[[rule]]\nid = \"linux-core.kernel\"\ntype = \"journald\"\nmatches = [\"_TRANSPORT=kernel\"]\n",
        },
        Preset {
            id: "linux-auditd",
            os: "linux",
            auto: Auto::Detect(yes),
            toml: "schema_version = 1\n[[rule]]\nid = \"linux-auditd.log\"\ntype = \"journald\"\n",
        },
        Preset {
            id: "linux-containers",
            os: "linux",
            auto: Auto::Detect(no),
            toml: "[[rule]]\nid = \"linux-containers.docker\"\ntype = \"journald\"\n",
        },
        Preset {
            id: "linux-extra",
            os: "linux",
            auto: Auto::OptIn,
            toml: "[[rule]]\nid = \"linux-extra.x\"\ntype = \"journald\"\n",
        },
        Preset {
            id: "windows-security",
            os: "windows",
            auto: Auto::Default,
            toml: "[[rule]]\nid = \"windows-security.log\"\ntype = \"wineventlog\"\nchannel = \"Security\"\n",
        },
    ];

    fn ids(selection: &[&str], os: &str) -> (Vec<&'static str>, Selection<'static>) {
        let selection: Vec<String> = selection.iter().map(|s| (*s).to_owned()).collect();
        let s = select(&selection, TEST_REGISTRY, os);
        (s.presets.iter().map(|p| p.id).collect(), s)
    }

    #[test]
    fn auto_selects_defaults_and_detected_for_the_os() {
        let (got, s) = ids(&["auto"], "linux");
        assert_eq!(got, ["linux-core", "linux-auditd"]);
        assert!(s.errors.is_empty() && s.warnings.is_empty());
        let (got, _) = ids(&["auto"], "windows");
        assert_eq!(got, ["windows-security"]);
        let (got, _) = ids(&["auto"], "macos");
        assert!(got.is_empty());
    }

    #[test]
    fn explicit_lists_and_auto_plus_opt_in() {
        let (got, _) = ids(&["linux-extra"], "linux");
        assert_eq!(got, ["linux-extra"]);
        let (got, _) = ids(&["auto", "linux-extra", "linux-containers"], "linux");
        assert_eq!(
            got,
            [
                "linux-core",
                "linux-auditd",
                "linux-containers",
                "linux-extra"
            ]
        );
        let (got, _) = ids(&[], "linux");
        assert!(got.is_empty());
    }

    #[test]
    fn unknown_and_other_os_presets() {
        let (got, s) = ids(&["linux-cor"], "linux");
        assert!(got.is_empty());
        assert_eq!(s.errors.len(), 1);
        assert!(s.errors[0].contains("linux-core"), "{:?}", s.errors);
        let (got, s) = ids(&["windows-security"], "linux");
        assert!(got.is_empty());
        assert!(s.errors.is_empty());
        assert_eq!(s.warnings.len(), 1);
    }

    /// Every built-in preset parses, validates and namespaces its rule ids.
    #[test]
    fn builtin_presets_load() {
        for preset in BUILTIN {
            assert!(
                preset.id.starts_with(&format!("{}-", preset.os)),
                "{}",
                preset.id
            );
            // Paths are only absolute on their own OS: elsewhere check the syntax only.
            if preset.os != std::env::consts::OS {
                if let Err(e) = toml::from_str::<toml::Table>(preset.toml) {
                    panic!("preset {}: {e}", preset.id);
                }
                continue;
            }
            let main = format!(
                "[agent]\nendpoint = \"https://ingest.example.com\"\npresets = [{:?}]\n",
                preset.id
            );
            let config = crate::AgentConfig::from_sources(
                std::path::Path::new("agent.toml"),
                &main,
                &[],
                BUILTIN,
                preset.os,
                None,
            );
            if let Err(e) = config {
                panic!("preset {}: {e}", preset.id);
            }
        }
    }
}
