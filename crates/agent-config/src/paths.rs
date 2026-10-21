//! Default file locations for each OS, and the rules for which files a rule may read.
//!
//! # Allowed roots and protected directories
//!
//! A `file` rule path is an absolute path or glob. Its **root** is the directory made of the
//! components before the first one with a glob character (`*`, `?`, `[`); for a plain path it
//! is the file's directory. For `/var/log/nginx/*.log` the root is `/var/log/nginx`, for
//! `/srv/app/**/*.log` it is `/srv/app`.
//!
//! Every file a rule matches is canonicalised (symlinks and `..` resolved) before it is
//! opened, and is refused unless:
//! - the canonical file is inside the canonical root, so a symlink in `/var/log/nginx` that
//!   points to `/etc/shadow` is not followed (point the rule at the real location instead);
//! - it is not inside a [protected directory](protected_dirs): the agent's state directory
//!   (credential, disk buffer, checkpoints), its configuration directory and, on macOS, the
//!   keychains and the agent's log directory;
//! - it is a regular file.
//!
//! Rule paths may not contain `.` or `..` components, and `check-config` also refuses a rule
//! whose root is inside a protected directory.

use std::path::{Component, Path, PathBuf};

/// `agent.toml` location.
pub fn default_config_path() -> PathBuf {
    config_dir().join("agent.toml")
}

/// Directory holding `agent.toml` and `rules.d`.
pub fn config_dir() -> PathBuf {
    if cfg!(windows) {
        program_data().join("Wedgetail")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/Wedgetail")
    } else {
        PathBuf::from("/etc/wedgetail-agent")
    }
}

/// State directory: disk buffer, checkpoints, status and credential.
pub fn default_state_dir() -> PathBuf {
    if cfg!(windows) {
        program_data().join("Wedgetail").join("state")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/Wedgetail/state")
    } else {
        PathBuf::from("/var/lib/wedgetail-agent")
    }
}

fn program_data() -> PathBuf {
    std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
}

/// Directories no rule may read: `state_dir` (credential, buffer, checkpoints), `config_dir`
/// and, on macOS, the keychains and the agent log directory.
pub fn protected_dirs(state_dir: &Path, config_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![state_dir.to_path_buf(), config_dir.to_path_buf()];
    if cfg!(target_os = "macos") {
        dirs.push(PathBuf::from("/Library/Keychains"));
        dirs.push(PathBuf::from("/Library/Logs/Wedgetail"));
    }
    dirs
}

/// Whether `s` has a glob character.
pub fn has_glob(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

/// The directory a rule path or glob is confined to (see the module docs).
pub fn glob_root(pattern: &Path) -> PathBuf {
    let mut root = PathBuf::new();
    let mut globbed = false;
    for component in pattern.components() {
        if has_glob(&component.as_os_str().to_string_lossy()) {
            globbed = true;
            break;
        }
        root.push(component);
    }
    if globbed {
        root
    } else {
        root.parent().map_or(root.clone(), Path::to_path_buf)
    }
}

/// Whether `path` is `dir` or inside it, comparing components (case-insensitively on
/// Windows).
pub fn is_within(path: &Path, dir: &Path) -> bool {
    if cfg!(windows) {
        let lower = |p: &Path| PathBuf::from(p.to_string_lossy().to_lowercase());
        lower(path).starts_with(lower(dir))
    } else {
        path.starts_with(dir)
    }
}

/// Whether the path has `.` or `..` components.
pub fn has_dot_components(path: &Path) -> bool {
    path.components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
}

/// `dir` canonicalised when it exists, as written otherwise.
pub fn canonical_or_same(dir: &Path) -> PathBuf {
    std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf())
}

/// Check a matched file against the policy in the module docs. Returns the canonical path
/// to open.
pub fn check_file(path: &Path, root: &Path, protected: &[PathBuf]) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let root = std::fs::canonicalize(root).map_err(|e| format!("{}: {e}", root.display()))?;
    if !is_within(&canonical, &root) {
        return Err(format!(
            "{} resolves to {}, outside {}; refusing to follow it",
            path.display(),
            canonical.display(),
            root.display()
        ));
    }
    if let Some(dir) = protected
        .iter()
        .find(|d| is_within(&canonical, &canonical_or_same(d)))
    {
        return Err(format!(
            "{} is inside {}, which holds the agent's own files",
            path.display(),
            dir.display()
        ));
    }
    let meta = std::fs::metadata(&canonical).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abs(p: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:{}", p.replace('/', "\\")))
        } else {
            PathBuf::from(p)
        }
    }

    #[test]
    fn roots() {
        assert_eq!(
            glob_root(&abs("/var/log/nginx/*.log")),
            abs("/var/log/nginx")
        );
        assert_eq!(glob_root(&abs("/srv/app/**/*.log")), abs("/srv/app"));
        assert_eq!(glob_root(&abs("/var/log/a?/x.log")), abs("/var/log"));
        assert_eq!(glob_root(&abs("/var/log/auth.log")), abs("/var/log"));
        assert!(has_glob("/a/[ab].log"));
        assert!(!has_glob("/a/b.log"));
        assert!(has_dot_components(&abs("/var/log/../../etc/shadow")));
        assert!(!has_dot_components(&abs("/var/log/x.log")));
    }

    #[test]
    fn within() {
        assert!(is_within(
            &abs("/var/lib/wt/credential"),
            &abs("/var/lib/wt")
        ));
        assert!(!is_within(&abs("/var/lib/wt2/x"), &abs("/var/lib/wt")));
        if cfg!(windows) {
            assert!(is_within(
                Path::new(r"C:\ProgramData\WEDGETAIL\state\x"),
                Path::new(r"c:\programdata\wedgetail")
            ));
        }
    }

    struct Dir(PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn check_file_policy() {
        let dir = Dir(std::env::temp_dir().join(format!("wt-paths-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&dir.0);
        let logs = dir.0.join("logs");
        let state = dir.0.join("state");
        std::fs::create_dir_all(&logs).expect("mkdir");
        std::fs::create_dir_all(&state).expect("mkdir");
        std::fs::write(logs.join("app.log"), "x\n").expect("write");
        std::fs::write(state.join("credential"), "secret\n").expect("write");
        std::fs::write(dir.0.join("outside.log"), "x\n").expect("write");

        let protected = vec![state.clone()];
        let ok = check_file(&logs.join("app.log"), &logs, &protected).expect("allowed");
        assert!(ok.ends_with("app.log"));
        assert!(check_file(&logs, &dir.0, &protected).is_err(), "directory");
        let err = check_file(&state.join("credential"), &dir.0, &protected).expect_err("state");
        assert!(err.contains("agent's own files"), "{err}");
        assert!(check_file(&dir.0.join("outside.log"), &logs, &protected).is_err());
        assert!(check_file(&logs.join("missing.log"), &logs, &protected).is_err());

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.0.join("outside.log"), logs.join("evil.log"))
                .expect("symlink");
            std::os::unix::fs::symlink(state.join("credential"), logs.join("cred.log"))
                .expect("symlink");
            std::os::unix::fs::symlink(logs.join("app.log"), logs.join("current.log"))
                .expect("symlink");
            let err = check_file(&logs.join("evil.log"), &logs, &protected).expect_err("escape");
            assert!(err.contains("outside"), "{err}");
            assert!(check_file(&logs.join("cred.log"), &dir.0, &protected).is_err());
            assert!(check_file(&logs.join("current.log"), &logs, &protected).is_ok());
        }
    }
}
