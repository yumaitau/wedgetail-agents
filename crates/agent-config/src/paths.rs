//! Default file locations for each OS.

use std::path::PathBuf;

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
