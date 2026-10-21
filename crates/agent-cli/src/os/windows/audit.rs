//! The Windows half of the `status` checks in `winaudit`: run `auditpol`, read the process
//! command line policy and the state of every channel a rule reads. Read only.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use agent_config::presets::windows::{ChannelState, channel_state};
use agent_config::{AgentConfig, RuleKind};
use serde_json::Value;

use crate::winaudit::{self, ChannelProblem};

/// The `windows` object for `status`.
pub fn checks(config: &AgentConfig) -> Value {
    let auditpol = auditpol();
    winaudit::report(
        auditpol.as_deref().map_err(String::as_str),
        Some(command_line()),
        &channel_problems(config),
        &config.presets,
    )
}

/// `auditpol /get /category:* /r`, run directly (no shell) from System32. Needs an
/// administrator; anyone else gets "A required privilege is not held by the client".
fn auditpol() -> Result<String, String> {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let out = Command::new(root.join("System32").join("auditpol.exe"))
        .args(["/get", "/category:*", "/r"])
        .output()
        .map_err(|e| format!("cannot run auditpol: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let reason = stdout
            .lines()
            .chain(stderr.lines())
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("no output");
        return Err(format!(
            "auditpol failed: {}",
            reason.chars().take(200).collect::<String>()
        ));
    }
    Ok(stdout)
}

/// "Include command line in process creation events" (Group Policy writes this value; unset
/// means off).
fn command_line() -> bool {
    let value = windows_registry::LOCAL_MACHINE
        .open(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit")
        .and_then(|key| key.get_u32("ProcessCreationIncludeCmdLine_Enabled"));
    value.is_ok_and(|v| v == 1)
}

/// Channels of enabled `wineventlog` rules that are missing or disabled.
fn channel_problems(config: &AgentConfig) -> Vec<ChannelProblem> {
    let mut channels: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for rule in config
        .rules
        .iter()
        .filter(|r| r.enabled && r.kind == RuleKind::Wineventlog)
    {
        if let Some(channel) = rule.channel.as_deref() {
            channels.entry(channel).or_default().push(rule.id.clone());
        }
    }
    channels
        .into_iter()
        .filter_map(|(channel, rules)| {
            let state = match channel_state(channel) {
                ChannelState::Enabled => return None,
                ChannelState::Missing => "missing",
                ChannelState::Disabled => "disabled",
            };
            Some(ChannelProblem {
                channel: channel.to_owned(),
                state,
                rules,
            })
        })
        .collect()
}
