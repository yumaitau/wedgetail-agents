//! Windows Event Log channel checks from the registry: cheap, side-effect free and readable by
//! `LocalService`. Used to detect presets (Sysmon, Defender) and by `wedgetail-agent status`.

/// Where the Event Log service registers every channel (manifest-based and classic).
const CHANNELS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels";
/// Classic logs (`Windows PowerShell`, ...) are also registered here.
const CLASSIC: &str = r"SYSTEM\CurrentControlSet\Services\EventLog";

/// Whether a channel exists and is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Not registered: the feature or product that writes it is not installed.
    Missing,
    /// Registered but switched off, so nothing is written to it.
    Disabled,
    Enabled,
}

/// The state of `channel`. A registered channel without an `Enabled` value counts as enabled
/// (classic logs always are).
pub fn channel_state(channel: &str) -> ChannelState {
    let hklm = windows_registry::LOCAL_MACHINE;
    match hklm.open(format!(r"{CHANNELS}\{channel}")) {
        Ok(key) => match key.get_u32("Enabled") {
            Ok(0) => ChannelState::Disabled,
            _ => ChannelState::Enabled,
        },
        Err(_) if !channel.contains('/') && hklm.open(format!(r"{CLASSIC}\{channel}")).is_ok() => {
            ChannelState::Enabled
        }
        Err(_) => ChannelState::Missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_on_every_windows_host() {
        for channel in [
            "Security",
            "System",
            "Application",
            "Windows PowerShell",
            "Microsoft-Windows-PowerShell/Operational",
        ] {
            assert_eq!(channel_state(channel), ChannelState::Enabled, "{channel}");
        }
        assert_eq!(
            channel_state("Wedgetail-Missing/Operational"),
            ChannelState::Missing
        );
        assert_eq!(channel_state("Wedgetail Missing"), ChannelState::Missing);
    }
}
