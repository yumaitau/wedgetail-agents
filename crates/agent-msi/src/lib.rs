//! Windows Installer custom actions for the wedgetail-agent MSI
//! (`packaging/windows/wedgetail-agent.wxs`), built as `wedgetail_msi.dll`.
//!
//! Three deferred actions, run as LocalSystem after the files are installed and before the
//! service is started:
//!
//! - `WedgetailConfigure` (ENDPOINT, PRESETS): sets `[agent] endpoint` and `presets` in
//!   `agent.toml`, keeping the rest of the file. The new file is checked with
//!   `wedgetail-agent check-config` first; an invalid one fails the install and the old file
//!   is left as it was.
//! - `WedgetailEnrol` (ENROLTOKEN): runs `wedgetail-agent enrol --token-stdin` and writes the
//!   token to its standard input. The token is never on a command line, in a file or in the
//!   installer log (the property is hidden and the action hides its data). Skipped when the
//!   host is already enrolled.
//! - `WedgetailEventLogReaders` (ADD_EVENT_LOG_READERS=1): adds NT AUTHORITY\LOCAL SERVICE to
//!   the built-in Event Log Readers group (S-1-5-32-573).

pub mod config;

#[cfg(windows)]
#[allow(unsafe_code)]
mod msi;
