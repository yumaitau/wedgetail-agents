//! Host checks for the Linux presets: the distribution family (from `/etc/os-release`) and
//! where its security logs are written.
//!
//! Debian and Ubuntu write authentication messages to `/var/log/auth.log`, RHEL, Fedora and
//! Amazon Linux to `/var/log/secure`, but only when rsyslog is installed: Debian 12 and
//! Amazon Linux 2023 images log to the journal only. Alpine has no journal and busybox
//! syslogd writes everything to `/var/log/messages`. The pure functions here decide from an
//! os-release text and a file-exists test so they can be tested with fixtures; the
//! [`checks`] wrappers look at the running host and are registered in
//! [`crate::presets::RULE_CHECKS`].

use std::io::Read;
use std::path::Path;

pub const AUTH_LOG: &str = "/var/log/auth.log";
pub const SECURE_LOG: &str = "/var/log/secure";
pub const MESSAGES_LOG: &str = "/var/log/messages";
pub const CRON_LOG: &str = "/var/log/cron";
pub const AUDIT_LOG: &str = "/var/log/audit/audit.log";
/// Exists while systemd-journald runs.
pub const JOURNAL_RUNTIME_DIR: &str = "/run/systemd/journal";
/// The binary the journald collector runs.
pub const JOURNALCTL: &str = "/usr/bin/journalctl";

/// Longest os-release file read.
const MAX_OS_RELEASE_BYTES: u64 = 64 * 1024;

/// The fields of `/etc/os-release` the agent uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    /// `ID`, for example `ubuntu`, `rhel`, `amzn`, `alpine`.
    pub id: String,
    /// `ID_LIKE`, for example `["debian"]` or `["fedora"]`.
    pub id_like: Vec<String>,
    /// `VERSION_ID`, for example `24.04`.
    pub version_id: String,
    /// `PRETTY_NAME`.
    pub pretty_name: String,
}

/// Distribution families that differ in where logs go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Debian, Ubuntu and derivatives: `/var/log/auth.log`.
    Debian,
    /// RHEL, Fedora, CentOS, Rocky, Alma, Amazon Linux: `/var/log/secure`.
    RedHat,
    /// SUSE: the journal (or `/var/log/messages` with rsyslog).
    Suse,
    /// Alpine: busybox syslogd, `/var/log/messages`, no journal.
    Alpine,
    Other,
}

impl OsRelease {
    /// Parse os-release text: `KEY=value` lines, values optionally in single or double
    /// quotes. Unknown keys, comments and malformed lines are ignored.
    pub fn parse(text: &str) -> Self {
        let mut out = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.trim().split_once('=') else {
                continue;
            };
            let value = unquote(value.trim());
            match key {
                "ID" => out.id = value.to_ascii_lowercase(),
                "ID_LIKE" => {
                    out.id_like = value
                        .split_whitespace()
                        .take(16)
                        .map(str::to_ascii_lowercase)
                        .collect();
                }
                "VERSION_ID" => out.version_id = value.chars().take(64).collect(),
                "PRETTY_NAME" => out.pretty_name = value.chars().take(128).collect(),
                _ => {}
            }
        }
        out
    }

    /// `/etc/os-release`, else `/usr/lib/os-release`; empty when neither can be read.
    pub fn read() -> Self {
        ["/etc/os-release", "/usr/lib/os-release"]
            .iter()
            .find_map(|p| read_small(Path::new(p)))
            .map(|text| Self::parse(&text))
            .unwrap_or_default()
    }

    pub fn family(&self) -> Family {
        let ids = std::iter::once(self.id.as_str()).chain(self.id_like.iter().map(String::as_str));
        for id in ids {
            match id {
                "debian" | "ubuntu" => return Family::Debian,
                "rhel" | "fedora" | "centos" | "amzn" | "rocky" | "almalinux" | "ol" => {
                    return Family::RedHat;
                }
                "suse" | "sles" | "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" => {
                    return Family::Suse;
                }
                "alpine" => return Family::Alpine,
                _ => {}
            }
        }
        Family::Other
    }
}

fn unquote(value: &str) -> &str {
    for q in ['"', '\''] {
        if let Some(inner) = value.strip_prefix(q).and_then(|v| v.strip_suffix(q)) {
            return inner;
        }
    }
    value
}

/// Read a small text file (at most 64 KiB); `None` if it cannot be read.
pub fn read_small(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(MAX_OS_RELEASE_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// Where one kind of log is read from on a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The distribution's own file (`auth.log`, `secure`, `cron`).
    File,
    /// The systemd journal.
    Journald,
    /// `/var/log/messages` written by busybox syslogd (Alpine), filtered by facility.
    Messages,
}

/// Whether the journal can be read: journald is running and `journalctl` is installed.
pub fn has_journal(exists: &dyn Fn(&str) -> bool) -> bool {
    exists(JOURNAL_RUNTIME_DIR) && exists(JOURNALCTL)
}

/// Where authentication messages (sshd, sudo, su, PAM, logind, useradd, ...) are read.
///
/// The family's own file wins when it exists (rsyslog is installed); otherwise the journal;
/// on a host without one, any auth file, then busybox `/var/log/messages`. With nothing at
/// all the file rule is kept so the file is picked up if it appears.
pub fn auth_source(os: &OsRelease, exists: &dyn Fn(&str) -> bool) -> Source {
    let any_file = || exists(AUTH_LOG) || exists(SECURE_LOG);
    let own_file = match os.family() {
        Family::Debian => exists(AUTH_LOG),
        Family::RedHat => exists(SECURE_LOG),
        Family::Suse | Family::Alpine | Family::Other => any_file(),
    };
    if own_file {
        Source::File
    } else if has_journal(exists) {
        Source::Journald
    } else if any_file() {
        Source::File
    } else if exists(MESSAGES_LOG) {
        Source::Messages
    } else {
        Source::File
    }
}

/// Where cron messages are read: `/var/log/cron` (RHEL family with rsyslog), else the
/// journal, else busybox `/var/log/messages`.
pub fn cron_source(exists: &dyn Fn(&str) -> bool) -> Source {
    if exists(CRON_LOG) {
        Source::File
    } else if has_journal(exists) {
        Source::Journald
    } else {
        Source::Messages
    }
}

/// Where kernel messages are read: the journal, else busybox `/var/log/messages`.
pub fn kernel_source(exists: &dyn Fn(&str) -> bool) -> Source {
    if has_journal(exists) {
        Source::Journald
    } else {
        Source::Messages
    }
}

/// Whether auditd runs: its pid file names a live `auditd` process, or the audit log can be
/// opened by the agent.
pub fn auditd_present(
    read: &dyn Fn(&str) -> Option<String>,
    readable: &dyn Fn(&str) -> bool,
) -> bool {
    let running = ["/run/auditd.pid", "/var/run/auditd.pid"]
        .iter()
        .any(|pid_file| {
            read(pid_file)
                .and_then(|pid| pid.trim().parse::<u32>().ok())
                .and_then(|pid| read(&format!("/proc/{pid}/comm")))
                .is_some_and(|comm| comm.trim() == "auditd")
        });
    running || readable(AUDIT_LOG)
}

/// The checks registered in [`crate::presets::RULE_CHECKS`], run against this host.
pub mod checks {
    use std::path::Path;

    use super::{OsRelease, Source};

    fn exists(path: &str) -> bool {
        Path::new(path).exists()
    }

    fn auth(source: Source) -> bool {
        super::auth_source(&OsRelease::read(), &exists) == source
    }

    pub fn auth_file() -> bool {
        auth(Source::File)
    }

    pub fn auth_journald() -> bool {
        auth(Source::Journald)
    }

    pub fn auth_messages() -> bool {
        auth(Source::Messages)
    }

    pub fn cron_file() -> bool {
        super::cron_source(&exists) == Source::File
    }

    pub fn cron_journald() -> bool {
        super::cron_source(&exists) == Source::Journald
    }

    pub fn cron_messages() -> bool {
        super::cron_source(&exists) == Source::Messages
    }

    pub fn kernel_messages() -> bool {
        super::kernel_source(&exists) == Source::Messages
    }

    pub fn journal() -> bool {
        super::has_journal(&exists)
    }

    pub fn dpkg() -> bool {
        exists("/var/lib/dpkg/status")
    }

    pub fn apt() -> bool {
        exists("/var/log/apt")
    }

    pub fn dnf() -> bool {
        exists("/var/log/dnf.rpm.log") || exists("/usr/bin/dnf")
    }

    /// yum itself (RHEL 7, Amazon Linux 2); on RHEL 8+ `yum` is dnf and logs as dnf.
    pub fn yum() -> bool {
        exists("/var/log/yum.log") || (exists("/usr/bin/yum") && !exists("/usr/bin/dnf"))
    }

    pub fn zypp() -> bool {
        exists("/var/log/zypp")
    }

    /// `linux-auditd`: auditd is running or its log is readable.
    pub fn auditd() -> bool {
        super::auditd_present(&|p| super::read_small(Path::new(p)), &|p| {
            std::fs::File::open(p).is_ok()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU_2204: &str =
        include_str!("../../../presets/linux/fixtures/os-release/ubuntu-22.04");
    const UBUNTU_2404: &str =
        include_str!("../../../presets/linux/fixtures/os-release/ubuntu-24.04");
    const DEBIAN_12: &str = include_str!("../../../presets/linux/fixtures/os-release/debian-12");
    const RHEL_9: &str = include_str!("../../../presets/linux/fixtures/os-release/rhel-9");
    const AMZN_2023: &str = include_str!("../../../presets/linux/fixtures/os-release/amzn-2023");
    const ALPINE_320: &str = include_str!("../../../presets/linux/fixtures/os-release/alpine-3.20");

    /// A host with these paths.
    fn host(paths: &'static [&'static str]) -> impl Fn(&str) -> bool {
        move |p| paths.contains(&p)
    }

    const SYSTEMD: [&str; 2] = [JOURNAL_RUNTIME_DIR, JOURNALCTL];

    #[test]
    fn parses_fixture_os_release_files() {
        let cases = [
            (UBUNTU_2204, "ubuntu", "22.04", Family::Debian),
            (UBUNTU_2404, "ubuntu", "24.04", Family::Debian),
            (DEBIAN_12, "debian", "12", Family::Debian),
            (RHEL_9, "rhel", "9.8", Family::RedHat),
            (AMZN_2023, "amzn", "2023", Family::RedHat),
            (ALPINE_320, "alpine", "3.20.10", Family::Alpine),
        ];
        for (text, id, version, family) in cases {
            let os = OsRelease::parse(text);
            assert_eq!(os.id, id);
            assert_eq!(os.version_id, version);
            assert_eq!(os.family(), family, "{id}");
            assert!(!os.pretty_name.is_empty());
        }
        assert_eq!(OsRelease::parse(RHEL_9).id_like, ["fedora"]);
        assert_eq!(OsRelease::parse("garbage\n=\nID").family(), Family::Other);
        assert_eq!(
            OsRelease::parse("ID=linuxmint\nID_LIKE=\"ubuntu debian\"").family(),
            Family::Debian
        );
    }

    /// `presets = ["auto"]` per distribution, as each ships by default.
    #[test]
    fn auth_source_per_distribution() {
        let cases: [(&str, &str, &'static [&'static str], Source); 9] = [
            // Ubuntu server images ship rsyslog.
            (
                "ubuntu 22.04",
                UBUNTU_2204,
                &[AUTH_LOG, JOURNAL_RUNTIME_DIR, JOURNALCTL],
                Source::File,
            ),
            (
                "ubuntu 24.04",
                UBUNTU_2404,
                &[AUTH_LOG, JOURNAL_RUNTIME_DIR, JOURNALCTL],
                Source::File,
            ),
            // Ubuntu minimal / containers without rsyslog.
            (
                "ubuntu 24.04 minimal",
                UBUNTU_2404,
                &SYSTEMD,
                Source::Journald,
            ),
            // Debian 12 no longer installs rsyslog by default.
            ("debian 12", DEBIAN_12, &SYSTEMD, Source::Journald),
            (
                "debian 12 + rsyslog",
                DEBIAN_12,
                &[AUTH_LOG, JOURNAL_RUNTIME_DIR, JOURNALCTL],
                Source::File,
            ),
            (
                "rhel 9",
                RHEL_9,
                &[SECURE_LOG, MESSAGES_LOG, JOURNAL_RUNTIME_DIR, JOURNALCTL],
                Source::File,
            ),
            // Amazon Linux 2023 has no rsyslog by default.
            ("amazon linux 2023", AMZN_2023, &SYSTEMD, Source::Journald),
            ("alpine 3.20", ALPINE_320, &[MESSAGES_LOG], Source::Messages),
            (
                "alpine 3.20 + rsyslog auth.log",
                ALPINE_320,
                &[AUTH_LOG, MESSAGES_LOG],
                Source::File,
            ),
        ];
        for (name, os_release, paths, want) in cases {
            let os = OsRelease::parse(os_release);
            assert_eq!(auth_source(&os, &host(paths)), want, "{name}");
        }
        // A Debian host with a leftover /var/log/secure still prefers the journal; a RHEL host
        // with auth.log only (custom rsyslog) as well.
        let debian = OsRelease::parse(DEBIAN_12);
        assert_eq!(
            auth_source(
                &debian,
                &host(&[SECURE_LOG, JOURNAL_RUNTIME_DIR, JOURNALCTL])
            ),
            Source::Journald
        );
        // Nothing at all: keep the file rule waiting for a file.
        assert_eq!(auth_source(&debian, &host(&[])), Source::File);
        // A journal directory without journalctl cannot be read.
        assert_eq!(
            auth_source(&debian, &host(&[JOURNAL_RUNTIME_DIR, MESSAGES_LOG])),
            Source::Messages
        );
    }

    #[test]
    fn cron_and_kernel_sources() {
        assert_eq!(
            cron_source(&host(&[CRON_LOG, JOURNAL_RUNTIME_DIR, JOURNALCTL])),
            Source::File
        );
        assert_eq!(cron_source(&host(&SYSTEMD)), Source::Journald);
        assert_eq!(cron_source(&host(&[MESSAGES_LOG])), Source::Messages);
        assert_eq!(kernel_source(&host(&SYSTEMD)), Source::Journald);
        assert_eq!(kernel_source(&host(&[MESSAGES_LOG])), Source::Messages);
    }

    #[test]
    fn auditd_detection() {
        let files = |pairs: &'static [(&'static str, &'static str)]| {
            move |p: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == p)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        let no = |_: &str| false;
        let running = files(&[("/run/auditd.pid", "812\n"), ("/proc/812/comm", "auditd\n")]);
        assert!(auditd_present(&running, &no));
        // A stale pid file naming another process.
        let stale = files(&[("/run/auditd.pid", "812\n"), ("/proc/812/comm", "bash\n")]);
        assert!(!auditd_present(&stale, &no));
        let garbage = files(&[("/var/run/auditd.pid", "../../etc/passwd")]);
        assert!(!auditd_present(&garbage, &no));
        // Not running (or not visible) but the log is readable.
        assert!(auditd_present(&files(&[]), &|p| p == AUDIT_LOG));
        assert!(!auditd_present(&files(&[]), &no));
    }
}
