//! Facts about the host for the heartbeat (and for enrolment).

/// OS, version, architecture and host name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    pub hostname: String,
    /// `linux`, `windows` or `macos`.
    pub os: &'static str,
    pub os_version: String,
    pub arch: &'static str,
}

impl HostInfo {
    pub fn detect() -> Self {
        Self {
            hostname: gethostname::gethostname()
                .to_string_lossy()
                .chars()
                .take(256)
                .collect(),
            os: std::env::consts::OS,
            os_version: os_version().unwrap_or_else(|| "unknown".to_owned()),
            arch: std::env::consts::ARCH,
        }
    }
}

#[cfg(target_os = "linux")]
fn os_version() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    os_release_version(&text)
}

/// `PRETTY_NAME`, else `NAME VERSION_ID`, from os-release text.
pub fn os_release_version(text: &str) -> Option<String> {
    let get = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_owned())
    };
    get("PRETTY_NAME")
        .or_else(|| {
            Some(
                format!("{} {}", get("NAME")?, get("VERSION_ID").unwrap_or_default())
                    .trim()
                    .to_owned(),
            )
        })
        .map(|v| v.chars().take(128).collect())
}

#[cfg(target_os = "macos")]
fn os_version() -> Option<String> {
    let text = std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist").ok()?;
    plist_string(&text, "ProductVersion").map(|v| format!("macOS {v}"))
}

/// The `<string>` after `<key>name</key>` in a simple XML plist.
pub fn plist_string(text: &str, key: &str) -> Option<String> {
    let after = text.split_once(&format!("<key>{key}</key>"))?.1;
    let value = after
        .trim_start()
        .strip_prefix("<string>")?
        .split_once("</string>")?
        .0;
    Some(value.chars().take(64).collect())
}

#[cfg(windows)]
fn os_version() -> Option<String> {
    let key = windows_registry::LOCAL_MACHINE
        .open(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .ok()?;
    let name = key.get_string("ProductName").ok()?;
    let build = key.get_string("CurrentBuildNumber").unwrap_or_default();
    Some(format!("{name} (build {build})"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn os_version() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release() {
        let ubuntu = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n";
        assert_eq!(
            os_release_version(ubuntu).as_deref(),
            Some("Ubuntu 24.04.1 LTS")
        );
        assert_eq!(
            os_release_version("NAME=\"Red Hat Enterprise Linux\"\nVERSION_ID=\"9.4\"").as_deref(),
            Some("Red Hat Enterprise Linux 9.4")
        );
        assert_eq!(os_release_version("garbage"), None);
    }

    #[test]
    fn plist() {
        let text = "<dict>\n\t<key>ProductName</key>\n\t<string>macOS</string>\n\t<key>ProductVersion</key>\n\t<string>15.1</string>\n</dict>";
        assert_eq!(
            plist_string(text, "ProductVersion").as_deref(),
            Some("15.1")
        );
        assert_eq!(plist_string(text, "Missing"), None);
    }

    #[test]
    fn detect_fills_fields() {
        let info = HostInfo::detect();
        assert!(!info.hostname.is_empty());
        assert!(["linux", "windows", "macos"].contains(&info.os));
    }
}
