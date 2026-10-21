//! Facts about the host for the heartbeat and for enrolment (including the machine id).

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

/// The OS machine id, sent at enrolment so the server can flag cloned images (two hosts with
/// one id). Linux `/etc/machine-id` (or the D-Bus copy), Windows `MachineGuid`, macOS
/// `IOPlatformUUID`. Normalised to lower case.
pub fn machine_id() -> Result<String, String> {
    detect_machine_id()
}

#[cfg(target_os = "linux")]
fn detect_machine_id() -> Result<String, String> {
    let mut errors = Vec::new();
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        match std::fs::read_to_string(path) {
            Ok(text) => match parse_linux_machine_id(&text) {
                Some(id) => return Ok(id),
                None => errors.push(format!("{path} does not hold a machine id")),
            },
            Err(e) => errors.push(format!("{path}: {e}")),
        }
    }
    Err(errors.join("; "))
}

#[cfg(target_os = "macos")]
fn detect_machine_id() -> Result<String, String> {
    let out = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("cannot run ioreg: {e}"))?;
    parse_ioreg_platform_uuid(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| "ioreg did not report an IOPlatformUUID".to_owned())
}

#[cfg(windows)]
fn detect_machine_id() -> Result<String, String> {
    let key = windows_registry::LOCAL_MACHINE
        .open(r"SOFTWARE\Microsoft\Cryptography")
        .map_err(|e| format!(r"HKLM\SOFTWARE\Microsoft\Cryptography: {e}"))?;
    let value = key
        .get_string("MachineGuid")
        .map_err(|e| format!("MachineGuid: {e}"))?;
    parse_windows_machine_guid(&value).ok_or_else(|| "MachineGuid is not a GUID".to_owned())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn detect_machine_id() -> Result<String, String> {
    Err("no machine id source on this OS".into())
}

/// `/etc/machine-id`: 32 hex digits and a newline. systemd writes `uninitialized` on first
/// boot before the id is committed; that and anything else odd is rejected.
pub fn parse_linux_machine_id(text: &str) -> Option<String> {
    let id = text.trim();
    (id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_ascii_lowercase())
}

/// The `"IOPlatformUUID" = "<uuid>"` line of `ioreg -rd1 -c IOPlatformExpertDevice`.
pub fn parse_ioreg_platform_uuid(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let value = line
            .trim()
            .strip_prefix("\"IOPlatformUUID\"")?
            .trim_start()
            .strip_prefix('=')?
            .trim();
        let value = value.strip_prefix('"')?.strip_suffix('"')?;
        is_uuid(value).then(|| value.to_ascii_lowercase())
    })
}

/// `MachineGuid` from the registry: a GUID, sometimes written with braces.
pub fn parse_windows_machine_guid(text: &str) -> Option<String> {
    let value = text.trim();
    let value = value
        .strip_prefix('{')
        .and_then(|v| v.strip_suffix('}'))
        .unwrap_or(value);
    is_uuid(value).then(|| value.to_ascii_lowercase())
}

/// `8-4-4-4-12` hex digits.
fn is_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups
            .iter()
            .all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()))
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
    fn linux_machine_id() {
        assert_eq!(
            parse_linux_machine_id("4C4C4544004d3510804bc4c04f4e4a32\n").as_deref(),
            Some("4c4c4544004d3510804bc4c04f4e4a32")
        );
        for bad in [
            "",
            "\n",
            "uninitialized\n",
            "4c4c4544004d3510804bc4c04f4e4a3",
            "4c4c4544004d3510804bc4c04f4e4a32ff",
            "4c4c4544-004d-3510-804b-c4c04f4e4a32",
            "zc4c4544004d3510804bc4c04f4e4a32",
            "4c4c4544004d3510\n804bc4c04f4e4a32",
        ] {
            assert_eq!(parse_linux_machine_id(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn ioreg_platform_uuid() {
        let fixture = r#"+-o Mac15,8  <class IOPlatformExpertDevice, id 0x100000110, registered, matched, active, busy 0 (12 ms), retain 39>
    {
      "IOPolledInterface" = "AppleARMWatchdogTimerHibernateHandler is not serializable"
      "model" = <"Mac15,8">
      "IOPlatformSerialNumber" = "C02XX0000000"
      "IOPlatformUUID" = "3F2A9C4E-1B7D-4E6A-9C1F-0A2B3C4D5E6F"
      "IOPlatformUUIDx" = "not this one"
    }
"#;
        assert_eq!(
            parse_ioreg_platform_uuid(fixture).as_deref(),
            Some("3f2a9c4e-1b7d-4e6a-9c1f-0a2b3c4d5e6f")
        );
        for bad in [
            "",
            "\"IOPlatformUUID\" = \"\"",
            "\"IOPlatformUUID\" = <\"3F2A9C4E-1B7D-4E6A-9C1F-0A2B3C4D5E6F\">",
            "\"IOPlatformUUID\" = \"3F2A9C4E-1B7D-4E6A-9C1F-0A2B3C4D5E6\"",
            "\"IOPlatformUUID\" = \"3F2A9C4E-1B7D-4E6A-9C1F-0A2B3C4D5E6F\" junk",
            "\"IOPlatformUUID\" = \"3F2A9C4E\u{0}1B7D-4E6A-9C1F-0A2B3C4D5E6F\"",
            "\"IOPlatformSerialNumber\" = \"3F2A9C4E-1B7D-4E6A-9C1F-0A2B3C4D5E6F\"",
        ] {
            assert_eq!(parse_ioreg_platform_uuid(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn windows_machine_guid() {
        assert_eq!(
            parse_windows_machine_guid("6F1D3C2B-8A4E-4F70-9B2C-1D3E5F7A9B0C").as_deref(),
            Some("6f1d3c2b-8a4e-4f70-9b2c-1d3e5f7a9b0c")
        );
        assert_eq!(
            parse_windows_machine_guid("{6f1d3c2b-8a4e-4f70-9b2c-1d3e5f7a9b0c}\0").as_deref(),
            None
        );
        assert_eq!(
            parse_windows_machine_guid("{6f1d3c2b-8a4e-4f70-9b2c-1d3e5f7a9b0c}").as_deref(),
            Some("6f1d3c2b-8a4e-4f70-9b2c-1d3e5f7a9b0c")
        );
        for bad in [
            "",
            "{}",
            "6f1d3c2b8a4e4f709b2c1d3e5f7a9b0c",
            "6f1d3c2b-8a4e-4f70-9b2c-1d3e5f7a9b0g",
        ] {
            assert_eq!(parse_windows_machine_guid(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn machine_id_on_this_host() {
        // CI runners and developer machines all have one; the value is never printed.
        let id = machine_id().expect("machine id");
        assert!(!id.is_empty() && id.len() <= 36);
    }

    #[test]
    fn detect_fills_fields() {
        let info = HostInfo::detect();
        assert!(!info.hostname.is_empty());
        assert!(["linux", "windows", "macos"].contains(&info.os));
    }
}
