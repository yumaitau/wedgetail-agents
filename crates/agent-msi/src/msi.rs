//! The custom action entry points and their Windows Installer and Win32 calls.

use std::fs;
use std::io::{self, Write};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use windows::Win32::Foundation::{ERROR_MEMBER_IN_ALIAS, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_MEMBERS_INFO_0, NetLocalGroupAddMembers,
};
use windows::Win32::Security::{
    CreateWellKnownSid, LookupAccountSidW, PSID, SECURITY_MAX_SID_SIZE, SID_NAME_USE,
    WELL_KNOWN_SID_TYPE, WinBuiltinEventLogReadersGroup, WinLocalServiceSid,
};
use windows::Win32::System::ApplicationInstallationAndServicing::{
    INSTALLMESSAGE_INFO, MSIHANDLE, MsiCloseHandle, MsiCreateRecord, MsiGetPropertyW,
    MsiProcessMessage, MsiRecordSetStringW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR, w};

use crate::config;

/// ERROR_INSTALL_FAILURE: the install fails and is rolled back.
const FAILURE: u32 = 1603;
/// `CREATE_NO_WINDOW`: the agent runs without a console window.
const NO_WINDOW: u32 = 0x0800_0000;

/// `[agent] endpoint` and `presets` from ENDPOINT and PRESETS.
/// CustomActionData: `<wedgetail-agent.exe>|<agent.toml>|<PRESETS>|<ENDPOINT>`.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn WedgetailConfigure(install: MSIHANDLE) -> u32 {
    let result = custom_action_data(install).and_then(|data| {
        let mut parts = data.splitn(4, '|');
        let (Some(exe), Some(config), Some(presets), Some(endpoint)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err("malformed CustomActionData".into());
        };
        configure(
            install,
            Path::new(exe),
            Path::new(config),
            presets,
            endpoint,
        )
    });
    finish(install, "WedgetailConfigure", result)
}

/// Enrolment with ENROLTOKEN, given to `enrol` on standard input.
/// CustomActionData: `<wedgetail-agent.exe>|<agent.toml>|<state dir>|<ENROLTOKEN>`.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn WedgetailEnrol(install: MSIHANDLE) -> u32 {
    let result = custom_action_data(install).and_then(|data| {
        let mut parts = data.splitn(4, '|');
        let result = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(exe), Some(config), Some(state), Some(token)) => enrol(
                install,
                Path::new(exe),
                Path::new(config),
                Path::new(state),
                token,
            ),
            _ => Err("malformed CustomActionData".into()),
        };
        wipe(data);
        result
    });
    finish(install, "WedgetailEnrol", result)
}

/// NT AUTHORITY\LOCAL SERVICE into Event Log Readers. A failure is logged and the install
/// carries on: the agent runs without it and `status` reports the channels it cannot read.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn WedgetailEventLogReaders(install: MSIHANDLE) -> u32 {
    match add_event_log_readers() {
        Ok(true) => log(
            install,
            "added NT AUTHORITY\\LOCAL SERVICE to Event Log Readers",
        ),
        Ok(false) => log(
            install,
            "NT AUTHORITY\\LOCAL SERVICE is already in Event Log Readers",
        ),
        Err(e) => log(
            install,
            &format!(
                "warning: cannot add NT AUTHORITY\\LOCAL SERVICE to Event Log Readers ({e}); \
                 add it by hand (docs/presets/windows.md)"
            ),
        ),
    }
    ERROR_SUCCESS.0
}

fn finish(install: MSIHANDLE, action: &str, result: Result<(), String>) -> u32 {
    match result {
        Ok(()) => ERROR_SUCCESS.0,
        Err(e) => {
            log(install, &format!("{action} failed: {e}"));
            FAILURE
        }
    }
}

fn configure(
    install: MSIHANDLE,
    exe: &Path,
    config_path: &Path,
    presets: &str,
    endpoint: &str,
) -> Result<(), String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err("ENDPOINT is empty".into());
    }
    let mut keys = vec![("endpoint", config::toml_string(endpoint))];
    if let Some(value) = config::presets_value(presets)? {
        keys.push(("presets", value));
    }
    let (bom, original) = match fs::read(config_path) {
        Ok(bytes) => {
            let bom = bytes.starts_with(b"\xEF\xBB\xBF");
            let text = String::from_utf8(bytes[if bom { 3 } else { 0 }..].to_vec())
                .map_err(|_| format!("{} is not UTF-8", config_path.display()))?;
            (bom, text)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (false, "schema_version = 1\n".into()),
        Err(e) => return Err(format!("{}: {e}", config_path.display())),
    };
    let mut updated = config::set_agent_keys(&original, &keys).into_bytes();
    if bom {
        updated.splice(0..0, *b"\xEF\xBB\xBF");
    }

    // Check the new file next to the old one (so rules.d is read too) before replacing it.
    let candidate = config_path.with_extension("toml.msi-new");
    fs::write(&candidate, &updated).map_err(|e| format!("{}: {e}", candidate.display()))?;
    let checked = run(exe, &["check-config", "--config"], &candidate, None);
    let _ = fs::remove_file(&candidate);
    let output = checked?;
    log_output(install, "check-config", &output);
    if !output.status.success() {
        return Err(format!(
            "the configuration with ENDPOINT and PRESETS is not valid ({}); {} is unchanged",
            output.status,
            config_path.display()
        ));
    }
    // Written in place, so the file keeps its owner and access list.
    fs::write(config_path, &updated).map_err(|e| format!("{}: {e}", config_path.display()))?;
    log(
        install,
        &format!("set endpoint = {endpoint:?} in {}", config_path.display()),
    );
    // A running agent (a reinstall over a running service) applies it now; otherwise this
    // fails quietly and the service reads the file when it starts.
    let system = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let _ = Command::new(Path::new(&system).join("System32").join("sc.exe"))
        .args(["control", "WedgetailAgent", "paramchange"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(NO_WINDOW)
        .status();
    Ok(())
}

fn enrol(
    install: MSIHANDLE,
    exe: &Path,
    config_path: &Path,
    state_dir: &Path,
    token: &str,
) -> Result<(), String> {
    if state_dir.join("credential.dpapi").exists() {
        log(
            install,
            "this host is already enrolled; ENROLTOKEN was not used (enrol again with \
             wedgetail-agent enrol --force)",
        );
        return Ok(());
    }
    let output = run(
        exe,
        &["enrol", "--token-stdin", "--config"],
        config_path,
        Some(token),
    )?;
    // enrol never prints the token.
    log_output(install, "enrol", &output);
    if output.status.success() {
        return Ok(());
    }
    // Enrolled with a state_dir other than the default one.
    if String::from_utf8_lossy(&output.stderr).contains("already enrolled") {
        log(
            install,
            "this host is already enrolled; ENROLTOKEN was not used",
        );
        return Ok(());
    }
    Err(format!("wedgetail-agent enrol failed ({})", output.status))
}

/// Run the agent with `args` and `path` as the last argument; `stdin` is written to its
/// standard input (then closed).
fn run(exe: &Path, args: &[&str], path: &Path, stdin: Option<&str>) -> Result<Output, String> {
    let mut child = Command::new(exe)
        .args(args)
        .arg(path)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(NO_WINDOW)
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", exe.display()))?;
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let mut line = text.trim().to_owned();
        line.push('\n');
        let written = pipe.write_all(line.as_bytes());
        wipe(line);
        drop(pipe);
        if let Err(e) = written {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("cannot write to wedgetail-agent: {e}"));
        }
    }
    child
        .wait_with_output()
        .map_err(|e| format!("cannot run {}: {e}", exe.display()))
}

fn log_output(install: MSIHANDLE, what: &str, output: &Output) {
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        let text = text.trim();
        if !text.is_empty() {
            log(install, &format!("{what}: {text}"));
        }
    }
}

/// Overwrite a string that held a secret before it is freed.
fn wipe(text: String) {
    let mut bytes = text.into_bytes();
    for b in &mut bytes {
        // SAFETY: a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

fn custom_action_data(install: MSIHANDLE) -> Result<String, String> {
    let mut buf = vec![0u16; 512];
    loop {
        let mut len = u32::try_from(buf.len()).map_err(|_| "property too long")?;
        // SAFETY: `buf` holds `len` u16s; the name is a static, NUL-terminated string.
        let rc = unsafe {
            MsiGetPropertyW(
                install,
                w!("CustomActionData"),
                Some(PWSTR(buf.as_mut_ptr())),
                Some(&mut len),
            )
        };
        if rc == ERROR_MORE_DATA.0 {
            wipe_wide(&mut buf);
            buf = vec![0u16; len as usize + 1];
            continue;
        }
        if rc != ERROR_SUCCESS.0 {
            wipe_wide(&mut buf);
            return Err(format!("cannot read CustomActionData (error {rc})"));
        }
        let text = String::from_utf16(&buf[..(len as usize).min(buf.len())])
            .map_err(|_| "CustomActionData is not valid UTF-16".to_owned());
        wipe_wide(&mut buf);
        return text;
    }
}

fn wipe_wide(buf: &mut [u16]) {
    for c in buf {
        // SAFETY: a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(c, 0) };
    }
}

/// A line in the installer log. Field 0 is the template `[1]` so the text itself is never
/// formatted (it may contain `[agent]`).
fn log(install: MSIHANDLE, text: &str) {
    let text = HSTRING::from(format!("Wedgetail: {text}"));
    // SAFETY: the record is created, used and closed here; the strings outlive the calls.
    unsafe {
        let record = MsiCreateRecord(1);
        if record.is_invalid() {
            return;
        }
        MsiRecordSetStringW(record, 0, w!("[1]"));
        MsiRecordSetStringW(record, 1, PCWSTR(text.as_ptr()));
        MsiProcessMessage(install, INSTALLMESSAGE_INFO, record);
        MsiCloseHandle(record);
    }
}

/// `Ok(true)` when added, `Ok(false)` when it was already a member.
fn add_event_log_readers() -> Result<bool, String> {
    let mut group = well_known_sid(WinBuiltinEventLogReadersGroup)?;
    let mut member = well_known_sid(WinLocalServiceSid)?;
    let group_sid = PSID(group.as_mut_ptr().cast());
    // The group's name in this display language (NetLocalGroupAddMembers takes a name).
    let mut name = [0u16; 257];
    let mut name_len = 257u32;
    let mut domain = [0u16; 257];
    let mut domain_len = 257u32;
    let mut kind = SID_NAME_USE::default();
    // SAFETY: the buffers and their lengths match; the SID was built by CreateWellKnownSid.
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            group_sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
    }
    .map_err(|e| format!("cannot look up S-1-5-32-573: {e}"))?;
    let info = LOCALGROUP_MEMBERS_INFO_0 {
        lgrmi0_sid: PSID(member.as_mut_ptr().cast()),
    };
    // SAFETY: one LOCALGROUP_MEMBERS_INFO_0 at level 0; the name is NUL-terminated.
    let rc = unsafe {
        NetLocalGroupAddMembers(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            0,
            std::ptr::from_ref(&info).cast(),
            1,
        )
    };
    match rc {
        0 => Ok(true),
        rc if rc == ERROR_MEMBER_IN_ALIAS.0 => Ok(false),
        rc => Err(format!("NetLocalGroupAddMembers error {rc}")),
    }
}

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Result<Vec<u8>, String> {
    let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = SECURITY_MAX_SID_SIZE;
    // SAFETY: `sid` holds `len` bytes.
    unsafe { CreateWellKnownSid(kind, None, Some(PSID(sid.as_mut_ptr().cast())), &mut len) }
        .map_err(|e| format!("cannot build a well-known SID: {e}"))?;
    sid.truncate(len as usize);
    Ok(sid)
}
