# Windows MSI

`wedgetail-agent.wxs` builds `wedgetail-agent-<version>-x86_64.msi` (WiX 5). It installs
`C:\Program Files\Wedgetail Agent\wedgetail-agent.exe`, `%ProgramData%\Wedgetail\agent.toml`
and the `WedgetailAgent` service (`NT AUTHORITY\LocalService`, automatic start). The state
directory `%ProgramData%\Wedgetail\state` is writable only by SYSTEM, Administrators and
LocalService. `agent.toml` and the state directory are kept on upgrade and uninstall.

```powershell
cargo build --release --workspace
wix build packaging/windows/wedgetail-agent.wxs -arch x64 `
  -d Version=0.1.0 -d BinPath=target/release/wedgetail-agent.exe `
  -d CaPath=target/release/wedgetail_msi.dll `
  -d ConfigPath=packaging/common/agent.toml -o wedgetail-agent-0.1.0-x86_64.msi
```

`wedgetail_msi.dll` holds the installer's custom actions (`crates/agent-msi`).

## Properties

All optional. Without any, the MSI installs the files and the service and leaves it stopped
until you set `endpoint` in `agent.toml` and enrol (the agent guide's manual steps).

| Property | Value | What the installer does |
| --- | --- | --- |
| `ENDPOINT` | Your ingest URL, `https://...` | Sets `endpoint` under `[agent]` in `agent.toml`, and starts the service at the end of the install. |
| `PRESETS` | `auto`, `none` or a comma-separated list of preset ids, such as `windows-security,windows-powershell` | Sets `presets` under `[agent]`. Only used together with `ENDPOINT`. |
| `ENROLTOKEN` | An enrolment token, `wge_...` | Enrols the host (see below). Skipped when the host is already enrolled. |
| `ADD_EVENT_LOG_READERS` | `1` (default) or `0` | `1` adds `NT AUTHORITY\LOCAL SERVICE` to the built-in Event Log Readers group (`S-1-5-32-573`), which the Security and Sysmon presets need. `0` leaves group membership alone. |

```powershell
msiexec /i wedgetail-agent-0.1.0-x86_64.msi /qn /l*v install.log `
  ENDPOINT=https://abcdefghijklmnopqrstuvwxyz012345.lambda-url.ap-southeast-2.on.aws/ `
  PRESETS=auto
```

### ENDPOINT and PRESETS

The installer edits the existing `agent.toml`: it replaces `endpoint` and `presets` in the
`[agent]` table (and a deprecated top-level `endpoint`), or adds the table, and keeps every
other line, comment and rule. The new file is checked with `wedgetail-agent check-config`
(including `rules.d`) before it replaces the old one; if it is not valid, for example an
`http://` endpoint or an unknown preset id, the install fails with exit code 1603, the
checker's messages are in the installer log (lines starting `Wedgetail:`) and `agent.toml` is
unchanged. The file is rewritten in place, so it keeps its owner and access list: like the
file a plain install creates, only SYSTEM and Administrators can change it, and the service
(LocalService) can only read it.

Running the same `msiexec /i` again on an installed host (as Intune and Group Policy do)
applies the properties again and asks a running service to reload
(`sc.exe control WedgetailAgent paramchange`). Edit your own rules in `rules.d\*.toml` or
outside the `[agent]` table: the installer only ever touches those two keys.

### ENROLTOKEN

The token is given to `wedgetail-agent enrol --token-stdin` on standard input, by a deferred
custom action running as LocalSystem after the files are installed:

- `ENROLTOKEN` is a hidden property (`MsiHiddenProperties`) and the action that receives it
  hides its data, so the installer log masks it. CI checks that the token is nowhere in a
  verbose (`/l*v`) log.
- It is never written to disk and never on the agent's command line or in its environment;
  the agent refuses tokens in arguments anyway.
- When the host is already enrolled (`%ProgramData%\Wedgetail\state\credential.dpapi`
  exists), the token is not used and the install carries on, so the same command works for
  upgrades and repairs. Re-enrol with `wedgetail-agent enrol --force`.
- A failed enrolment (token not accepted, endpoint unreachable, TLS failure) fails the
  install with exit code 1603 and the reason in the log, rather than leaving a host that
  looks installed but never reports.
- It needs an endpoint: `ENDPOINT` in the same command, or one already in `agent.toml`.

What a property cannot hide: the `msiexec` command line itself. While the install runs, its
arguments, including `ENROLTOKEN=...`, are visible to administrators on that machine in the
process list, and your deployment tool keeps the command it ran (Intune stores the install
command of a Win32 app and the Intune Management Extension logs it on the device; a Group
Policy transform (`.mst`) holding the token sits on the share). Treat the token as disclosed
to everyone who can read those: use a token with a short expiry and a host limit, scoped to
the host group, and revoke it when the rollout ends. If that is not acceptable, leave
`ENROLTOKEN` out and enrol as a separate step that reads the token from standard input or
`WEDGETAIL_ENROL_TOKEN` (docs/enrolment.md).

### ADD_EVENT_LOG_READERS

On by default because the Security and Sysmon presets read nothing without it, and it is the
documented least privilege (docs/presets/windows.md): read access to event logs, without the
right to clear them or change audit policy. It applies to every service that runs as
LocalService on the machine, not just the agent; set `ADD_EVENT_LOG_READERS=0` if you manage
the group yourself (for example with Restricted Groups, which would remove the member again)
or do not use those presets. If adding the member fails (on a domain controller, for
example), the install carries on and the log says why; `wedgetail-agent status` then shows
the channels it cannot read. Uninstalling does not remove the membership, since something
else may rely on it:
`Remove-LocalGroupMember -SID 'S-1-5-32-573' -Member 'NT AUTHORITY\LOCAL SERVICE'`.

## Intune

A Win32 app (`.intunewin` holding the MSI), install command run as System:

```text
msiexec /i wedgetail-agent-0.1.0-x86_64.msi /qn ENDPOINT=https://<your ingest URL>/ PRESETS=auto ENROLTOKEN=wge_...
```

Uninstall command `msiexec /x {product code} /qn`; detection rule: the MSI product code, or the
file `C:\Program Files\Wedgetail Agent\wedgetail-agent.exe`. Intune keeps the install command
(and so the token) in the app's configuration and the device's Intune Management Extension
log: see the token caveat above, and replace the token in the app for each rollout wave.

## Group Policy

Software installation (Computer Configuration > Policies > Software Settings) cannot pass
properties on a command line; use a transform. Create an `.mst` with Orca or any MSI editor
that adds rows to the `Property` table (`ENDPOINT`, `PRESETS`, and `ADD_EVENT_LOG_READERS` if
you want `0`), and assign the MSI with the transform on the Modifications tab. Keep
`ENROLTOKEN` out of the transform (it would sit on the share for as long as the GPO exists)
and enrol with a startup script instead, as described in the agent guide.
