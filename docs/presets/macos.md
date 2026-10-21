# macOS presets

| Preset | Selected by `"auto"` | Collects |
| --- | --- | --- |
| `macos-core` | always | Unified log: logins, privilege use, remote access, Gatekeeper, XProtect, code signing, privacy (TCC) decisions, login and background items, configuration profiles, firewall. Files: `/var/log/install.log`, `/var/log/system.log`. |
| `macos-audit` | when auditd has an active trail (`/var/audit/current` exists) | OpenBSM audit trail, classes `lo`, `aa`, `ad`, `ex`. |
| `macos-es` | not built (phase 2) | Endpoint Security events. Plan and entitlement status: [macos-es.md](macos-es.md). |

Contents:

- [Requirements](#requirements)
- [Full Disk Access and MDM](#full-disk-access-and-mdm)
- [`macos-core` rules](#macos-core-rules)
- [`macos-audit` rules](#macos-audit-rules)
- [Fields by `source_type`](#fields-by-source_type)
- [Checkpoints, overlap and duplicates](#checkpoints-overlap-and-duplicates)
- [CPU](#cpu)
- [Volume](#volume)
- [Tuning](#tuning)
- [What was tested, and what was not](#what-was-tested-and-what-was-not)

## Requirements

- The agent runs as **root** (launchd daemon `au.com.yumait.wedgetail-agent`):
  `/usr/bin/log stream` and `log show` refuse users who are not administrators, and giving a
  service account admin rights would also give it `sudo`. The agent opens no listener, runs
  no remote commands and executes only `/usr/bin/log` and, for `macos-audit`,
  `/usr/sbin/praudit`, always with a fixed argument list.
- macOS 13 or later for Background Task Management events (`macos-core.persistence`); the
  other rules work on any macOS with the unified log. Only macOS 26 on Apple silicon has been
  tested so far (see [the last section](#what-was-tested-and-what-was-not)).
- `macos-audit` needs auditd running. Apple deprecated audit(4) in macOS 11 and turned it off
  by default from macOS 14 (no `/etc/security/audit_control`, launchd job `com.apple.auditd`
  disabled), so on a default install `"auto"` does not select the preset. Apple's notice in
  `/etc/security/audit_control.example` gives the way back while it still exists: copy that
  file to `/etc/security/audit_control`, run `sudo launchctl enable system/com.apple.auditd`,
  and reboot. Apple says audit(4) will be removed in a future macOS; Endpoint Security
  ([macos-es.md](macos-es.md)) is the long-term replacement. When it is configured, `flags` in
  `/etc/security/audit_control` decide what reaches the trail; to have all four classes the
  preset keeps, use at least `flags:lo,aa,ad,ex` (the macOS default was `lo,aa`). `ex` adds an
  event for every `execve`, which is busy on a developer Mac; on macOS most programs start
  with `posix_spawn`, which is class `pc` and not kept.

## Full Disk Access and MDM

macOS privacy protection (TCC) applies to root too: without Full Disk Access a read of a
protected location (users' `~/Library`, Mail, Messages, Safari data, Time Machine and
other volumes, the TCC database) fails with `Operation not permitted`. The built-in
`macos-core` and `macos-audit` sources are outside those locations, but rules you add for
files in users' home folders are not, and the phase 2 Endpoint Security extension requires
Full Disk Access outright. Grant it up front so no rule fails silently.

On managed Macs this is done with a Privacy Preferences Policy Control (PPPC) payload from
your MDM; macOS only honours PPPC payloads delivered by MDM (user-approved or automated
device enrolment), not profiles installed by hand. A sample is in
[`packaging/macos/wedgetail-agent-pppc.mobileconfig`](../../packaging/macos/wedgetail-agent-pppc.mobileconfig):

- `Services` → `SystemPolicyAllFiles` (Full Disk Access), `Authorization` `Allow`.
- `Identifier` `/usr/local/bin/wedgetail-agent`, `IdentifierType` `path`: launchd starts the
  agent binary directly, so the binary itself is the "responsible" process TCC checks, and
  the `log` and `praudit` processes it starts inherit that.
- `CodeRequirement`: macOS grants access only to a binary that satisfies this designated
  requirement, so a different binary copied to the same path gets nothing. The sample's
  requirement is the one a Developer ID build has, with the team id left as
  `REPLACE_WITH_TEAM_ID`. **Replace it** with the team id of the Developer ID certificate the
  agent is signed with; with the placeholder nothing matches and no access is granted. After
  installing a signed build, print the exact requirement with
  `codesign --display --requirements - /usr/local/bin/wedgetail-agent`.
  [`build-pkg.sh`](../../packaging/macos/build-pkg.sh) signs with the fixed identifier
  `au.com.yumait.wedgetail-agent` so the requirement does not change between releases.
- Unsigned builds (development, CI) have no stable requirement and cannot be granted access
  this way; signed and notarised releases are pending the Developer ID certificate.
- `PayloadOrganization`, `PayloadIdentifier` and the `PayloadUUID`s are examples; give the
  profile your own.

Without MDM, an administrator can add `/usr/local/bin/wedgetail-agent` in System Settings →
Privacy & Security → Full Disk Access.

## `macos-core` rules

Every rule id can be switched off with `[agent] disable_rules`. Predicates are shown as they
are in [`presets/macos/macos-core.toml`](../../presets/macos/macos-core.toml). Unified log
messages are written by Apple for its own diagnostics: wording can change between macOS
releases, and personal data in them is often `<private>` (macOS redacts dynamic strings
unless a profile enables private data).

### `macos-core.auth`

`macos_unified`, `source_type` `macos.unified`, level `default`.

```text
eventType == "logEvent" AND NOT eventMessage BEGINSWITH "Too many groups requested" AND (
  (process == "sudo" AND eventMessage CONTAINS " ; ")
  OR process == "su" OR process == "login"
  OR process == "sshd" OR process == "sshd-session" OR process == "sshd-auth"
  OR process == "SecurityAgent"
  OR subsystem == "com.apple.Authorization"
  OR (subsystem == "com.apple.opendirectoryd" AND (category == "auth" OR category == "policy"))
  OR (process == "screensharingd" AND (eventMessage BEGINSWITH "Authentication:"
      OR eventMessage BEGINSWITH "accept new screen sharing connection"
      OR eventMessage BEGINSWITH "closing index"))
)
```

- `sudo`, `su`, `login`: command lines and failures, for example
  `alice : 3 incorrect password attempts ; TTY=ttys001 ; PWD=/Users/alice ; USER=root ; COMMAND=/usr/bin/true`
  or `  runner : TTY=... ; PWD=... ; USER=root ; COMMAND=/usr/local/bin/wedgetail-agent status`
  (seen on macOS 14). Only `sudo` lines with the ` ; ` field separator are kept: every
  `sudo` run also logs `Reading config`, and `libsystem_info` logs
  `Too many groups requested (...)` for many processes, which is dropped for all of them.
- `sshd`, and `sshd-session`/`sshd-auth` (OpenSSH 9.8 and later, macOS 15 and later, split
  the server into these processes): `Accepted publickey for alice from 192.0.2.10 port 52113 ssh2: ...`,
  `Failed password for invalid user admin from 203.0.113.50 port 40022 ssh2`.
- Authorization Services (`authd`): `Succeeded authorizing right 'system.privilege.admin' by client '...'`,
  `Failed to authorize right ...`, session owner checks.
- Open Directory password checks: `Authentication failed for <private> (<record UUID>): ODErrorCredentialsInvalid`,
  `AccountPolicy: Authentication not allowed by auth failure`, `Authentication succeeded for ...`.
  These are the local password checks behind sudo, unlock, Screen Sharing and so on.
- Screen Sharing (`screensharingd`): `accept new screen sharing connection tcp IPv4`,
  `Authentication: SUCCEEDED :: User Name: alice :: Viewer Address: 198.51.100.23 :: Type: DH`
  (or `FAILED`), `closing index 0 ...` when a viewer disconnects. `screensharingd` logs
  hundreds of messages a minute during a session; only these three are kept.
- `loginwindow` is not included although the issue listed it: on macOS 26 it logs
  application lifecycle messages at default level and, in a day of observation, no login,
  logout or lock lines. Console logins are in the audit trail (`AUE_lw_login`,
  `macos-audit`) and will be in Endpoint Security (`NOTIFY_LW_SESSION_*`, phase 2).

### `macos-core.gatekeeper`

`macos_unified`, `source_type` `macos.unified`, level `default`.

```text
eventType == "logEvent" AND (
  (subsystem == "com.apple.syspolicy.exec" AND (eventMessage BEGINSWITH "GK evaluateScanResult"
      OR eventMessage BEGINSWITH "Prompt shown"))
  OR (subsystem == "com.apple.xprotect" AND (eventMessage CONTAINS[c] "detect"
      OR eventMessage CONTAINS[c] "malware"))
  OR (subsystem == "com.apple.XProtectFramework.PluginAPI" AND eventMessage CONTAINS "status_message"
      AND NOT eventMessage CONTAINS "NoThreatDetected")
  OR (process == "XProtect" AND subsystem == "com.apple.XProtectFramework")
  OR (process == "amfid" AND eventMessage CONTAINS " not valid: ")
)
```

- Gatekeeper (`syspolicyd`, subsystem `com.apple.syspolicy.exec`, a child of the
  `com.apple.syspolicy` subsystem named in the issue): one
  `GK evaluateScanResult: <result>, PST: (path: <hash>), (team: <team id>), (id: <signing id>), (bundle_id: ...), ...`
  per assessment of new or quarantined code (`<result>` 0 allowed; non-zero needs a prompt
  or is blocked), and `Prompt shown (...), waiting for response: PST: ...` when the user is
  shown the "cannot be opened" dialogue. Observed blocking an unsigned, quarantined binary:
  `GK evaluateScanResult: 1, ... (bundle_id: NOT_A_BUNDLE), 1, 0, 1, 0, 7, 7, 0` then
  `Prompt shown (8, 0)`. The info-level detail lines (`GK eval - was allowed: 0, show prompt: 1`,
  `GK Xprotect results`) are left out: `com.apple.syspolicy.exec` logs over 100 info
  messages a second while apps launch.
- XProtect: detections forwarded by `syspolicyd` (`Forwarding detection succeeded!`), scan
  notices, XProtect Remediator results other than `NoThreatDetected`
  (`{"caused_by":[...],"status_message":"ThreatDetected",...}`), and the XProtect agent's own
  messages.
- AMFI: `<path> not valid: Error Domain=AppleMobileFileIntegrityError Code=... "The file is adhoc signed or signed by an unknown certificate chain"`
  when code fails signature validation at load. On a developer Mac with Homebrew this is
  regular (unsigned libraries).

### `macos-core.tcc`

`macos_unified`, `source_type` `macos.unified`, level `default`.

```text
process == "tccd" AND subsystem == "com.apple.TCC" AND (
  (eventMessage BEGINSWITH "AUTHREQ_RESULT" AND NOT eventMessage CONTAINS "authReason=11,")
  OR eventMessage BEGINSWITH "AUTHREQ_SUBJECT"
  OR (eventMessage BEGINSWITH "AUTHREQ_CTX" AND eventMessage CONTAINS "preflight=no")
  OR eventMessage CONTAINS "Access Record"
)
```

Privacy decisions made by `tccd`. For every access check the system `tccd` writes, at
default level, `AUTHREQ_CTX` (function, service, whether it is a preflight check),
`AUTHREQ_ATTRIBUTION` (the accessing and responsible process), sometimes `AUTHREQ_SUBJECT`
(the requesting app's identifier) and `AUTHREQ_RESULT: msgID=..., authValue=2, authReason=..., ...`;
lines of one request share the `msgID`. `authValue` is 0 denied, 1 unknown, 2 allowed,
3 limited; `authReason` 11 means granted by entitlement. On the test Mac that was about
70 lines a minute, nearly all preflight checks by entitled Apple processes, so the rule keeps
only results not granted by entitlement (user consent, user settings, MDM policy, denials),
`AUTHREQ_SUBJECT` lines, non-preflight requests, and lines containing `Access Record`, which
tccd writes when access is changed in System Settings or by MDM (not seen on the test Mac,
where no setting was changed). Routine access checks at info level (`Handling access request
to kTCCService...`, `REQUEST_MSG`/`REPLY_MSG`) are not collected: streaming info-level `tccd`
messages cost about 2% of a core in `diagnosticd` on the test Mac (see [CPU](#cpu)). Add your
own rule if you want them; an example is under [Tuning](#tuning).

### `macos-core.persistence`

`macos_unified`, `source_type` `macos.unified`, level `default`. macOS 13 and later.

```text
eventType == "logEvent" AND subsystem == "com.apple.backgroundtaskmanagement"
```

Background Task Management records every login item, launch agent, launch daemon and app
extension that registers to run in the background:
`registerLaunchItem: pid=82867, uid=501, type=login item, url=<private>, config=(null)`,
`effectiveItemDisposition: appURL=file:///Applications/ExampleVault.app/, type=login item, url=Contents/Library/LoginItems/...`,
`registerLaunchItem: uid=501, type=legacy agent, ...` for a launchd plist dropped into a
`LaunchAgents`/`LaunchDaemons` folder. launchd itself logs no stable "job loaded" message at
default level (none in three days of observation on the test Mac, against 138,000 launchd
messages in six hours), so launchd job loads are covered through BTM, which launchd consults
for every new plist (`launchdWillScanPath`, `registerLaunchItem ... type=legacy agent|daemon`).
Typical volume is tens of messages a day.

### `macos-core.mdm`

`macos_unified`, `source_type` `macos.unified`, level `default`.

```text
eventType == "logEvent" AND subsystem == "com.apple.ManagedClient"
  AND (process == "mdmclient" OR process == "ManagedClient") AND (
  eventMessage CONTAINS "configuration profile:"
  OR eventMessage CONTAINS "Processing server request"
  OR eventMessage CONTAINS[c] "enrolled"
  OR messageType == error OR messageType == fault
)
```

Configuration profile installs and removals, MDM commands processed by `mdmclient`, and
enrolment changes and errors. `mdmclient` and `ManagedClient` log several thousand routine
messages a day (profile queries, push connection housekeeping); those are left out. The test
Mac is not MDM-enrolled, so this rule has only been checked to parse and to stay quiet.

### `macos-core.firewall`

`macos_unified`, `source_type` `macos.unified`, level `default`.

```text
process == "socketfilterfw" AND subsystem == "com.apple.ALF.ApplicationFirewall" AND NOT (
  eventMessage BEGINSWITH "Handle flow"
  OR eventMessage BEGINSWITH "Updating app rule"
  OR eventMessage BEGINSWITH "Updating path for app"
  OR eventMessage BEGINSWITH "Found matching app"
  OR eventMessage BEGINSWITH "Found known filter app"
  OR eventMessage BEGINSWITH "ApplicationFirewall::AFGet"
  OR eventMessage BEGINSWITH "AF_CMD_GLOBAL_STATE getAppFirewallState"
  OR eventMessage ENDSWITH "verdict: 1"
  OR eventMessage ENDSWITH "verdict: allowVerdict"
)
```

Application Firewall state changes (`Starting Application Firewall.`), inbound and outbound
flow decisions other than plain allows. `socketfilterfw` logs about 18,000 messages a day on
the test Mac, almost all `KNOWN APP FLOW: ..., return known verdict: 1` (allowed); those and
the per-flow housekeeping are dropped.

### `macos-core.install`

`file`, `source_type` `macos.install`, `/var/log/install.log`, parser `regex`:

```text
^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{2}(?::?\d{2})?) (?P<hostname>\S+) (?P<app_name>[^\[:\s]+)(?:\[(?P<proc_id>\d+)\])?: (?s:(?P<message>.*))$
```

with `multiline = { pattern = '^\s', match = "after" }` (installd writes package lists and
dictionaries as indented continuation lines). Package installs and their authorisation
(`installer`, `installd`, `system_installd`, `package_script_service`), for example
`Product archive /Users/alice/Downloads/ExampleTool-2.1.pkg trustLevel=350`,
`Administrator authorization granted.`, `Installed "ExampleTool" (2.1)`, and Software
Update activity. About 700 lines a day on the test Mac.

### `macos-core.syslog`

`file`, `source_type` `file`, `/var/log/system.log`, parser `syslog_rfc3164`. The legacy
syslog file still written by `syslogd` on current macOS (mostly ASL statistics and a few
daemons that log through syslog). When the file does not exist the rule waits for it.

## `macos-audit` rules

### `macos-audit.trail`

`macos_bsm`, `source_type` `macos.bsm`, `classes = ["lo", "aa", "ad", "ex"]`.

Reads the trail auditd is writing (`/var/audit/current`, a symlink to
`/var/audit/<start>.not_terminated`) and follows it across rotations: when auditd renames
the trail to `<start>.<end>` and starts a new one, the old file is read to its end once more
after the switch is seen, then the next trail by start time is read (so trails started while
the agent was stopped are not skipped), up to the current one.
Records are framed from the binary trail by the agent (header and trailer tokens), so a
half-written record is never sent and garbage is skipped to the next valid record; each
chunk of up to 512 KiB is converted with `/usr/sbin/praudit -x -r` (XML, numeric form, so
times and ids do not depend on the time zone or the user database). Event names and
classes come from `/etc/security/audit_event`; events not in one of the four classes are
dropped by the agent.

Classes, from `/etc/security/audit_class`: `lo` login and logout (`AUE_login`,
`AUE_logout`, `AUE_lw_login` loginwindow, `AUE_openssh`, `AUE_su`), `aa` authentication and
authorisation (`AUE_auth_user`, `AUE_sudo`, `AUE_ssauthorize` Security Server,
`AUE_SESSION_*`), `ad` administrative (`AUE_create_user`, `AUE_modify_user`,
`AUE_delete_user`, `AUE_modify_password`, `AUE_add_to_group`, `AUE_audit_startup`,
`AUE_SETTIMEOFDAY`, ...), `ex` exec (`AUE_EXECVE`, `AUE_MAC_EXECVE`).

## Fields by `source_type`

Every event also has the standard wire keys (`v`, `source_type`, `rule_id`, `ts`, `body`,
`attrs`); see the agent's wire format. The server stamps host identity.

### `macos.unified`

`body` is `null`; `ts` is the message time. `fields` (a subset of the `log stream --style ndjson`
object; a key is absent when the message does not have it):

| Key | Type | Example | Notes |
| --- | --- | --- | --- |
| `subsystem` | string | `com.apple.opendirectoryd` | empty string for messages without one (for example `sudo`, `screensharingd`) |
| `category` | string | `auth` | may be empty |
| `process` | string | `opendirectoryd` | last component of `processImagePath` |
| `processImagePath` | string | `/usr/libexec/opendirectoryd` | |
| `sender` | string | `PlistFile` | last component of `senderImagePath` (the library or plug-in that logged) |
| `eventMessage` | string | `Authentication failed for <private> (A0000002-0000-4000-8000-000000000002): ODErrorCredentialsInvalid` | cut at 64 KiB |
| `messageType` | string | `Default`, `Info`, `Debug`, `Error`, `Fault` | |
| `eventType` | string | `logEvent` | |
| `userID` | number | `0` | the effective uid of the logging process |
| `timestamp` | string | `2026-10-21 19:00:00.123456+1100` | local time with offset, as `log` prints it; `ts` is the same instant in UTC |

### `macos.install`

`body` is the line (continuation lines joined with `\n`), `attrs.path` is
`/var/log/install.log`, `ts` is when the agent read the line. `fields` from the `regex`
parser, all strings:

| Key | Example |
| --- | --- |
| `timestamp` | `2026-10-21 19:20:05+11` (local time, hour offset) |
| `hostname` | `mac-01` |
| `app_name` | `installd` |
| `proc_id` | `1281` (absent when the line has no `[pid]`) |
| `message` | `Installed "ExampleTool" (2.1)` |

A line the expression does not match is sent with no `fields` and `attrs.parse_error = "regex"`.

### `file` (`macos-core.syslog`)

`body` is the line, `attrs.path` `/var/log/system.log`, `ts` the read time. `fields` from
`syslog_rfc3164` ([docs/rules.md](../rules.md#parsers)): `timestamp` (`Oct 21 19:30:12`),
`hostname`, `app_name`, `proc_id`, `message`; lines such as
`--- last message repeated 1 time ---` have `attrs.parse_error = "syslog_rfc3164"`.

### `macos.bsm`

`body` is `null`; `ts` is the record time (header seconds and milliseconds, UTC);
`attrs.path` is the trail file; `attrs.truncated = true` when strings were cut (more than
128 KiB of strings, 256 tokens or 1,024 arguments in one record), so a huge command line is
shortened rather than dropping the event. A record longer than 256 KiB, or bytes that are not
a record (checked against the header length and the trailer), are skipped and logged.
`fields`:

| Key | Type | Example | Notes |
| --- | --- | --- | --- |
| `event` | string | `AUE_sudo` | name from `/etc/security/audit_event`, or the number as a string when unknown |
| `event_id` | number | `45028` | |
| `classes` | array of strings | `["aa"]` | the event's classes (`[]` when unknown) |
| `modifier` | number | `0` | header event modifier |
| `subject` | object | `{"audit_uid": "501", "uid": "501", "gid": "20", "ruid": "501", "rgid": "20", "pid": "2305", "sid": "100004", "tid": "52113 192.0.2.10"}` | who did it. `audit_uid` `-1` is unset; `tid` is `<port> <address>` (the remote address for SSH logins) |
| `return` | object | `{"errval": "0", "retval": "0"}` | `errval` 0 is success, otherwise an errno-style code (for example `1` for a failed sudo, `255` for a failed authentication) |
| `text` | array of strings | `["successful login alice"]` | text tokens, in order |
| `exec_args` | array of strings | `["sudo", "/usr/bin/whoami"]` | command line (`ex` events and `AUE_sudo`) |
| `exec_env` | array of strings | `["PATH", "AWS_SECRET_ACCESS_KEY"]` | environment variable **names** only, when the `arge` audit policy records the environment; values are dropped on the host because they often hold tokens and passwords |
| `path` | array of strings | `["/bin/sh"]` | |
| `attribute` | array of objects | `[{"mode": "100755", "uid": "0", "gid": "0", "fsid": "16777234", "nodeid": "1152921500311879000", "device": "0"}]` | file attributes for each path; `mode` is octal |
| `argument` | array of objects | `[{"arg_num": "1", "value": "0x0", "desc": "..."}]` | system call arguments |
| other tokens | object or string | `process`, `subject_ex`, `identity`, `socket_inet`, `exit`, ... | praudit's element name with `-` replaced by `_`; attributes become an object of strings, text-only elements a string; a token that appears twice becomes an array |

All token values are strings exactly as `praudit -r` prints them (numbers in decimal,
`mode` in octal). Example (an OpenSSH login):

```json
{"event": "AUE_openssh", "event_id": 32800, "classes": ["lo"], "modifier": 0,
 "subject": {"audit_uid": "501", "uid": "501", "gid": "20", "ruid": "501", "rgid": "20",
             "pid": "2400", "sid": "100004", "tid": "52113 192.0.2.10"},
 "text": ["successful login alice"], "return": {"errval": "0", "retval": "0"}}
```

## Checkpoints, overlap and duplicates

- **Unified log rules.** `log stream` cannot start in the past, so the checkpoint is the
  time of the newest event sent plus hashes of the events in the 2 seconds before it. After
  a restart the agent starts `log stream` first, then reads the gap with
  `log show --start <checkpoint - 2 s>`, and drops every event whose hash it has already
  sent (the hash covers `machTimestamp`, thread, trace and process ids and the message, which
  are identical in `log show` and `log stream`). Nothing is pruned while the catch-up read
  runs, so events that both reads return are sent once. The catch-up covers at most 24 hours
  of downtime. Tested in `crates/agent-collectors/src/macos_unified.rs`, including against the
  real `log` on macOS.
- **`macos-audit.trail`.** The checkpoint is the trail file identity (device and inode) and
  the byte offset after the last whole record. After a restart the agent finds the file by
  identity even if auditd renamed it on rotation, reads the rest of it, then every later
  trail in start-time order. Without a checkpoint it starts at the end of the current trail. Tested
  with the real `praudit` and a simulated rotation in
  `crates/agent-collectors/src/macos_bsm/tests.rs`.
- **File rules** use the agent's file checkpoints ([docs/rules.md](../rules.md#type--file)).

## CPU

Measured on one Mac: Apple M3 Max, macOS 26.6 (build 25G83), a developer workload in the
background (builds, browsers, several agents). CPU time was read with `ps` before and after
each window; percentages are of one core. `log stream` was run as an administrator (not
root); filtering works the same way for root.

How `log stream` filters matters more than how many processes run. The log system
(`diagnosticd`) evaluates simple terms itself and sends a client only matching messages;
anything it cannot evaluate makes it send every message at the stream's level to the `log`
process, which then tests each one:

| Predicate shape (one `log stream`, 45 s each) | `log` | `diagnosticd` |
| --- | --- | --- |
| `process == "a" OR process == "b" OR ...` (7 processes) | 0.00% | 0.00% |
| the same 7 as `process IN {"a", "b", ...}` | **7.35%** | **8.31%** |
| `subsystem == "x" AND category == "y"` | 0.00% | 0.00% |
| `process == "x" AND eventMessage BEGINSWITH "..."` | 0.04% | 0.02% |
| `process == "a" OR (process == "b" AND eventMessage BEGINSWITH "...")` | 0.00% | 0.00% |
| `process == "x" AND NOT eventMessage BEGINSWITH "..."` | 0.00% | 0.00% |
| `eventMessage BEGINSWITH "..."` alone | 3.48% | 4.44% |
| `subsystem BEGINSWITH "com.apple.syspolicy"`, level info | 2.55% | 1.31% |
| `subsystem == "com.apple.syspolicy.exec"`, level info | 1.26% | 0.64% |
| `process == "tccd" AND subsystem == "com.apple.TCC"`, level info | 0.00% | 2.13% |

So every `macos-core` predicate anchors each alternative with `process ==` or
`subsystem ==` (never `IN`, never a lone `eventMessage` test), and every rule streams at
level `default`. Info level is what Gatekeeper's and tccd's chattiest messages use, and
streaming it cost 0.6 to 2% of a core in `diagnosticd` per rule.

The first draft of the preset (one rule using `process IN {...}`, Gatekeeper and TCC at
info level) measured, over 180 s windows (baseline `diagnosticd` 1.23 s with no stream):

| Layout | `log` processes | `diagnosticd` above baseline | Total |
| --- | --- | --- | --- |
| first draft, 6 rules | 8.4% and 10.1% | 6.9% and 8.2% | about 15 to 18% |
| first draft, all 6 ORed into one rule (info) | 18.1% and 21.8% | 6.9% and 8.4% | about 25 to 30% |
| the issue's subsystem/process list ORed, no message filters (info) | 0.52% | 0.9% | 1.4%, but 42 events a second |

The shipped `macos-core`, run as the real agent (release build, all 8 rules, not enrolled
so nothing was sent), over two 300 s windows:

| Window (300 s, fresh state) | agent | 6 `log` children | `diagnosticd` above the window before | Total |
| --- | --- | --- | --- | --- |
| 1 | 0.24% | 1.55% | +0.61% | about 2.4% |
| 2 | 0.22% | 1.01% | +0.63% | about 1.9% |
| 3 (per child) | 0.26% | 1.13%, of which `macos-core.gatekeeper` 1.06%, `macos-core.tcc` 0.06%, the other four 0.00% | about +0.5% | about 1.9% |

Memory: agent 12.5 to 14.7 MB RSS, the six `log stream` children about 30 MB together.
`logd` CPU did not change measurably (2.2 to 3.3 s per window with and without the agent).

Almost all of it is `macos-core.gatekeeper`. Its predicate is anchored on
`subsystem == "com.apple.syspolicy.exec"`, and on this Mac `syspolicyd` logs hundreds of
default- and error-level messages a second in that subsystem while processes are being
started (`Unable to initialize qtn_proc`, during builds), which the log system has to hand to
`log` for the `eventMessage` test. Measured on its own it ranged from 0.1% (quiet minute) to
2.5% (builds running). A Mac that is not compiling software all day will be at the low
end; on build machines consider `disable_rules = ["macos-core.gatekeeper"]`. Without it the
preset measured about 0.5 to 1% in total.

Restarting the agent with saved checkpoints runs one `log show` per unified rule to catch up
on the gap; after a 5 minute stop that cost about 6 s of CPU once (plus about 6 s in
`diagnosticd`).

Six `log stream` processes is a deliberate trade: merging them into one would not lower CPU
(each is filtered by `diagnosticd`, and an idle `log stream` costs nothing measurable) but
would lose per-rule `disable_rules` and per-rule rate limits. Each `log stream` process
uses about 5 MB of memory.

Intel Macs and macOS 14/15 have not been measured.

## Volume

Events a day on the test Mac (a developer workstation; a managed office Mac is likely
lower), counted with `log show --last 24h` and the rule's own predicate:

VOLUME_TABLE

## Tuning

Switch rules off:

```toml
[agent]
disable_rules = ["macos-core.gatekeeper", "macos-core.syslog"]
```

Keep AMFI failures for Homebrew libraries out (matching runs on the event's `fields` as JSON):

```toml
# rules.d/20-macos.toml: a copy of the preset rule with an exclusion
[[rule]]
id = "site-gatekeeper"
type = "macos_unified"
level = "default"
predicate = '(subsystem == "com.apple.syspolicy.exec" AND eventMessage BEGINSWITH "GK evaluateScanResult") OR (process == "amfid" AND eventMessage CONTAINS " not valid: ")'
exclude_match = ['"eventMessage":"/opt/homebrew/']
```

(and add `macos-core.gatekeeper` to `disable_rules`).

Every routine TCC access check, at the cost measured above:

```toml
[[rule]]
id = "site-tcc-all"
type = "macos_unified"
level = "info"
predicate = 'process == "tccd" AND subsystem == "com.apple.TCC" AND (eventMessage BEGINSWITH "Handling access request" OR eventMessage BEGINSWITH "REPLY_MSG")'
```

## What was tested, and what was not

Fixtures are in [`presets/macos/fixtures`](../../presets/macos/fixtures); the golden test
`crates/agent-core/tests/macos_presets.rs` runs each through the preset rule (collector
parsing, the rule pipeline and the wire encoding) on Linux, macOS and Windows and compares
it with `fixtures/expected/<scenario>.ndjson`. On macOS it also checks every predicate with
the real `log`.

| Scenario | Fixture | Source |
| --- | --- | --- |
| Failed sudo | `unified/failed-sudo.ndjson` | Open Directory lines captured on the test Mac (a real failed password check); the `sudo` line itself is synthesised in the same shape (sudo was not run for this work) |
| SSH login | `unified/ssh-login.ndjson` | synthesised: Remote Login is off on the test Mac and the log had no `sshd` messages |
| Screen sharing session | `unified/screen-sharing.ndjson` | captured on the test Mac (a real session) |
| New login item | `unified/login-item.ndjson` | captured on the test Mac (BTM registering an app's login item and a launch agent) |
| Gatekeeper block | `unified/gatekeeper-block.ndjson` | captured on the test Mac: an unsigned, quarantined binary was run and blocked |
| Installs | `install.log` | written in the shape of the test Mac's `install.log` |
| system.log | `system.log` | written in the shape of the test Mac's `system.log` |
| OpenBSM | `bsm/trail.bsm`, `bsm/praudit.xml` | a hand-built binary trail (auditd is not configured on macOS 26 here); the XML is the real `praudit -x -r` output for it on macOS 26.6 |

All captured lines were sanitised: user and host names, addresses, application names,
UUIDs and path hashes were replaced with fictional values, and timestamps moved to
2026-10-21.

Not done yet (needs hardware, accounts or certificates): runs on macOS 14 and 15, on Intel,
on an MDM-managed Mac, as the root launchd daemon with a signed and notarised build, an SSH
login and failed sudo on a real Mac, and the end-to-end check that these events arrive in
Athena.
