# Windows presets

The `windows-*` presets collect the high-value Windows Event Log channels with a curated list
of event ids, so a host gives logon, privilege, process, account, persistence and tamper
evidence without Windows Event Forwarding. Every event is sent as `source_type`
`windows.eventlog` with `fields` in the WEF JSON shape the Wedgetail `windows` normaliser
reads, so the existing endpoint rules (WT-ENDPOINT-*) work on agent data unchanged.

Contents:

- [Presets](#presets)
- [Rights the agent needs](#rights-the-agent-needs)
- [Audit policy and other host settings](#audit-policy-and-other-host-settings)
- [Rules](#rules)
- [How events are collected](#how-events-are-collected)
- [PowerShell script blocks](#powershell-script-blocks)
- [Fixtures](#fixtures)
- [Changing a preset](#changing-a-preset)
- [What is tested where](#what-is-tested-where)

## Presets

| Preset | Selected by `"auto"` | Channels |
| --- | --- | --- |
| `windows-security` | yes | `Security` |
| `windows-security-objects` | no (opt-in, noisy) | `Security` |
| `windows-security-dc` | no (opt-in, for domain controllers) | `Security` |
| `windows-system` | yes | `System` |
| `windows-powershell` | yes | `Microsoft-Windows-PowerShell/Operational`, `Windows PowerShell` |
| `windows-sysmon` | when the Sysmon channel exists | `Microsoft-Windows-Sysmon/Operational` |
| `windows-defender` | when the Defender channel exists | `Microsoft-Windows-Windows Defender/Operational` |
| `windows-operational` | yes | Task Scheduler, RDP (RemoteConnectionManager, LocalSessionManager), WMI-Activity, Windows Firewall, BITS |
| `windows-app-control` | yes | `Microsoft-Windows-AppLocker/*` (4 channels), `Microsoft-Windows-CodeIntegrity/Operational` |
| `windows-app-control-allowed` | no (opt-in, high volume) | `Microsoft-Windows-AppLocker/EXE and DLL`, `Microsoft-Windows-AppLocker/MSI and Script` |

Detection for `windows-sysmon` and `windows-defender` is a registry lookup under
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels`; it runs when the agent
starts or reloads. The agent never installs or configures Sysmon or Defender.

```toml
[agent]
presets = ["auto", "windows-security-dc"]      # a domain controller
# presets = ["auto", "windows-security-objects"] # file servers with SACLs on shares
# presets = ["auto", "windows-app-control-allowed"] # ISM-1660: allowed executions too
```

The preset files are [`presets/windows`](../../presets/windows). `wedgetail-agent
check-config` lists the presets and rules that load on a host.

## Rights the agent needs

The MSI installs the `WedgetailAgent` service as `NT AUTHORITY\LocalService`. What it can read
depends on each channel's access control list (`wevtutil gl <channel>`, `channelAccess`).

| Channels | Needs |
| --- | --- |
| `System`, `Windows PowerShell`, `Microsoft-Windows-PowerShell/Operational`, Task Scheduler, RDP, WMI-Activity, Firewall, BITS, AppLocker, CodeIntegrity, Defender | Nothing extra: their default lists give services (`SU`) read, and also Event Log Readers (`S-1-5-32-573`). |
| `Security` | **Event Log Readers.** The default list is `O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)`: SYSTEM, Administrators, and read for Event Log Readers only. |
| `Microsoft-Windows-Sysmon/Operational` | Event Log Readers. Sysmon's manifest restricts its channel to SYSTEM, Administrators and Event Log Readers (not checked in CI: the runners have no Sysmon). |

So the documented least privilege is **LocalService + Event Log Readers** for every preset
channel, with no other right. The channel lists above are what GitHub's Windows Server 2022
and 2025 runners report (`wevtutil gl`, printed by the CI end-to-end test); check yours with
`wevtutil gl <channel>`.

Add the service account to Event Log Readers once, as an administrator (the group is found by
its well-known SID `S-1-5-32-573`, so this works on any display language), then restart the
service so its new token carries the group:

```powershell
Add-LocalGroupMember -SID 'S-1-5-32-573' -Member 'NT AUTHORITY\LOCAL SERVICE'
Restart-Service WedgetailAgent
```

With Group Policy: Computer Configuration > Preferences > Control Panel Settings > Local
Users and Groups, update the built-in group "Event Log Readers" and add `LOCAL SERVICE`.

### The Security channel

Event Log Readers membership is all the Security channel needs while it keeps its default
access list (above). If `windows-security.*` collectors show `access is denied` in
`wedgetail-agent status`, something has replaced that list: usually the Group Policy setting
*Computer Configuration > Administrative Templates > Windows Components > Event Log Service >
Security > Configure log access*, which sets a custom `ChannelAccess`. Then, in order of
preference:

1. **Least bad: add read for Event Log Readers to the custom list.** Append
   `(A;;0x1;;;S-1-5-32-573)` to the SDDL in that Group Policy setting (or, without Group
   Policy, `wevtutil sl Security /ca:<current SDDL>(A;;0x1;;;S-1-5-32-573)`). This grants
   read only: no clearing, no audit policy or SACL changes.
2. Do **not** give the agent "Manage auditing and security log" (`SeSecurityPrivilege`) or
   make it an administrator. That right lets its holder clear the Security log and change
   object SACLs, which is exactly the tampering these presets exist to detect.

The agent never changes group membership, channel access lists, audit policy or any other
host setting itself; `wedgetail-agent status` only reports.

## Audit policy and other host settings

Most Security events are written only when the matching advanced audit policy subcategory is
on, and some channels need a setting before anything is logged.
[`presets/windows/recommended-audit-policy.md`](../../presets/windows/recommended-audit-policy.md)
lists the recommended settings with their Microsoft and ASD sources.

`wedgetail-agent status`, run as an administrator on Windows, adds a read-only section:

- every recommended subcategory for the loaded presets that is off, from
  `auditpol /get /category:* /r` (matched by subcategory GUID, so localised names still work;
  settings in a language other than English are listed as unrecognised);
- a warning when 4688 process creation events do not include the command line (registry value
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled`);
- channels used by enabled rules that do not exist on the host or are disabled (for example
  Task Scheduler history). A subscription made while its channel was disabled receives
  nothing after the channel is enabled, so reload the agent (`sc.exe control WedgetailAgent
  paramchange`) after enabling one.

`status --json` has the same in a `windows` object:

```json
"windows": {
  "audit_policy": {"checked": true, "off": [{"subcategory": "Process Creation",
    "guid": "{0CCE922B-69AE-11D9-BED3-505054503030}", "setting": "No Auditing",
    "recommended": "Success", "events": "4688"}], "unrecognised": []},
  "process_command_line": false,
  "channels": [{"channel": "Microsoft-Windows-TaskScheduler/Operational", "state": "disabled",
    "rules": ["windows-operational.task-scheduler"]}]
}
```

`auditpol` needs an administrator; otherwise the audit policy part says it was not checked.
The `auditpol` executable is run directly from `System32`, never through a shell, and only by
the interactive `status` command: the service itself runs no programs.

## Rules

Each rule is one Event Log subscription. "Needs" is the audit policy subcategory or setting
without which the events are not written (see the recommended policy).

### windows-security

| Rule id | Event ids | Detection value | Needs |
| --- | --- | --- | --- |
| `windows-security.logon` | 4624, 4625, 4634, 4647, 4648, 4672, 4776, 4768, 4769, 4771, 4778, 4779 | Successful and failed logons with logon type and source address (password spraying, brute force, lateral movement), explicit credential use (`runas`, pass-the-hash tooling), special privileges at logon (admin logons), NTLM validation, Kerberos TGT and service tickets (Kerberoasting, AS-REP roasting; written on domain controllers), RDP reconnects and disconnects | Logon, Logoff, Special Logon, Account Lockout, Other Logon/Logoff Events, Credential Validation; Kerberos subcategories on DCs |
| `windows-security.process` | 4688, 4689 | Process creation with parent, token elevation and (when enabled) the full command line: encoded PowerShell, LOLBins, ransomware tooling (WT-ENDPOINT-001 to 003) | Process Creation, Process Termination; "Include command line in process creation events" |
| `windows-security.accounts` | 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4738, 4740, 4756, 4767 | Accounts created, enabled, disabled, deleted, changed; password changes and resets; members added to global, local and universal security groups (new local administrators); lockouts and unlocks | User Account Management, Security Group Management |
| `windows-security.policy` | 1102, 4719, 4739, 4904, 4905, 4946, 4947, 4948 | Security log cleared (WT-ENDPOINT-015, always written), audit policy changed, domain policy changed, security event sources registered or removed, Windows Firewall rules added, changed or deleted | Audit Policy Change, Authentication Policy Change, MPSSVC Rule-Level Policy Change |
| `windows-security.services` | 4697, 4698, 4699, 4700, 4701, 4702 | Services installed (WT-ENDPOINT-013) and scheduled tasks created, deleted, enabled, disabled or updated, with the task XML: persistence | Security System Extension, Other Object Access Events |

### windows-security-objects (opt-in)

| Rule id | Event ids | Detection value | Needs |
| --- | --- | --- | --- |
| `windows-security-objects.access` | 4656, 4663, 5140, 5145 | Handle requests and access to audited files and registry keys, share access and per-file share access (PsExec over `ADMIN$`, data staging, ransomware on shares) | File System, Registry, File Share, Detailed File Share, plus SACLs on what you want audited. Very noisy without scoped SACLs. |

### windows-security-dc (opt-in, domain controllers)

| Rule id | Event ids | Detection value | Needs |
| --- | --- | --- | --- |
| `windows-security-dc.directory` | 4662, 5136, 5137 | Operations on directory objects (DCSync replication rights use, reads of sensitive attributes), directory objects modified (group membership, GPO and ACL changes) and created | Directory Service Access, Directory Service Changes, plus SACLs on the directory objects of interest |

### windows-system

| Rule id | Event ids | Detection value | Needs |
| --- | --- | --- | --- |
| `windows-system.core` | 7045, 7040, 104, 6005, 6006, 6008, 1074 | Service installed (WT-ENDPOINT-013), service start type changed (disabling security services), any log cleared (WT-ENDPOINT-015), event log service started and stopped, unexpected shutdowns, who requested a shutdown or restart | nothing |
| `windows-system.service-stopped` | 7036, only when a security service stops | Windows Event Log, Microsoft Defender Antivirus (and its network inspection), Defender for Endpoint, Windows Defender Firewall, Security Center, Sysmon or the Wedgetail agent itself stopping | nothing. Matches the English service display names and the word `stopped`; on other display languages copy the rule with the local text. |

### windows-powershell

| Rule id | Event ids | Detection value | Needs |
| --- | --- | --- | --- |
| `windows-powershell.operational` | 4103, 4104, 4105, 4106 | Module logging (cmdlets and parameters), script block text after de-obfuscation (WT-ENDPOINT-004 to 006: download and execute, AMSI and logging tampering), script block start and stop | "Turn on PowerShell Script Block Logging" (4104; PowerShell also logs suspicious blocks without it), "Turn on Module Logging" (4103), invocation logging (4105/4106) |
| `windows-powershell.classic` | 400, 600, 800 | Engine started with host application and engine version (PowerShell 2.0 downgrade), providers started, pipeline execution details | nothing (800 needs module logging) |

### windows-sysmon (when Sysmon is installed)

| Rule id | Event ids | Detection value | Needs |
| --- | --- | --- | --- |
| `windows-sysmon.events` | 1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 22, 23, 25, 26 | Process creation with hashes (WT-ENDPOINT-001 to 003), network connections, driver and image loads, remote threads, process access such as LSASS reads (WT-ENDPOINT-014), file creation and alternate data streams, registry persistence, named pipes, DNS queries, file deletion, process tampering | A Sysmon configuration that logs these ids |

### windows-defender (when Defender is present)

| Rule id | Event ids | Detection value | Needs |
| --- | --- | --- | --- |
| `windows-defender.operational` | 1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012 | Malware and suspicious behaviour detected, actions taken and failed, real-time protection disabled, configuration changed (exclusions added), scanning disabled | nothing |

### windows-operational

| Rule id | Channel | Event ids | Detection value | Needs |
| --- | --- | --- | --- | --- |
| `windows-operational.task-scheduler` | `Microsoft-Windows-TaskScheduler/Operational` | 106, 140, 141, 200, 201 | Tasks registered, updated, deleted, run and completed | The channel enabled (task history); `status` says when it is not |
| `windows-operational.rdp-connections` | `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | 1149 | RDP network-level authentication succeeded, with user and source address | nothing |
| `windows-operational.rdp-sessions` | `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | 21, 22, 23, 24, 25 | Session logon, shell start, logoff, disconnect, reconnect with source address | nothing |
| `windows-operational.wmi` | `Microsoft-Windows-WMI-Activity/Operational` | 5857, 5860, 5861 | WMI provider loads, temporary and permanent event subscriptions (WMI persistence) | nothing |
| `windows-operational.firewall` | `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | 2003, 2004, 2005, 2006, 2033, 2052, 2082, 2097, 2099 | Firewall profile settings changed (firewall turned off), rules added, changed, deleted and all rules deleted. Builds log different ids for the same change: on the CI runners a rule added is 2097 on both Server 2022 and 2025, and deleted is 2006 on 2022 and 2052 on 2025; older builds use 2004/2005/2006/2003, newer ones 2097/2099/2052/2082, so the rule lists both. | nothing |
| `windows-operational.bits` | `Microsoft-Windows-Bits-Client/Operational` | 59, 60 | BITS jobs started (with URL) and stopped: downloads and persistence | nothing |

### windows-app-control

| Rule id | Channel | Event ids | Detection value | Needs |
| --- | --- | --- | --- | --- |
| `windows-app-control.applocker-exe` | `Microsoft-Windows-AppLocker/EXE and DLL` | 8003, 8004 | Executables and DLLs that would be (audit) or were blocked (WT-ENDPOINT-007) | An AppLocker policy |
| `windows-app-control.applocker-script` | `Microsoft-Windows-AppLocker/MSI and Script` | 8006, 8007 | MSI and scripts that would be or were blocked (WT-ENDPOINT-008) | An AppLocker policy |
| `windows-app-control.applocker-packaged-execution` | `Microsoft-Windows-AppLocker/Packaged app-Execution` | 8021, 8022 | Packaged apps that would be or were blocked (WT-ENDPOINT-009) | An AppLocker policy |
| `windows-app-control.applocker-packaged-deployment` | `Microsoft-Windows-AppLocker/Packaged app-Deployment` | 8024, 8025 | Packaged app installs that would be or were blocked | An AppLocker policy |
| `windows-app-control.code-integrity` | `Microsoft-Windows-CodeIntegrity/Operational` | 3033, 3034, 3076, 3077 | Images failing signing requirements, App Control for Business (WDAC) audit and block events (WT-ENDPOINT-010 to 012) | An App Control policy for 3076/3077 |

Audit mode (8003, 8006, 8021, 8024, 3034, 3076) and enforced blocks (8004, 8007, 8022, 8025,
3033, 3077) are both on by default. Allowed executions are in the opt-in preset below.

### windows-app-control-allowed (opt-in, high volume)

| Rule id | Channel | Event ids | Detection value | Needs |
| --- | --- | --- | --- | --- |
| `windows-app-control-allowed.applocker-exe` | `Microsoft-Windows-AppLocker/EXE and DLL` | 8002 | Executables and DLLs allowed to run, with the matching AppLocker rule, file path, hash and publisher | An AppLocker policy (enforced or audit) |
| `windows-app-control-allowed.applocker-script` | `Microsoft-Windows-AppLocker/MSI and Script` | 8005 | MSI files and scripts allowed to run, with the matching rule | An AppLocker policy (enforced or audit) |

ISM-1660 asks for allowed **and** blocked application control events to be centrally logged.
`windows-app-control` gives the blocked and audit half on every host; add
`windows-app-control-allowed` to `presets` on hosts where you need the allowed half as
evidence:

```toml
[agent]
presets = ["auto", "windows-app-control-allowed"]
```

It is opt-in because of volume: AppLocker writes one 8002 event for every allowed program
start (roughly the rate of 4688 process creation), and when DLL rules are enforced one for
every DLL load, which can be thousands an hour per workstation. Turn on one rule only with
`disable_rules = ["windows-app-control-allowed.applocker-exe"]` (scripts and MSI only) if the
EXE and DLL volume is too high. Allowed packaged apps (8020, 8023) and App Control for
Business allowed events are not collected: App Control does not log allowed files by
default, and AppLocker writes 8020/8023 for every packaged app start and install; add your own
rule if you need them.

## How events are collected

- **Subscriptions.** Each rule is an `EvtSubscribe` pull subscription on its channel. The event
  id list becomes an XPath filter, `*[System[(EventID=4624 or EventID=4625 ...)]]`, so the
  Event Log service filters before the agent reads anything. The Event Log service refuses
  expressions with many terms (a single 60-term expression fails with "The specified query is
  invalid" on Server 2025), so an `event_ids` list longer than 20 becomes a structured
  query with one `<Select>` per 20 ids:

  ```xml
  <QueryList><Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=1 or ... or EventID=20)]]</Select>
    <Select Path="Security">*[System[(EventID=21 or ...)]]</Select>
  </Query></QueryList>
  ```

  The presets keep every rule at 20 ids or fewer (a test enforces it) and split categories
  into separate rules instead, which also lets you disable one category.
- **Bookmarks.** After every batch is written to the disk buffer, the agent saves the
  subscription's bookmark (`<state>\checkpoints`). A restart, reload or crash resumes after
  the bookmark, so events written while the agent was stopped are sent once and nothing is
  sent twice. With no bookmark (first start, or a new rule) a subscription starts at new
  events only; history is not back-filled.
- **Shape.** The rendered event XML (`EvtRenderEventXml`) becomes `fields`: `System` (numbers
  for `EventID`, `Version`, `Level`, `Task`, `Opcode`, `EventRecordID`; attributes as objects
  such as `Provider.Name` and `TimeCreated.SystemTime`), `EventData` (named `Data` elements as
  strings; unnamed ones as a `Data` array) and `UserData` (as nested objects). `body` is null
  and `ts` is `TimeCreated`. XML is parsed with depth, node and size limits; a value longer
  than 64 KiB is cut.

Example wire line (shortened):

```json
{"v":1,"source_type":"windows.eventlog","rule_id":"windows-security.logon",
 "ts":"2026-10-21T08:00:02.123456Z","body":null,
 "fields":{"System":{"Provider":{"Name":"Microsoft-Windows-Security-Auditing","Guid":"{54849625-...}"},
   "EventID":4625,"Channel":"Security","Computer":"web-01.example.com",
   "TimeCreated":{"SystemTime":"2026-10-21T08:00:02.1234567Z"},"EventRecordID":812342,...},
  "EventData":{"TargetUserName":"administrator","LogonType":"3","IpAddress":"203.0.113.45",...}},
 "attrs":{}}
```

## PowerShell script blocks

PowerShell writes a long script block as several 4104 events with the same `ScriptBlockId`,
numbered `MessageNumber` 1 to `MessageTotal`. Detections need the whole script, so for 4104
events from `Microsoft-Windows-PowerShell` (and `PowerShellCore`) the agent:

- holds the parts until all have arrived, then sends **one** event: the first part's event
  with the parts' `ScriptBlockText` joined in order, `MessageNumber` and `MessageTotal` set to
  `"1"`, and `attrs.script_block_parts = {"received": n, "total": n}`;
- caps the joined text at 192 KiB measured as JSON, so the event fits the default 256 KiB
  `max_event_bytes`; a capped script is marked `attrs.truncated = true`;
- sends what it has, marked `attrs.truncated = true` with `received` < `total`, when parts are
  still missing after 15 seconds or when more than 16 script blocks are waiting at once;
- keeps the bookmark before any held part, so a restart reads the parts again rather than
  losing them.

Single-part script blocks (`MessageTotal` 1) and malformed part numbers are sent as they are.

## Fixtures

[`presets/windows/fixtures/<preset>/`](../../presets/windows/fixtures) holds rendered event XML
samples (fictional hosts, users and addresses) for every rule, including a 4104 script block
split into three parts, and `expected.ndjson` with the wire lines the agent sends for them
(after reassembly). The test `crates/agent-collectors/tests/windows_presets.rs` checks that
every sample is selected by exactly one rule of its preset, that every rule has a sample, and
that the output matches; regenerate with
`UPDATE_GOLDEN=1 cargo test -p agent-collectors --test windows_presets`.

The `fields` object of each expected line is a ready record for a Wedgetail endpoint rule
fixture:

```sh
jq -s '{connector: "endpoint-windows", format: "windows", records: map(.fields)}' \
  presets/windows/fixtures/windows-system/expected.ndjson
```

`presets/windows/fixtures/auditpol/` holds `auditpol /get /category:* /r` samples for the
`status` audit policy parser.

## Changing a preset

Switch a rule off and, if you want a variant, add your own rule with a new id (`rules.d` file
or `agent.toml`):

```toml
[agent]
disable_rules = ["windows-security.logon"]

# Logons without the very frequent 4624/4634 on a busy server.
[[rule]]
id = "site-windows-logon"
type = "wineventlog"
channel = "Security"
event_ids = [4625, 4648, 4672, 4776, 4778, 4779]
```

PowerShell 7 logs to `PowerShellCore/Operational`; collect it with your own rule
(`channel = "PowerShellCore/Operational"`, `event_ids = [4103, 4104]`); its script blocks are
reassembled the same way.

## What is tested where

- On every OS (CI on Linux, macOS and Windows): preset files load and validate, the XPath and
  structured queries are built as above, the fixtures produce the golden wire lines, script
  block reassembly (order, duplicates, interleaving, size cap, timeout, hostile part numbers),
  and the `auditpol` parser and `status` report.
- On Windows (`windows-latest` unit tests): every preset rule's query is accepted by the Event
  Log service, a structured query with 60 ids still filters, and a subscription resumes after
  its bookmark.
- On Windows Server 2022 and 2025 GitHub runners, with the MSI installed
  (`.github/scripts/windows-e2e.ps1`): the service runs as LocalService in Event Log Readers
  with every default preset collector running, Security included; `status` reports audit
  policy gaps and the 4688 command line setting; events generated for each preset (failed
  logon, new local user and group membership, process creation with command line, service
  install, scheduled task, a script block long enough to be split, firewall rule, log clears)
  arrive at a mock ingest endpoint in the WEF shape; and across a service restart events
  written while it was stopped arrive once, with no event sent twice.
- Not yet tested: Windows Server 2019, Windows 11, domain controllers, Sysmon, and the Athena
  and endpoint rule checks in a real Wedgetail install.
