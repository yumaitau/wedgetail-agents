# Recommended Windows audit policy for the Wedgetail presets

The `windows-security*` presets select event ids; Windows only writes those events when the
matching **advanced audit policy** subcategory is on. This page lists what the presets need,
based on Microsoft's audit policy recommendations and the Australian Signals Directorate's
(ASD) Windows event logging guidance (sources at the end). `wedgetail-agent status`, run as an
administrator, lists the subcategories below that are off for the presets a host loads.

**The agent never changes audit policy, registry policy or log settings.** Apply them with
Group Policy (Computer Configuration > Policies > Windows Settings > Security Settings >
Advanced Audit Policy Configuration > Audit Policies), Intune or your configuration
management, and test before rolling out widely. Use the advanced subcategories only: mixing
them with the legacy nine "Audit ..." categories gives unpredictable results, so also enable
*Security Options > Audit: Force audit policy subcategory settings to override audit policy
category settings*.

## Audit policy subcategories

GUIDs are what `auditpol /r` prints and what `status` matches, so they work on any display
language. "S" is Success, "F" is Failure.

### `windows-security` (every Windows host)

| Category | Subcategory | GUID | Setting | Events |
| --- | --- | --- | --- | --- |
| Account Logon | Credential Validation | `{0CCE923F-69AE-11D9-BED3-505054503030}` | S and F | 4776 |
| Logon/Logoff | Logon | `{0CCE9215-69AE-11D9-BED3-505054503030}` | S and F | 4624, 4625, 4648 |
| Logon/Logoff | Logoff | `{0CCE9216-69AE-11D9-BED3-505054503030}` | S | 4634, 4647 |
| Logon/Logoff | Account Lockout | `{0CCE9217-69AE-11D9-BED3-505054503030}` | F | 4625 |
| Logon/Logoff | Special Logon | `{0CCE921B-69AE-11D9-BED3-505054503030}` | S | 4672 |
| Logon/Logoff | Other Logon/Logoff Events | `{0CCE921C-69AE-11D9-BED3-505054503030}` | S and F | 4778, 4779 |
| Detailed Tracking | Process Creation | `{0CCE922B-69AE-11D9-BED3-505054503030}` | S | 4688 |
| Detailed Tracking | Process Termination | `{0CCE922C-69AE-11D9-BED3-505054503030}` | S | 4689 |
| Account Management | User Account Management | `{0CCE9235-69AE-11D9-BED3-505054503030}` | S and F | 4720, 4722 to 4726, 4738, 4740, 4767 |
| Account Management | Security Group Management | `{0CCE9237-69AE-11D9-BED3-505054503030}` | S | 4728, 4732, 4756 |
| Policy Change | Audit Policy Change | `{0CCE922F-69AE-11D9-BED3-505054503030}` | S and F | 4719, 4904, 4905 |
| Policy Change | Authentication Policy Change | `{0CCE9230-69AE-11D9-BED3-505054503030}` | S | 4739 |
| Policy Change | MPSSVC Rule-Level Policy Change | `{0CCE9232-69AE-11D9-BED3-505054503030}` | S and F | 4946, 4947, 4948 |
| System | Security System Extension | `{0CCE9211-69AE-11D9-BED3-505054503030}` | S | 4697 |
| Object Access | Other Object Access Events | `{0CCE9227-69AE-11D9-BED3-505054503030}` | S and F | 4698 to 4702 |

1102 (Security log cleared) is always written; it needs no policy.

### `windows-security-dc` (domain controllers)

| Category | Subcategory | GUID | Setting | Events |
| --- | --- | --- | --- | --- |
| Account Logon | Kerberos Authentication Service | `{0CCE9242-69AE-11D9-BED3-505054503030}` | S and F | 4768, 4771 |
| Account Logon | Kerberos Service Ticket Operations | `{0CCE9240-69AE-11D9-BED3-505054503030}` | S and F | 4769 |
| DS Access | Directory Service Access | `{0CCE923B-69AE-11D9-BED3-505054503030}` | S and F | 4662 |
| DS Access | Directory Service Changes | `{0CCE923C-69AE-11D9-BED3-505054503030}` | S | 5136, 5137 |

4768, 4769 and 4771 are collected by `windows-security.logon` on every host but are only
written on domain controllers, so `status` reports the Kerberos subcategories only where
`windows-security-dc` is loaded. 4662 and 5136 also need auditing entries (SACLs) on the
directory objects you care about, for example the domain root for replication rights
(DCSync) and AdminSDHolder, privileged groups and Group Policy objects for changes.

### `windows-security-objects` (opt-in)

| Category | Subcategory | GUID | Setting | Events |
| --- | --- | --- | --- | --- |
| Object Access | File System | `{0CCE921D-69AE-11D9-BED3-505054503030}` | S and F | 4656, 4663 |
| Object Access | Registry | `{0CCE921E-69AE-11D9-BED3-505054503030}` | S and F | 4656, 4663 |
| Object Access | File Share | `{0CCE9224-69AE-11D9-BED3-505054503030}` | S and F | 5140 |
| Object Access | Detailed File Share | `{0CCE9244-69AE-11D9-BED3-505054503030}` | S and F | 5145 |

File System and Registry only log objects with a SACL, so scope SACLs to sensitive data and
persistence keys. Detailed File Share logs every file touched over SMB; ASD and Microsoft
both warn about its volume, so enable it on servers where share access matters (it shows
PsExec-style use of `ADMIN$`), or Failure only.

## Other settings the presets rely on

| Setting | Where | Why |
| --- | --- | --- |
| Include command line in process creation events | Administrative Templates > System > Audit Process Creation (registry `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`, `ProcessCreationIncludeCmdLine_Enabled` = 1) | 4688 carries `CommandLine`; WT-ENDPOINT-001 to 003 match on it. `status` warns when it is off. Command lines can contain secrets typed on the command line; use rule `redact` patterns if that is a concern. |
| Turn on PowerShell Script Block Logging | Administrative Templates > Windows Components > Windows PowerShell | 4104 for every script block, not only the ones PowerShell considers suspicious (WT-ENDPOINT-004 to 006). Leave "Log script block invocation start/stop events" off unless you need 4105/4106: it is very noisy. |
| Turn on Module Logging (module names `*`) | Administrative Templates > Windows Components > Windows PowerShell | 4103 and 800 with cmdlet names and parameters. |
| Remove or disable PowerShell 2.0 | Windows features (`MicrosoftWindowsPowerShellV2Root`) | PowerShell 2.0 writes no script block or module logs; 400 events still show when it is used. |
| Task Scheduler history | `wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true`, or "Enable All Tasks History" | The channel is disabled on some editions; `status` reports it. |
| Security log size and retention | Administrative Templates > Windows Components > Event Log Service > Security > Specify the maximum log file size | The agent reads from the local log; a log that wraps while the agent is stopped or cannot send loses events. Size the Security log to cover the longest outage you expect between host and Wedgetail. |
| Security log access | *Configure log access* in the same place | Leave it unset, or include read for Event Log Readers (`(A;;0x1;;;S-1-5-32-573)`); see [docs/presets/windows.md](../../docs/presets/windows.md#the-security-channel). |

Applying a policy with `auditpol` (for a test machine; use Group Policy in production):

```powershell
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable
auditpol /get /category:* /r
```

## Sources

- Microsoft, *Audit Policy Recommendations* (baseline and stronger recommendations per
  subcategory):
  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations
- Microsoft, *Command line process auditing*:
  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- Microsoft, *about_Logging_Windows* (script block and module logging):
  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Microsoft, *Use Windows Event Forwarding to help with intrusion detection* (event selection,
  Event Log Readers and the Security channel access list):
  https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection
- ASD (Australian Cyber Security Centre), *Windows event logging and forwarding* (October
  2021), with its Group Policy settings and event list:
  https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding
- ASD's ACSC with CISA, NSA, FBI and international partners, *Best practices for event logging
  and threat detection* (August 2024), also published on cyber.gov.au:
  https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection
