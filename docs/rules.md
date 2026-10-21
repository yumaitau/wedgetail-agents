# Configuration and rules (schema version 1)

The agent reads `agent.toml` and then every `*.toml` file in the `rules.d` directory next to
it. Built-in presets load first. All files use one TOML schema, version 1, so a rule written
for a preset, `agent.toml` or `rules.d` looks the same.

| OS | `agent.toml` | Rule files |
| --- | --- | --- |
| Linux | `/etc/wedgetail-agent/agent.toml` | `/etc/wedgetail-agent/rules.d/*.toml` |
| macOS | `/Library/Application Support/Wedgetail/agent.toml` | `.../Wedgetail/rules.d/*.toml` |
| Windows | `%ProgramData%\Wedgetail\agent.toml` | `%ProgramData%\Wedgetail\rules.d\*.toml` |

Check a configuration before (re)loading it:

```sh
sudo wedgetail-agent check-config
```

`check-config` prints every problem as `file:line: message`, one per line, and exits non-zero
when anything is wrong. When the configuration is valid it lists the presets and every rule
with the file and line it came from.

Contents:

- [Load order and rule ids](#load-order-and-rule-ids)
- [Reloading](#reloading)
- [Editor support (JSON Schema)](#editor-support-json-schema)
- [`schema_version`](#schema_version)
- [`[agent]`](#agent)
- [`[limits]` and `[heartbeat]`](#limits-and-heartbeat)
- [`[[rule]]`: common fields](#rule-common-fields)
- [`type = "file"`](#type--file)
- [`type = "journald"`](#type--journald)
- [`type = "wineventlog"`](#type--wineventlog)
- [`type = "macos_unified"`](#type--macos_unified)
- [The event pipeline](#the-event-pipeline)
- [Parsers](#parsers)
- [Which files a rule may read](#which-files-a-rule-may-read)
- [Presets](#presets)
- [Compatibility](#compatibility)
- [Design note: signed rule bundles (not in v1)](#design-note-signed-rule-bundles-not-in-v1)

## Load order and rule ids

1. Presets selected by `[agent] presets`, in the agent's preset order.
2. `[[rule]]` tables in `agent.toml`.
3. `rules.d/*.toml`, in byte-wise file name order (`10-web.toml` before `20-db.toml`; note
   `9-x.toml` sorts after `10-web.toml`, so pad numbers). Other file names are ignored.

`rules.d` files may only hold `schema_version` and `[[rule]]` tables; agent settings belong in
`agent.toml`. Each file is at most 1 MiB, and at most 1,000 rule files are read.

Every rule id must be unique across all files and presets. A repeated id is an error that names
both places:

```text
/etc/wedgetail-agent/rules.d/40-dup.toml:3: rule id "nginx-access" is used more than once (first defined at /etc/wedgetail-agent/rules.d/10-web.toml:1)
```

To change a preset rule, disable it with `[agent] disable_rules` and add your own rule with a
new id.

## Reloading

| OS | Reload |
| --- | --- |
| Linux | `sudo systemctl reload wedgetail-agent` (sends `SIGHUP`) |
| macOS | `sudo launchctl kill HUP system/au.com.yumait.wedgetail-agent` |
| Windows | `sc.exe control WedgetailAgent paramchange` |

On a reload the agent reads and validates every file again. If the new configuration is
valid, collection restarts with it; the disk buffer and checkpoints carry over, so no event is
lost or sent twice. If it is invalid, the problems are written to the agent log
(`journalctl -u wedgetail-agent`, `/Library/Logs/Wedgetail/agent.log`,
`%ProgramData%\Wedgetail\state\agent.log`) and the agent keeps running the last good
configuration. A foreground `wedgetail-agent run` on Linux and macOS reloads on `SIGHUP` too.

## Editor support (JSON Schema)

[`schema/rules.v1.json`](../schema/rules.v1.json) is a JSON Schema for these files, generated
from the agent's own types (CI fails if it is out of date). Editors with a TOML language
server such as Taplo (Even Better TOML in VS Code) use it when a file starts with:

```toml
#:schema https://raw.githubusercontent.com/yumaitau/wedgetail-agents/main/schema/rules.v1.json
```

The schema checks names, types and enumerations. Ranges, regular expressions, paths and
duplicate ids are checked by `check-config`.

## `schema_version`

```toml
schema_version = 1
```

Optional in every file; leaving it out means `1`. Any other value is refused by this agent.

## `[agent]`

Only in `agent.toml`.

```toml
[agent]
endpoint = "https://ingest.example.com/"
buffer_max_mb = 256
presets = ["auto"]
disable_rules = ["linux-core.kernel"]
max_open_files = 1000
# state_dir = "/var/lib/wedgetail-agent"
```

| Field | Type | Default | Valid values |
| --- | --- | --- | --- |
| `endpoint` | string | required | `https://host[:port][/path]`; no credentials, query or fragment; at most 2,048 characters. Plain `http://` is refused. |
| `buffer_max_mb` | integer | `256` | 16 to 65,536. When the disk buffer is full the oldest unsent events are dropped and counted in the heartbeat (`dropped.buffer_full`). |
| `presets` | string or list | `"auto"` | `"auto"`, a list of preset ids, a list with `"auto"` plus opt-in presets (`["auto", "linux-containers"]`), or `[]` for none. Unknown ids are errors; ids for another OS are skipped with a warning. |
| `disable_rules` | list of rule ids | `[]` | Rule ids from presets or rule files to switch off. An id also switches off the rules under it: `linux-core.auth` switches off `linux-core.auth.journald` too, and `linux-core` every rule of that preset. An id that matches no rule is a warning, not an error, so one file can be shared by hosts that load different presets. |
| `max_open_files` | integer | `1000` | 1 to 100,000. Most files tailed at once across all `file` rules; files over the cap are skipped with a warning in the agent log. |
| `state_dir` | path | per OS | Disk buffer, checkpoints, `status.json` and the credential. Linux `/var/lib/wedgetail-agent`, macOS `/Library/Application Support/Wedgetail/state`, Windows `%ProgramData%\Wedgetail\state`. |

Older files may set `endpoint` and `state_dir` at the top level and `[buffer] max_mb`; they
still load, but setting the same thing both ways is an error.

## `[limits]` and `[heartbeat]`

```toml
[limits]
max_batch_bytes = 1048576
max_batch_uncompressed_bytes = 8388608
max_batch_records = 5000
max_requests_per_minute = 120
max_event_bytes = 262144

[heartbeat]
interval_s = 60
```

| Field | Default | Valid values |
| --- | --- | --- |
| `limits.max_batch_bytes` | 1 MiB | 1,024 to 1,048,576 (gzip request body) |
| `limits.max_batch_uncompressed_bytes` | 8 MiB | 1,024 to 8,388,608 |
| `limits.max_batch_records` | 5,000 | 1 to 5,000 |
| `limits.max_requests_per_minute` | 120 | 1 to 120 |
| `limits.max_event_bytes` | 256 KiB | 1,024 to `max_batch_bytes`; larger events are dropped and counted (`dropped.oversize`) |
| `heartbeat.interval_s` | 60 | 10 to 3,600 |

The defaults are the server limits; they can be lowered, not raised.

## `[[rule]]`: common fields

These fields work with every rule type.

```toml
[[rule]]
id = "nginx-access"
type = "file"
paths = ["/var/log/nginx/access.log"]
enabled = true
source_type = "file"
source_label = "web/nginx"
tags = { env = "prod", app = "shop" }
include_match = ['\s(4|5)\d\d\s']
exclude_match = ['/healthz']
redact = [{ pattern = 'password=\S+', replace = "password=[REDACTED]" }]
sample_rate = 1.0
rate_limit = { events_per_second = 500, burst = 2000 }
```

| Field | Type | Default | Valid values and meaning |
| --- | --- | --- | --- |
| `id` | string | required | `^[a-z0-9][a-z0-9._-]{0,63}$`, unique. Sent as `rule_id`; used by `disable_rules`. |
| `type` | string | required | `file`, `journald` (Linux), `wineventlog` (Windows), `macos_unified` (macOS). `command` is refused: the agent never runs commands. A type the OS does not support fails `check-config` on that OS. |
| `enabled` | bool | `true` | `false` keeps the rule without running it. |
| `source_type` | string | per type | 1 to 64 characters of `[A-Za-z0-9._-]`. Defaults: `file`, `journald`, `windows.eventlog`, `macos.unified`. |
| `source_label` | string | none | 1 to 256 characters, no control characters. Sent as `attrs.source_label`. |
| `tags` | table of strings | none | At most 32; keys 1 to 64 characters, values up to 256, no control characters. Sent as `attrs.tags`. |
| `include_match` | list of regex | none | Keep only events matching at least one. At most 32, each at most 1,024 characters. |
| `exclude_match` | list of regex | none | Drop events matching any. Same limits. |
| `redact` | list of `{ pattern, replace }` | none | At most 32. Every match of `pattern` (a regex) is replaced with `replace` (literal text, default `[REDACTED]`, at most 256 characters; `$1` is not expanded). |
| `sample_rate` | float | `1.0` | Greater than 0 and at most 1: the fraction of events kept. Dropped events are counted in the heartbeat as `dropped.sampled`. |
| `rate_limit` | `{ events_per_second, burst }` | none | A token bucket per rule. `events_per_second` 1 to 1,000,000 (required); `burst` 1 to 10,000,000, default `events_per_second`. Events over the limit are dropped and counted as `dropped.rate_limited`. |

Regular expressions use the Rust [`regex`](https://docs.rs/regex) syntax. It runs in time
linear in the input, so there are no look-around assertions or backreferences, and each
compiled expression is capped in size; a rule cannot make the agent hang. Use single-quoted
TOML strings (`'\d+'`) so backslashes need no escaping.

## `type = "file"`

Tail text files, following rotation (rename and create, or copytruncate).

```toml
[[rule]]
id = "app"
type = "file"
paths = ["/var/log/app/*.log", "/srv/app/**/current.log"]
exclude = ["*.gz", "/var/log/app/debug-*.log"]
start_at = "end"
multiline = { pattern = '^\d{4}-', negate = true, match = "after", max_lines = 500 }
parser = "regex"
regex = '^(?P<time>\S+) (?P<level>[A-Z]+) (?P<message>.*)$'
max_line_bytes = 65536
```

| Field | Type | Default | Valid values and meaning |
| --- | --- | --- | --- |
| `paths` | list of paths | required | 1 to 64 absolute paths or globs (`*`, `?`, `[abc]`, `**` for any depth). No `.` or `..` components. See [Which files a rule may read](#which-files-a-rule-may-read). |
| `format` | string | `"lines"` | How the file becomes events: `lines` (text lines), `auditd`, `utmp` or `lastlog`. See [`format`](#format). |
| `exclude` | list of globs | none | At most 64. A pattern with a path separator is matched against the whole path (`/var/log/app/debug-*.log`), otherwise against the file name (`*.gz`). |
| `start_at` | string | `"end"` | Where to start in a file that has no checkpoint when the agent starts: `end` (only new lines) or `beginning`. Files that appear later are always read from the start. |
| `multiline` | table | none | Join continuation lines into one event; see below. |
| `parser` | string | `"raw"` | `raw`, `json`, `syslog_rfc3164`, `syslog_rfc5424`, `cef`, `logfmt`, `regex`, `nginx_combined`, `apache_combined`. See [Parsers](#parsers). |
| `regex` | string | none | Required with, and only allowed with, `parser = "regex"`. At most 4,096 characters, at least one named capture (`(?P<name>...)`); named captures become fields. |
| `max_line_bytes` | integer | `65536` | 256 to 1,048,576. Longer lines (and multiline events) are cut and marked `attrs.truncated = true`. |

Globs are expanded again every 5 seconds, so new files are picked up. Rotated files are
followed by identity (inode or Windows file index), not name: a file matched under two names
is read once, a renamed file is drained before it is let go, and a glob that also matches
rotated names (`app.log*`) does not read the same lines twice. Exclude compressed rotations
(`*.gz`) anyway: they are not text.

### `format`

| Value | Reads | Events |
| --- | --- | --- |
| `lines` | text, one event per line (or per `multiline` group) | `body` is the line; `parser` fills `fields` |
| `auditd` | the Linux audit log (`/var/log/audit/audit.log`) | one event per audit event: the records with the same `msg=audit(<time>:<serial>)` merged into `fields.records`, hex values decoded; `body` is null. `max_line_bytes` caps the raw bytes kept per event |
| `utmp` | binary login records (`/var/log/wtmp`, `/var/log/btmp`), glibc layout of the agent's architecture | one event per record, `fields` decoded; `body` is null |
| `lastlog` | binary `/var/log/lastlog`; exactly one path, no globs | a summary of every user's last login, at most once an hour and only when the file changed |

`multiline` and `parser` apply only to `lines`, and `max_line_bytes` to `lines` and `auditd`.
The fields each format produces are listed in [docs/presets/linux.md](presets/linux.md). A
file is still followed through rotation and truncation; `auditd` checkpoints at the first
record of the oldest unfinished event, so a restart reads and merges it again.

### `multiline`

| Field | Type | Default | Valid values and meaning |
| --- | --- | --- | --- |
| `pattern` | regex | required | Tested against each line (at most 1,024 characters). |
| `negate` | bool | `false` | With `false`, lines that match are continuations; with `true`, lines that do **not** match are. |
| `match` | string | `"after"` | `after`: continuations join the line before them. `before`: continuations join the next line that is not a continuation. |
| `max_lines` | integer | `500` | 1 to 10,000 lines per event. |

An event is also sent when no new line has arrived for 3 seconds, and when it reaches
`max_line_bytes`. Common settings:

```toml
# Java/Python stack traces: every event starts with a date.
multiline = { pattern = '^\d{4}-\d{2}-\d{2}', negate = true, match = "after" }
# Indented continuation lines.
multiline = { pattern = '^\s', match = "after" }
# Lines ending in a backslash continue on the next line.
multiline = { pattern = '\\$', match = "before" }
```

## `type = "journald"`

Linux only. Follows the systemd journal through `journalctl`. Events carry the journal fields
`MESSAGE`, `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, `_PID`, `_UID`, `PRIORITY`,
`SYSLOG_FACILITY`, `_TRANSPORT`, `_COMM` and `_EXE` in `fields`, and no `body`.

```toml
[[rule]]
id = "custom-journald"
type = "journald"
units = ["myapp.service"]
matches = ["SYSLOG_IDENTIFIER=myapp"]
priority_max = 6
```

| Field | Type | Default | Valid values and meaning |
| --- | --- | --- | --- |
| `units` | list | none | At most 64 systemd unit names (`[A-Za-z0-9:_.\@-]`, not starting with `-` or `.`). `.service` is added to a name with no suffix. Becomes `_SYSTEMD_UNIT=` matches. |
| `matches` | list | none | `FIELD=value` journal matches, `FIELD` in `[A-Z0-9_]` (at most 64 characters), value at most 1,024. The same field is ORed, different fields are ANDed (so `units` and other matches are ANDed). |
| `priority_max` | integer | none | 0 (emerg) to 7 (debug): keep this priority and everything more severe. 6 drops debug messages. |

No `units` and no `matches` means the whole journal.

## `type = "wineventlog"`

Windows only. Subscribes to an Event Log channel; `fields` holds the event in the WEF JSON
shape (`System`, `EventData`), and there is no `body`.

```toml
[[rule]]
id = "win-rdp"
type = "wineventlog"
channel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
event_ids = [1149]
# xpath = "*[System[(EventID=1149)]]"
```

| Field | Type | Default | Valid values and meaning |
| --- | --- | --- | --- |
| `channel` | string | required | 1 to 256 characters, for example `Security`, `System`, `Microsoft-Windows-Sysmon/Operational`. Reading `Security` and Sysmon needs the agent account in Event Log Readers; see [Windows presets](presets/windows.md#rights-the-agent-needs). |
| `event_ids` | list of integers | all | At most 256 ids, each 1 to 65,535. Filtered by the Event Log service at subscription time; more than 20 ids become a structured query with one `Select` per 20, because the service refuses long expressions. |
| `xpath` | string | none | A raw XPath query, or a structured `<QueryList>` query (1 to 4,096 characters); overrides `event_ids`. |

Events resume after a saved bookmark, so a restart neither repeats nor loses events. Split
PowerShell 4104 script blocks are joined into one event (see
[Windows presets](presets/windows.md#powershell-script-blocks)).

## `type = "macos_unified"`

macOS only. Streams the unified log through `/usr/bin/log`; `fields` holds `subsystem`,
`category`, `process`, `processImagePath`, `sender`, `eventMessage`, `messageType`,
`eventType`, `userID` and `timestamp`, and there is no `body`.

```toml
[[rule]]
id = "mac-ssh"
type = "macos_unified"
predicate = 'process == "sshd"'
level = "info"
```

| Field | Type | Default | Valid values and meaning |
| --- | --- | --- | --- |
| `predicate` | string | none (everything) | A `log stream --predicate` filter, 1 to 4,096 characters. |
| `level` | string | `"info"` | `default`, `info` or `debug` (very noisy): the least severe messages streamed. |

## The event pipeline

Every event from a rule goes through these steps, in order, **before** it is written to the
disk buffer:

1. `include_match` and `exclude_match`. Dropped events are filtered on purpose and not counted
   as loss.
2. `sample_rate`. Dropped events are counted in the heartbeat as `dropped.sampled`.
3. `rate_limit`. Dropped events are counted in the heartbeat as `dropped.rate_limited`.
4. `redact`, on the raw line and on every string inside `fields`. A redacted secret never
   reaches the disk buffer, the network or a parser.
5. The `parser`, on the redacted line. Its output is the event's `fields`. A line the parser
   does not recognise is kept, with `attrs.parse_error` set to the parser name.

Events with a raw line (`file` rules) are matched on the line. Events without one (`journald`,
`wineventlog`, `macos_unified`) are matched on their `fields` as compact JSON, for example
`{"MESSAGE":"Failed password for root from 192.0.2.10","_SYSTEMD_UNIT":"ssh.service"}`.

The heartbeat (`agent.heartbeat`, every 60 seconds) reports the drop counters:

```json
"dropped": {"buffer_full": 0, "rate_limited": 1250, "sampled": 9000, "oversize": 0}
```

`wedgetail-agent status` shows the same counters.

## Parsers

Values of `-` (nil) are left out. Numbers are JSON numbers where noted, everything else is a
string. Golden-file tests for each parser are in
[`crates/agent-config/tests/parsers`](../crates/agent-config/tests/parsers).

| Parser | Input | `fields` |
| --- | --- | --- |
| `raw` | anything | none (the line is in `body`) |
| `json` | one JSON object per line | the object as is (nesting limited to 128 levels) |
| `syslog_rfc3164` | `[<PRI>]Mmm dd hh:mm:ss host tag[pid]: message`, or the same with an RFC 3339 time as written by rsyslog | `priority`, `facility`, `severity` (numbers, when `<PRI>` is present), `timestamp`, `hostname`, `app_name`, `proc_id`, `message`. A line without `tag:` keeps everything after the host as `message`. |
| `syslog_rfc5424` | `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD [MSG]` | `priority`, `facility`, `severity`, `version` (numbers), `timestamp`, `hostname`, `app_name`, `proc_id`, `msg_id`, `structured_data` (`{"id@pen": {"param": "value"}}`), `message` |
| `cef` | `CEF:Version\|Vendor\|Product\|Version\|SignatureID\|Name\|Severity\|Extension`, optionally after a syslog header | `cef_version`, `device_vendor`, `device_product`, `device_version`, `signature_id`, `name`, `severity`, `extensions` (`{"src": "192.0.2.10", ...}`); CEF escapes are undone |
| `logfmt` | `key=value key2="quoted \"value\"" flag` | one field per key; a bare key is `true` |
| `regex` | anything the rule's `regex` matches | one field per named capture that took part in the match |
| `nginx_combined` | nginx `combined` log format | `remote_addr`, `remote_user`, `time_local`, `request`, `method`, `path`, `protocol`, `status`, `body_bytes_sent` (numbers), `http_referer`, `http_user_agent`; extra fields after the user agent are ignored |
| `apache_combined` | Apache `combined` log format | as `nginx_combined`, plus `ident` |

`logfmt` lines and CEF extensions produce at most 256 fields each.

Example: with `parser = "syslog_rfc3164"` the line

```text
Oct 21 08:00:00 web-01 sshd[812]: Accepted publickey for alice from 192.0.2.10 port 52113 ssh2
```

becomes

```json
{"timestamp": "Oct 21 08:00:00", "hostname": "web-01", "app_name": "sshd", "proc_id": "812",
 "message": "Accepted publickey for alice from 192.0.2.10 port 52113 ssh2"}
```

## Which files a rule may read

A `file` rule's **root** is the directory made of the path components before the first one
with a glob character; for a plain path it is the file's directory. For
`/var/log/nginx/*.log` the root is `/var/log/nginx`; for `/srv/app/**/*.log` it is `/srv/app`;
for `/var/log/auth.log` it is `/var/log`.

Before a matched file is opened, its path is canonicalised (symlinks and `..` resolved) and it
is refused unless:

- the canonical file is inside the canonical root. A symlink in `/var/log/nginx` pointing at
  `/etc/shadow` is not followed; a symlink to another file in the same root is. If your logs
  really live elsewhere, name the real location in `paths`;
- it is not inside one of the agent's own directories: `state_dir` (credential, disk buffer,
  checkpoints), the configuration directory (`agent.toml`, `rules.d`) and, on macOS, the
  keychains (`/Library/Keychains`) and the agent log directory (`/Library/Logs/Wedgetail`);
- it is a regular file (not a directory, device or pipe).

Refused files, and files the agent's account cannot open, are skipped with a warning in the
agent log. `check-config` also refuses a rule
whose path or root is inside one of the agent's own directories.

The agent also reads only what its service account can read: on Linux the `wedgetail-agent`
user in the `adm` and `systemd-journal` groups, on Windows `LocalService`. These checks stop
a rule file from turning the agent into a way to ship its own credential or another
restricted file off the host.

All `file` rules together keep at most `max_open_files` files open (default 1,000). The
packaged Linux and macOS services raise the process open-file limit to 8,192 to leave room
for it.

## Presets

Presets are curated rule files compiled into the agent, one set per OS (`linux-*`,
`windows-*`, `macos-*`). Each preset rule id starts with the preset id, for example
`linux-core.sshd`, so you can switch single rules off:

```toml
[agent]
presets = ["auto", "linux-containers"]
disable_rules = ["linux-core.kernel"]
```

`"auto"` selects the presets that are on by default for the OS plus the ones whose source is
detected on the host (for example `linux-auditd` when auditd is running). `check-config`
lists the presets that were loaded and the heartbeat reports them.

Some preset rules only apply to some hosts, for example `/var/log/auth.log` on Debian and
Ubuntu, `/var/log/secure` on RHEL, or the journal where neither exists. Such a preset rule is
loaded switched off when the host does not have its source (checked at start and on every
reload), and `check-config` shows it as disabled.

| OS | Presets |
| --- | --- |
| Linux | `linux-core`, `linux-auditd`, `linux-containers`: [docs/presets/linux.md](presets/linux.md) |
| Windows | `windows-security`, `windows-security-objects`, `windows-security-dc`, `windows-system`, `windows-powershell`, `windows-sysmon`, `windows-defender`, `windows-operational`, `windows-app-control`: [docs/presets/windows.md](presets/windows.md) |

## Compatibility

- The schema is versioned. Files written for version 1 keep loading in later agents: new
  settings are added as optional fields, and a breaking change would be version 2.
- Unknown keys are errors, so a typo is reported rather than ignored. A file using a setting
  from a newer agent is refused by an older one; `check-config` with the older binary says
  which key.

## Design note: signed rule bundles (not in v1)

In v1 rule files are placed by your own configuration management (Ansible, Puppet, Intune,
Jamf, MDM), and the agent trusts what it finds in its root-owned configuration directory.
A later release may add signed rule bundles so a central team can distribute rules without
trusting the host file system alone:

- A bundle is a tar of rule files plus a manifest (bundle name, version, created time, the
  SHA-256 of each file) and a detached Ed25519 signature over the manifest.
- The signing key is held by the customer, never by Wedgetail. Hosts are configured with one
  or more trusted public keys in `agent.toml` (`[agent] bundle_keys`), installed with the rest
  of the configuration.
- The agent verifies the signature and every file hash before loading a bundle, refuses a
  version older than the last one loaded (no rollback), and applies the same validation as
  `rules.d`. A bad bundle is rejected as a whole and the last good configuration is kept.
- Bundles are still delivered by your tooling into a directory such as `bundles.d`; the agent
  does not fetch them, so there is still no inbound or remote-control channel.
- Key rotation: list both keys during the overlap. Revocation: remove the key and reload.

This is a design only; nothing in v1 reads bundles.
