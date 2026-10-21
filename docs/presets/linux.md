# Linux presets

Three built-in presets collect the high-value Linux security logs. They are ordinary rule
files ([`presets/linux/`](../../presets/linux)) compiled into the agent, using the schema in
[docs/rules.md](../rules.md).

| Preset | Selected by `presets = ["auto"]` | What it collects |
| --- | --- | --- |
| `linux-core` | always | authentication (sshd, sudo, su, PAM, logind, polkit, account changes), security-relevant kernel messages, cron and systemd timers, firewall services, package managers, login records |
| `linux-auditd` | when auditd is running (its pid file names a live `auditd`) or `/var/log/audit/audit.log` can be opened | the audit log, records merged per event |
| `linux-containers` | only when named: `presets = ["auto", "linux-containers"]` | Docker, containerd and kubelet journals, Kubernetes API server audit log |

Every rule id starts with its preset id, so a rule can be switched off on its own. An id also
switches off the rules under it: `linux-core.auth` switches off `linux-core.auth`,
`linux-core.auth.journald` and `linux-core.auth.messages`, and `linux-core` the whole preset.

```toml
[agent]
presets = ["auto", "linux-containers"]
disable_rules = ["linux-core.kernel", "linux-core.btmp"]
```

`wedgetail-agent check-config` lists every rule with its type, `source_type` and whether it is
enabled on this host.

Contents:

- [Distribution detection](#distribution-detection)
- [Rules](#rules)
- [Wire format and `fields` per `source_type`](#wire-format-and-fields-per-source_type)
- [Host metadata](#host-metadata)
- [Permissions](#permissions)
- [Richer data: what to enable](#richer-data-what-to-enable)
- [Fixtures and golden files](#fixtures-and-golden-files)
- [Not yet measured](#not-yet-measured)

## Distribution detection

Distributions write the same messages to different places, and many minimal images log to
the journal only. Sources that differ have one rule per place: `<id>` reads the
distribution's file, `<id>.journald` the systemd journal, and `<id>.messages` busybox
`/var/log/messages` (Alpine). When the configuration is loaded (at start and on every reload)
the agent reads `/etc/os-release` (`ID`, `ID_LIKE`) and checks which files exist, and
switches on exactly one variant per source, so a message is never sent twice. The others are
listed as disabled by `check-config`.

Authentication (`linux-core.sshd`, `linux-core.auth`):

1. The family's own file, when it exists (rsyslog is installed): Debian and Ubuntu
   (`ID`/`ID_LIKE` `debian`, `ubuntu`) `/var/log/auth.log`; RHEL, Fedora, CentOS, Rocky,
   Alma, Oracle and Amazon Linux (`rhel`, `fedora`, `centos`, `rocky`, `almalinux`, `ol`,
   `amzn`) `/var/log/secure`; others either.
2. Otherwise the journal, when journald runs (`/run/systemd/journal` exists) and
   `/usr/bin/journalctl` is installed: `.journald`.
3. Otherwise `/var/log/auth.log` or `/var/log/secure` if either exists, then busybox
   `/var/log/messages` (`.messages`).
4. With none of them the file rule stays on and picks the file up when it appears.

| Host (as shipped) | Authentication | Kernel | Cron |
| --- | --- | --- | --- |
| Ubuntu 22.04 / 24.04 server (rsyslog) | `/var/log/auth.log` | journal | journal |
| Ubuntu minimal / cloud images without rsyslog | journal | journal | journal |
| Debian 12 (no rsyslog by default) | journal | journal | journal |
| Debian 12 with rsyslog | `/var/log/auth.log` | journal | journal |
| RHEL 9 (rsyslog) | `/var/log/secure` | journal | `/var/log/cron` |
| Amazon Linux 2023 (no rsyslog) | journal | journal | journal |
| Alpine 3.x (busybox syslogd, no journal) | `/var/log/messages` (auth, authpriv) | `/var/log/messages` (kern) | `/var/log/messages` (cron) |

These cases are unit-tested with the real os-release files of each distribution
([`fixtures/os-release/`](../../presets/linux/fixtures/os-release)) in
`crates/agent-config/src/linux.rs`. Package manager rules are switched on when the package
manager is installed (`/var/lib/dpkg/status`, `/var/log/apt`, `/usr/bin/dnf`, `yum.log`,
`/var/log/zypp`); journal rules only on hosts with a journal.

## Rules

| Rule id | Type | Source | `source_type` | Parser / format | On when |
| --- | --- | --- | --- | --- | --- |
| `linux-core.sshd` | file | `/var/log/auth.log`, `/var/log/secure`: `sshd`, `sshd-session`, `sshd-auth` lines | `linux.auth` | `syslog_rfc3164` | auth file |
| `linux-core.sshd.journald` | journald | `SYSLOG_IDENTIFIER=sshd`, `sshd-session`, `sshd-auth` (any unit: `ssh.service`, `sshd.service`, `sshd@.service`) | `linux.auth` | journal fields | journal only |
| `linux-core.sshd.messages` | file | `/var/log/messages`, auth/authpriv `sshd` lines | `linux.auth` | busybox regex | busybox |
| `linux-core.auth` | file | `/var/log/auth.log`, `/var/log/secure` except sshd: sudo, su, `pam_unix`, systemd-logind, polkit, useradd, usermod, userdel, groupadd, passwd, chpasswd, login, cron PAM sessions | `linux.auth` | `syslog_rfc3164` | auth file |
| `linux-core.auth.journald` | journald | `SYSLOG_FACILITY=4` (auth) and `10` (authpriv), except sshd | `linux.auth` | journal fields | journal only |
| `linux-core.auth.messages` | file | `/var/log/messages`, auth/authpriv facilities except sshd | `linux.auth` | busybox regex | busybox |
| `linux-core.kernel` | journald | `_TRANSPORT=kernel`, security-relevant messages only (below) | `linux.kernel` | journal fields | journal |
| `linux-core.kernel.messages` | file | `/var/log/messages`, `kern.* kernel:` lines with the same filter | `linux.kernel` | busybox regex | no journal |
| `linux-core.cron` | file | `/var/log/cron` (CROND, crontab, run-parts, anacron) | `linux.cron` | `syslog_rfc3164` | `/var/log/cron` exists |
| `linux-core.cron.journald` | journald | `SYSLOG_FACILITY=9` (cron): CRON/crond jobs, crontab edits | `linux.cron` | journal fields | journal, no cron file |
| `linux-core.cron.messages` | file | `/var/log/messages`, `cron.*` lines | `linux.cron` | busybox regex | no journal |
| `linux-core.timers` | journald | systemd (`_PID=1`) messages about `.timer` units and transient `run-*.service`/`.timer` units (`systemd-run`) | `linux.cron` | journal fields | journal |
| `linux-core.firewall` | journald | units `firewalld.service`, `ufw.service` (packet LOG lines are kernel messages) | `journald` | journal fields | journal |
| `linux-core.dpkg` | file | `/var/log/dpkg.log`: install, upgrade, remove, purge | `linux.package` | regex | dpkg installed |
| `linux-core.apt` | file | `/var/log/apt/history.log`, one event per `Start-Date` ... `End-Date` entry | `linux.package` | multiline + regex | apt installed |
| `linux-core.dnf` | file | `/var/log/dnf.rpm.log` (dnf 4: RHEL 8/9, Amazon Linux 2023): Installed, Upgrade(d), Downgrade(d), Erase, Reinstall(ed), Obsolete(d) | `linux.package` | regex | dnf installed |
| `linux-core.yum` | file | `/var/log/yum.log` (yum 3: RHEL 7, Amazon Linux 2) | `linux.package` | regex | yum (not dnf) installed |
| `linux-core.zypp` | file | `/var/log/zypp/history`: install, remove | `linux.package` | regex | zypper installed |
| `linux-core.wtmp` | file | `/var/log/wtmp`: logins, logouts, boots, shutdowns, run levels, clock changes | `linux.login` | `format = "utmp"` | always |
| `linux-core.btmp` | file | `/var/log/btmp`: failed logins (see [Permissions](#permissions)) | `linux.login` | `format = "utmp"` | always |
| `linux-core.lastlog` | file | `/var/log/lastlog`, summarised: each user's last login | `linux.login` | `format = "lastlog"` | always |
| `linux-auditd.audit` | file | `/var/log/audit/audit.log` | `linux.auditd` | `format = "auditd"` | preset selected |
| `linux-containers.docker` | journald | unit `docker.service` | `journald` | journal fields | journal |
| `linux-containers.containerd` | journald | unit `containerd.service` | `journald` | journal fields | journal |
| `linux-containers.kubelet` | journald | unit `kubelet.service` | `journald` | journal fields | journal |
| `linux-containers.k8s-audit` | file | `/var/log/kubernetes/audit/*.log` (API server `--audit-log-path`), JSON lines | `file` | `json` | preset selected |

The kernel filter keeps messages matching any of: `taints kernel`, `tainting kernel`,
`module verification failed`, `Loading of unsigned module`, `Lockdown:` (out-of-tree and
unsigned module loads); `segfault at`, `general protection fault`, `traps:`, `Oops:`, `BUG:`;
`audit:` (kernel audit lines when auditd is not running), AppArmor `apparmor="DENIED"` and
`"AUDIT"`, SELinux `avc: denied`; `IN=... OUT=...` (iptables, nftables and UFW `LOG` targets);
`New USB device found`. Everything else from the kernel is dropped on the host.

The `dnf.log` debug log, zypper `command` and `patch` lines, dpkg `status`/`configure`/
`trigproc` lines and on Debian-family hosts without a journal `/var/log/kern.log` and
`/var/log/syslog` are not read.

## Wire format and `fields` per `source_type`

Every event is one v1 NDJSON line (see the wire contract):

```json
{"v":1,"source_type":"linux.auth","rule_id":"linux-core.sshd","ts":"2026-10-21T08:00:01.104512Z",
 "body":"<raw line or null>","fields":{...},"attrs":{"path":"/var/log/auth.log"}}
```

- `ts`: for text lines the time the agent read the line (the line's own time is in
  `fields.timestamp`); for journal entries `__REALTIME_TIMESTAMP`; for utmp records the
  record time; for audit events the `msg=audit(<time>:<serial>)` time; for the lastlog summary
  the time it was made.
- `body`: the raw line (after redaction) for text files; `null` for journal entries, utmp
  records, audit events and the lastlog summary, whose content is all in `fields`.
- `attrs.path`: the file read (file rules only). `attrs.truncated: true` when a line or audit
  event was cut to the rule's limit. Rules may add `attrs.source_label` and `attrs.tags`.

All values are strings unless the type says otherwise. Keys are left out when the source has
no value.

### Text lines: `syslog_rfc3164` (`linux.auth`, `linux.cron` from files)

From `/var/log/auth.log`, `/var/log/secure`, `/var/log/cron`.

| Key | Type | Example |
| --- | --- | --- |
| `timestamp` | string, as written: `Mmm dd hh:mm:ss` (RHEL, older Debian) or RFC 3339 (Ubuntu 23.10 and later, rsyslog high precision) | `2026-10-21T08:00:01.104512+00:00`, `Oct 21 08:00:01` |
| `hostname` | string | `web-01` |
| `app_name` | string, the syslog tag | `sshd`, `sshd-session`, `sudo`, `su`, `useradd`, `CROND` |
| `proc_id` | string, when the tag has `[pid]` | `2101` |
| `message` | string | `Accepted publickey for alice from 192.0.2.10 port 52113 ssh2: ED25519 SHA256:...` |
| `priority`, `facility`, `severity` | number, only when the line starts with `<PRI>` (not in default rsyslog files) | `38`, `4`, `6` |

### Text lines: busybox `/var/log/messages` (`.messages` rules)

| Key | Type | Example |
| --- | --- | --- |
| `timestamp` | string `Mmm dd hh:mm:ss` | `Oct 21 08:00:01` |
| `hostname` | string | `edge-01` |
| `facility_name` | string | `auth`, `authpriv`, `kern`, `cron` |
| `severity_name` | string | `notice`, `info`, `warn` |
| `app_name` | string | `sshd`, `sudo`, `kernel`, `crond` |
| `proc_id` | string | `3101` |
| `message` | string | `Failed password for root from 203.0.113.70 port 41000 ssh2` |

### Journal entries (`.journald` rules, `linux-core.kernel`, `linux-core.timers`, `journald`)

The journal JSON subset of the contract. Which of `linux.auth`, `linux.kernel`, `linux.cron`
or `journald` it is comes from the rule; the shape is the same. A normaliser can read the
syslog shape and the journal shape of one `source_type` the same way with
`message = fields.message ?? fields.MESSAGE`, `program = fields.app_name ??
fields.SYSLOG_IDENTIFIER`, `pid = fields.proc_id ?? fields._PID`.

| Key | Type | Example |
| --- | --- | --- |
| `MESSAGE` | string | `Failed password for root from 203.0.113.50 port 40022 ssh2` |
| `SYSLOG_IDENTIFIER` | string | `sshd-session`, `sudo`, `kernel`, `CRON`, `systemd` |
| `_SYSTEMD_UNIT` | string | `ssh.service`, `session-7.scope`, `init.scope` |
| `_PID`, `_UID` | string (decimal) | `2240`, `0` |
| `PRIORITY` | string `0`-`7` | `6` |
| `SYSLOG_FACILITY` | string (decimal) | `4` auth, `10` authpriv, `9` cron, `0` kernel, `3` daemon |
| `_TRANSPORT` | string | `syslog`, `journal`, `kernel`, `stdout` |
| `_COMM`, `_EXE` | string | `sshd-session`, `/usr/lib/openssh/sshd-session` |

A field the journal holds several times becomes an array of strings.

### `linux.package`

| Key | Rules | Type | Example |
| --- | --- | --- | --- |
| `timestamp` | dpkg, dnf, yum, zypp | string as written | `2026-10-21 08:20:01`, `2026-10-21T08:30:02+0000`, `Oct 21 08:40:01` |
| `action` | dpkg, dnf, yum, zypp | string as written | dpkg `install` `upgrade` `remove` `purge`; dnf `Installed` `Upgrade` `Upgraded` `Downgrade` `Downgraded` `Erase` `Reinstall` `Reinstalled` `Obsolete` `Obsoleted`; yum `Installed` `Updated` `Erased` `Dep-Installed`; zypp `install` `remove` |
| `package` | dpkg, dnf, yum, zypp | string, the name | `tree`, `openssl-libs` |
| `version` | dpkg, dnf, yum, zypp | string: dpkg and zypp the new version; dnf `[epoch:]version-release`; yum `version-release` (missing for name-only `Erased:` lines) | `2.1.1-2ubuntu3.24.04.2`, `1:3.2.2-6.el9_5` |
| `old_version` | dpkg | string, for upgrade, remove, purge | `1.5.3-5ubuntu5` |
| `arch` | dpkg, dnf, yum, zypp | string | `amd64`, `x86_64`, `aarch64` |
| `epoch` | yum | string, when written | `1` |
| `level` | dnf | string | `SUBDEBUG` |
| `requested_by` | zypp, apt | string: zypp `user@host`; apt `user (uid)` | `root@web-01`, `alice (1000)` |
| `repository` | zypp | string, install only | `repo-sle-update` |
| `start_date`, `end_date` | apt | string `YYYY-MM-DD  hh:mm:ss` (two spaces, local time) | `2026-10-21  08:20:01` |
| `command_line` | apt | string | `apt-get install -y tree` |
| `install`, `reinstall`, `upgrade`, `downgrade`, `remove`, `purge` | apt | string: `name:arch (version)` comma-separated; upgrades `name:arch (old, new)`; `, automatic` marks dependencies | `libpam-modules:amd64 (1.5.3-5ubuntu5, 1.5.3-5ubuntu5.7)` |
| `error` | apt | string | `Sub-process /usr/bin/dpkg returned an error code (1)` |

Which manager wrote the event is the `rule_id` (`linux-core.dpkg`, ...) and `attrs.path`.

### `linux.login`: wtmp and btmp records

One event per record (`EMPTY` records are skipped). Decoded from glibc `struct utmp`
(x86_64 384 bytes with 32-bit times; aarch64 400 bytes with 64-bit times).

| Key | Type | Example |
| --- | --- | --- |
| `log` | string: the file name before the first `.` | `wtmp`, `btmp` |
| `type` | string | `USER_PROCESS` (login), `DEAD_PROCESS` (logout), `LOGIN_PROCESS` (btmp: failed login), `BOOT_TIME` (user `reboot`), `RUN_LVL` (user `runlevel` or `shutdown`), `NEW_TIME`/`OLD_TIME` (clock changed), `INIT_PROCESS`, `ACCOUNTING` |
| `type_code` | number 1-9 | `7` |
| `pid` | number | `2101` |
| `line` | string, terminal | `pts/0`, `tty1`, `ssh:notty` |
| `id` | string, inittab id (up to 4 characters, may hold spaces) | `ts/0` |
| `user` | string (for btmp the name tried, which may not exist) | `alice`, `admin` |
| `host` | string, remote host or kernel release for boot records | `192.0.2.10`, `6.8.0-45-generic` |
| `addr` | string, IPv4 or IPv6 | `203.0.113.50`, `2001:db8::25` |
| `session` | number | `3` |
| `exit_termination`, `exit_status` | number, when not 0 | `1`, `0` |
| `time` | string RFC 3339 UTC, the record time (also the event `ts`) | `2026-10-21T08:00:01.104512Z` |

### `linux.login`: lastlog summary

At most one event an hour, and only when `/var/log/lastlog` changed (the first one at start
unless the file is unchanged since the last summary sent). `fields.log` is `lastlog`.

| Key | Type | Example |
| --- | --- | --- |
| `log` | string | `lastlog` |
| `users_total` | number, users with a recorded login | `3` |
| `truncated` | bool, more than 1,000 users (the most recent 1,000 are listed) | `false` |
| `users` | array, most recent first, of `{uid: number, user?: string (from /etc/passwd), time: RFC 3339, line?: string, host?: string}` | `[{"uid":1000,"user":"alice","time":"2026-10-21T08:00:01.000000Z","line":"pts/0","host":"192.0.2.10"}]` |

### `linux.auditd`

`fields = {serial, node?, records: [...]}`, one event per audit event (all records with the
same `msg=audit(<time>:<serial>)`).

| Key | Type | Example |
| --- | --- | --- |
| `serial` | number | `4567` |
| `node` | string, when auditd writes `name_format` node names | `web-01` |
| `records` | array of objects, in log order (`EOE` is not included) | see below |

Each record object has `type` (`SYSCALL`, `EXECVE`, `PATH`, `CWD`, `PROCTITLE`, `SOCKADDR`,
`USER_LOGIN`, `USER_AUTH`, `USER_CMD`, `USER_START`, `USER_END`, `ADD_USER`, `DEL_USER`,
`ADD_GROUP`, `CRED_ACQ`, `CRED_DISP`, `CRED_REFR`, `ANOM_ABEND`, `ANOM_PROMISCUOUS`, `AVC`,
`USER_AVC`, `CONFIG_CHANGE`, `KERN_MODULE`, `DAEMON_START`, ...) and every field of the record
as a string, as auditd wrote it:

- Quoted values lose their quotes (`comm="cat"` becomes `"comm": "cat"`).
- Hex-encoded values are decoded: `proctitle` (arguments separated by spaces), EXECVE `a0`,
  `a1`, ... and chunks `a1[0]`, `a1[1]`, ... (with `a1_len`), and `acct`, `cmd` (USER_CMD),
  `comm`, `cwd`, `data`, `dir`, `exe`, `file`, `grp`, `key` (several keys joined with `,`),
  `name`, `new_group`, `ocomm`, `old_group`, `path`, `root_dir`, `vm`, `watch`. SYSCALL
  `a0`-`a3` are syscall arguments and stay hex.
- User-space records (`msg='op=... acct=... res=...'`) are flattened: the inner fields join
  the record (`op`, `acct`, `exe`, `hostname`, `addr`, `terminal`, `res`, `grantors`, `id`,
  `cmd`, `cwd`, ...). Outer fields win on a clash.
- With `log_format = ENRICHED` (the default on current auditd) the interpreted fields after
  the `0x1d` separator are added in upper case: `ARCH`, `SYSCALL`, `AUID`, `UID`, `GID`,
  `EUID`, `SUID`, `FSUID`, `EGID`, `SGID`, `FSGID`, `OUID`, `OGID`, `ID`, ...
- SELinux AVC text adds `seresult` (`denied`, `granted`) and `seperms` (`read,write`).

Example (`cat /etc/shadow` under sudo, abridged):

```json
{"serial":4567,"records":[
 {"type":"SYSCALL","syscall":"59","SYSCALL":"execve","success":"yes","exit":"0","auid":"1000","AUID":"alice",
  "uid":"0","UID":"root","pid":"2502","ppid":"2501","tty":"pts0","ses":"7","comm":"cat","exe":"/usr/bin/cat","key":"exec", ...},
 {"type":"EXECVE","argc":"2","a0":"cat","a1":"/etc/shadow"},
 {"type":"CWD","cwd":"/home/alice"},
 {"type":"PATH","item":"0","name":"/usr/bin/cat","nametype":"NORMAL","mode":"0100755", ...},
 {"type":"PROCTITLE","proctitle":"cat /etc/shadow"}]}
```

An event is finished by its `EOE` record, at once for single-record events (user-space,
`DAEMON_*`, `ANOM_ABEND`), or 2 seconds after its last record. At most 128 records and the
rule's `max_line_bytes` (128 KiB in the preset) of raw records are kept per event, and at most
256 events are open at once; beyond that `attrs.truncated` is set or the oldest event is sent
early.

### `file` (`linux-containers.k8s-audit`)

The Kubernetes audit event object as written (`json` parser): `kind`, `apiVersion`, `level`,
`auditID`, `stage`, `requestURI`, `verb`, `user`, `sourceIPs`, `userAgent`, `objectRef`,
`responseStatus`, `requestReceivedTimestamp`, `stageTimestamp`, `annotations`, ...

## Host metadata

Host identity is never in event lines: the server stamps it from the enrolled host record.
The heartbeat (every 60 seconds, `source_type` `agent.heartbeat`) carries what the server
attaches to the host's events, in addition to `hostname`, `os` and `os_version`
(`PRETTY_NAME`):

| Key | Type | Example |
| --- | --- | --- |
| `os_id` | string, os-release `ID` | `ubuntu` |
| `os_version_id` | string, os-release `VERSION_ID` | `24.04` |
| `kernel_version` | string, `/proc/sys/kernel/osrelease` | `6.8.0-45-generic` |
| `ips` | array of strings: the source addresses of the default IPv4 and IPv6 routes, found without sending a packet | `["192.0.2.10", "2001:db8::10"]` |

They are read at start and on every reload.

## Permissions

The packaged service runs as `wedgetail-agent` with the `adm` and `systemd-journal` groups
and no capabilities. That reads:

- the journal (`systemd-journal`): every `.journald`, kernel, timer, firewall and container
  rule;
- `/var/log/auth.log`, `/var/log/dpkg.log`, `/var/log/apt/history.log` on Debian and Ubuntu
  (group `adm`);
- `/var/log/wtmp`, `/var/log/lastlog`, `/var/log/dnf.rpm.log`, `/var/log/zypp/history`
  (world-readable on most distributions).

These need more, and are reported once in the agent log (`journalctl -u wedgetail-agent`) when
they cannot be opened:

| File | Why | Grant |
| --- | --- | --- |
| `/var/log/secure`, `/var/log/cron`, `/var/log/messages` (RHEL family) | `0600 root` | `CAP_DAC_READ_SEARCH` (below), or an rsyslog `$FileGroup adm` / `FileCreateMode` setting of your own |
| `/var/log/btmp` | `0600 root:utmp` (RHEL) or `0660 root:utmp` (Debian) | `CAP_DAC_READ_SEARCH`. Adding the agent to `utmp` also works on Debian but gives write access to wtmp and utmp, so it is not recommended |
| `/var/log/audit/audit.log` | `0600 root`, directory `0700` | `CAP_DAC_READ_SEARCH`, or `log_group = wedgetail-agent` (or `adm`) in `/etc/audit/auditd.conf` |
| `/var/log/kubernetes/audit/*.log` | usually `0600 root` | `CAP_DAC_READ_SEARCH` |

`CAP_DAC_READ_SEARCH` lets the agent read any file, which its path rules still confine (see
[Which files a rule may read](../rules.md#which-files-a-rule-may-read)). Grant it with a
drop-in, then restart:

```sh
sudo systemctl edit wedgetail-agent
# [Service]
# CapabilityBoundingSet=CAP_DAC_READ_SEARCH
# AmbientCapabilities=CAP_DAC_READ_SEARCH
sudo systemctl restart wedgetail-agent
```

The agent never changes system logging configuration, audit rules or file permissions
itself.

## Richer data: what to enable

- **auditd** with the recommended rule set
  [`presets/linux/audit.rules`](../../presets/linux/audit.rules) (based on the Neo23x0 auditd
  rules and the CIS Benchmarks): program execution, identity and sudoers changes, SSH
  configuration and `/root/.ssh`, cron and systemd unit changes, kernel module loads,
  `ptrace`, time changes and mounts. Installing it is your choice and is described at the top
  of the file. **The execve rules log every program started and can cost several percent of
  CPU on busy hosts**; try it on one host first.
- **rsyslog** is not needed: the journal variants collect the same authentication and cron
  messages. If you install it anyway the agent switches to the files at the next reload.
- **sshd `LogLevel VERBOSE`** adds the key fingerprint to every public key login and logs
  failed key attempts.
- **sudo I/O or `log_subcmds`** (sudo 1.9.8+) logs commands run from a sudo shell.
- **Persistent journal** (`Storage=persistent` in `journald.conf`) keeps entries over reboots
  so the agent can catch up after an outage longer than the volatile journal holds.
- **Kubernetes API server auditing** (`--audit-policy-file`, `--audit-log-path`) for
  `linux-containers.k8s-audit`.

## Fixtures and golden files

[`presets/linux/fixtures/`](../../presets/linux/fixtures) holds raw samples for every source:
`auth.log` (Ubuntu 24.04), `secure` and `cron` (RHEL 9), `messages` (Alpine busybox),
`journal.json` (`journalctl -o json` entries for every journal rule), `dpkg.log`,
`apt-history.log`, `dnf.rpm.log`, `yum.log`, `zypp-history`, `audit.log`, `k8s-audit.log`,
binary `wtmp` and `btmp` written by util-linux `utmpdump -r` on Ubuntu 24.04 x86_64 (and
`wtmp-aarch64`, `btmp-aarch64`; the text input is `*.utmpdump`), binary `lastlog` (and
`lastlog-aarch64`), checked with `lastlog(8)`, and `passwd`. All names and addresses are
fictional (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`).

`fixtures/golden/<rule id>.ndjson` holds the exact wire lines the agent sends for those
samples, produced by the real collectors and rule pipeline in
`crates/agent-core/tests/linux_presets.rs`. Two values are fixed so the files are stable:
`attrs.path` is the path on a real host, and the `ts` of text lines and the lastlog summary
(the time they were read) is `2026-10-21T08:00:00.000000Z`. Regenerate after an intended
change with `UPDATE_GOLDEN=1 cargo test -p agent-core --test linux_presets` and review the
diff.

## Not yet measured

Events per day on an idle and a busy host, CPU and memory with and without the execve audit
rules, and runs on real Ubuntu, Debian, RHEL, Amazon Linux and Alpine machines are still to
be done and will be added here.
