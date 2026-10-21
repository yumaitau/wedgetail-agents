# wedgetail-agent

A small host agent that collects high-value security logs on Linux, Windows and macOS and
ships them to your own Wedgetail install over HTTPS. Setup, enrolment and the ingest API are
described in the agent guide of your Wedgetail documentation.

It is a collect-and-ship agent only. It does:

- tail log files (rotation and truncation aware), follow the systemd journal, subscribe to
  Windows Event Log channels and stream the macOS unified log;
- filter, sample, rate-limit, redact and parse every event per rule **before** it is written
  to disk;
- buffer events durably on disk (bounded, 256 MiB by default) so outages and restarts lose
  nothing until the buffer is full, and count what it drops when it is;
- batch events as gzip NDJSON within the ingest limits (1 MiB compressed, 5,000 records,
  120 requests a minute), back off with jitter and honour `429`/`503` `Retry-After`;
- send a heartbeat every 60 seconds with its version, buffer depth, drop counts and collector
  health.

It does not:

- listen on any port, accept remote commands, run shell commands or update itself;
- send anything anywhere except the endpoint you configure;
- use OpenSSL: TLS is [rustls](https://github.com/rustls/rustls) (TLS 1.2 and 1.3) with the
  operating system's certificate verifier, and plain `http://` endpoints are refused.

> Status: early. This release has the runtime, collectors, packaging, enrolment with per-host
> credentials, the rule schema (version 1) and the Linux presets
> ([docs/presets/linux.md](docs/presets/linux.md)). The Windows and macOS presets are coming in
> the next releases.

## Install

Packages are attached to each [release](https://github.com/yumaitau/wedgetail-agents/releases)
with `SHA256SUMS`, a CycloneDX SBOM and Sigstore signatures (see "Verifying a release").

| OS | Package | Service |
| --- | --- | --- |
| Debian, Ubuntu | `wedgetail-agent_<v>_<arch>.deb` | systemd `wedgetail-agent`, user `wedgetail-agent` |
| RHEL, Rocky, Alma | `wedgetail-agent-<v>.<arch>.rpm` | systemd `wedgetail-agent`, user `wedgetail-agent` |
| Windows | `wedgetail-agent-<v>-x86_64.msi` | `WedgetailAgent`, `NT AUTHORITY\LocalService` |
| macOS | `wedgetail-agent-<v>-universal.pkg` | launchd `au.com.yumait.wedgetail-agent`, root (see below) |

Linux builds are static (musl) for x86_64 and aarch64. After installing, set `endpoint` in the
config file, enrol the host with a token from the Wedgetail console and start the service; a
fresh install does not start until it is configured.

```sh
sudoedit /etc/wedgetail-agent/agent.toml
sudo wedgetail-agent check-config
sudo wedgetail-agent enrol < token.txt     # or WEDGETAIL_ENROL_TOKEN, or the prompt
sudo systemctl enable --now wedgetail-agent
sudo wedgetail-agent status
```

The enrolment token is never accepted on the command line. See
[docs/enrolment.md](docs/enrolment.md) for enrolment, where the host credential is stored on
each OS, rotation and revocation.

## Configuration

| | Config | State (buffer, checkpoints, status, enrolment; the credential on Linux and Windows) |
| --- | --- | --- |
| Linux | `/etc/wedgetail-agent/agent.toml`, `rules.d/*.toml` | `/var/lib/wedgetail-agent/` |
| Windows | `%ProgramData%\Wedgetail\agent.toml`, `rules.d\*.toml` | `%ProgramData%\Wedgetail\state\` |
| macOS | `/Library/Application Support/Wedgetail/agent.toml`, `rules.d/*.toml` | `/Library/Application Support/Wedgetail/state/` |

**[docs/rules.md](docs/rules.md)** documents every setting and rule field with examples:
paths and globs, multiline, parsers, include/exclude matching, redaction, sampling, rate
limits, presets, and which files a rule may read. A JSON Schema for editors is in
[`schema/rules.v1.json`](schema/rules.v1.json). For example:

```toml
schema_version = 1

[agent]
endpoint = "https://ingest.example.com"
presets = ["auto"]

[[rule]]
id = "nginx-access"
type = "file"            # file | journald | wineventlog | macos_unified
paths = ["/var/log/nginx/*.log"]
exclude = ["*.gz"]
parser = "nginx_combined"
source_label = "web/nginx"
tags = { env = "prod" }
redact = [{ pattern = 'password=\S+', replace = "password=[REDACTED]" }]
rate_limit = { events_per_second = 500, burst = 2000 }
```

Unknown keys are errors, so `wedgetail-agent check-config` catches typos; it prints every
problem as `file:line: message` and exits non-zero. Reload with `systemctl reload
wedgetail-agent` (SIGHUP), `sudo launchctl kill HUP system/au.com.yumait.wedgetail-agent` or
`sc.exe control WedgetailAgent paramchange`; an invalid configuration is reported and the
running one kept.

## Resource use

Targets: under 2% of one CPU on average and under 50 MB RSS in steady state on an idle host.
The systemd unit sets ceilings (`CPUQuota=25%`, `MemoryMax=256M`) that you can change with
`systemctl edit wedgetail-agent`.

Measured so far (one machine, not a fleet): on an Apple M3 Max running macOS 26.6, a release
build with a file rule and a unified log rule, not enrolled (so no network traffic), used
0.12 s of CPU over 300 s idle (about 0.04%) with 7.5 MB RSS, plus 4.9 MB for the `log stream`
child process. Linux and Windows figures on real hosts are still to be measured.

## Security model

- **Least privilege.** Linux: a dedicated `wedgetail-agent` user in `adm` and `systemd-journal`
  only, no capabilities, a strict systemd sandbox (`ProtectSystem=strict`, `NoNewPrivileges`,
  system call filter); reading auditd logs needs `CAP_DAC_READ_SEARCH`, which you opt into with
  a drop-in. Windows: `LocalService` in the "Event Log Readers" group, which covers the
  Security channel too while it keeps its default access list
  ([docs/presets/windows.md](docs/presets/windows.md#rights-the-agent-needs)). macOS: runs as root because `log stream`
  refuses non-admin users, and an admin service account would also be able to use sudo.
- **No inbound surface.** No listener, no remote commands, no shell, no self-update. Updates
  come from your OS package manager or a signed release.
- **Secrets stay off disk.** Rule redaction runs before the disk buffer. Rules cannot read
  the agent's own state or configuration directories, and symlinks out of a rule's directory
  are refused.
- **Bounded work.** Rule regular expressions run in linear time with capped sizes, lines are
  capped, and all file rules share a cap on open files.
- **Per-host credentials.** Each host enrols once with a short-lived token (read from standard
  input, an environment variable or a no-echo prompt, never from arguments) and gets its own
  credential, which rotates automatically (30 days by default) and can be revoked alone. It is
  stored in a `0600` file owned by the service account on Linux, with DPAPI (machine scope)
  in a file only SYSTEM, Administrators and LocalService can read on Windows, and in the
  System keychain on macOS. Tokens and credentials are never logged or printed. See
  [docs/enrolment.md](docs/enrolment.md).
- **Transport.** HTTPS only (TLS 1.2 and 1.3), rustls with the OS certificate verifier and no
  way to turn verification off, redirects not followed. The server stamps host identity from
  the credential and never trusts host fields in events.
- **Durability.** Buffer writes are fsynced; each batch has a stable id that is reused after a
  crash so the server can drop the repeat. At most the unacknowledged batch is resent.
- **Unsafe code** is forbidden except in the small Windows FFI modules
  (`crates/agent-collectors/src/os/windows`, `crates/agent-cli/src/os/windows`: event log,
  service entry point, DPAPI and file ACLs), each with `SAFETY` notes.

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Building

Rust 1.95 (pinned in `rust-toolchain.toml`).

```sh
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

Static Linux build: `rustup target add x86_64-unknown-linux-musl`, install `musl-tools`, then
`cargo build --release --target x86_64-unknown-linux-musl`. Packages: `cargo deb -p agent-cli`,
`cargo generate-rpm -p crates/agent-cli`, `packaging/macos/build-pkg.sh`, and
`wix build packaging/windows/wedgetail-agent.wxs` (see the CI workflow for exact commands).

## Layout

```text
crates/agent-config      agent.toml + rules.d + presets loading and validation, parsers, multiline
crates/agent-collectors  Collector trait; file tail, journald, Windows Event Log, macOS unified log
crates/agent-core        rule pipeline (filter, sample, rate limit, redact, parse), disk buffer,
                         batching, shipper, heartbeat, enrolment client, credential rotation,
                         Linux credential file
crates/agent-cli         the wedgetail-agent binary, enrol command, Windows service glue,
                         DPAPI (Windows) and System keychain (macOS) credential stores
docs/                    enrolment.md: enrolment, credential storage, rotation, revocation;
                         rules.md: configuration and rule reference
packaging/               systemd unit, launchd plist, WiX source, deb/rpm scripts, pkg builder
schema/rules.v1.json     JSON Schema for configuration files (generated, checked in CI)
```

## Verifying a release

```sh
sha256sum -c SHA256SUMS --ignore-missing
cosign verify-blob --bundle <file>.sigstore.json \
  --certificate-identity-regexp '^https://github.com/yumaitau/wedgetail-agents/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>
```

Authenticode signing of the Windows binaries and Apple Developer ID signing and notarisation
of the macOS package are wired into the release workflow and switch on once the certificates
are available.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
