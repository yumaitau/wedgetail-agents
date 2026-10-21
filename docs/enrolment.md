# Enrolment, host credentials and rotation

How a host joins your Wedgetail install, where its credential is kept, how the credential
rotates and what happens when it is revoked. Step-by-step install guides for each OS are in
the agent guide of your Wedgetail documentation.

## Overview

1. An administrator creates an **enrolment token** in the Wedgetail console (Sources, Host
   agents). It is scoped to a host group, expires (24 hours by default, at most 30 days), may
   have a use limit, and is shown once. Shape: `wge_<12 [a-z0-9]>_<43 base64url>`.
2. On the host, `wedgetail-agent enrol` sends the token and a few facts about the host to
   `POST <endpoint>/v1/agent/enrol` and receives a **host credential**
   (`wgh_<12 [a-z0-9]>_<43 base64url>`) and a host id.
3. The agent sends events with that credential (`Authorization: Bearer wgh_...`). Every host
   has its own credential, so one host can be revoked without touching the others, and the
   server stamps each event with the host's identity from the credential (it never trusts host
   fields inside events).
4. The agent rotates its credential every `rotate_after_days` (30 by default).

The token is only used once by the agent and is not stored.

## Enrolling a host

Run as root (Linux, macOS) or as an elevated administrator (Windows), after setting
`endpoint` in `agent.toml`:

```sh
# The token on standard input (from a file, a secrets manager or a pipe):
sudo wedgetail-agent enrol < token.txt

# Or in the environment:
sudo WEDGETAIL_ENROL_TOKEN="$TOKEN" wedgetail-agent enrol

# Or typed at a prompt that does not echo:
sudo wedgetail-agent enrol
```

```powershell
# Windows, elevated PowerShell
Get-Content token.txt | & "$env:ProgramFiles\Wedgetail Agent\wedgetail-agent.exe" enrol
```

For fleets, the Ansible role ([ansible/roles/wedgetail_agent](../ansible/roles/wedgetail_agent/README.md))
and the MSI's `ENROLTOKEN` property ([packaging/windows/README.md](../packaging/windows/README.md))
run the same command and give it the token on standard input; both skip a host that is
already enrolled.

The token is **never accepted on the command line**: arguments are visible to every user in
the process list and are kept in shell history. `--token`, `--token=...` and any argument
that looks like a token or credential are refused with an error that does not repeat it.

Where the token comes from, in order:

1. standard input, with `--token-stdin` (useful when standard input is a terminal);
2. `WEDGETAIL_ENROL_TOKEN`, if set and not empty;
3. standard input, when it is not a terminal (a pipe or a file);
4. a prompt on the terminal that does not echo.

The token's shape is checked locally before anything is sent.

Options:

| Option | Meaning |
| --- | --- |
| `--endpoint <url>` | Enrol with this ingest URL instead of the `endpoint` in `agent.toml` (https only). The agent always sends to the `endpoint` in `agent.toml`, so keep the two the same; enrol warns if they differ. |
| `--token-stdin` | Read the token from standard input even when it is a terminal. |
| `--force` | Enrol again over an existing enrolment (see "Re-enrolling"). |
| `--config <path>` | `agent.toml` location. |

Enrol stops before using the token if the host is already enrolled (without `--force`), if
the state directory is not writable (not root or administrator, or the agent is not
installed) or if the machine id cannot be read.

A running agent picks up the new credential on its next attempt to send (within a minute);
there is no need to restart it. Events collected before enrolment are kept in the disk buffer
and sent once the host is enrolled.

### What enrol sends

```http
POST /v1/agent/enrol
Authorization: Bearer wge_...
Content-Type: application/json

{"hostname":"web-01","os":"linux","os_version":"Ubuntu 24.04.1 LTS","arch":"x86_64",
 "machine_id":"4c4c4544004d3510804bc4c04f4e4a32","agent_version":"0.1.0"}
```

- `os` is `linux`, `windows` or `macos`; `arch` is the Rust architecture name (`x86_64`,
  `aarch64`).
- `machine_id`, in lower case: Linux `/etc/machine-id` (or `/var/lib/dbus/machine-id`),
  32 hex digits; Windows `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`; macOS
  `IOPlatformUUID` from `ioreg -rd1 -c IOPlatformExpertDevice`. Both GUIDs are sent as
  `8-4-4-4-12` hex. The server uses it to flag cloned images: a second host enrolling with the
  same machine id is registered as a new host marked as a duplicate, never merged.

A successful reply is `200` with
`{"host_id":"...","credential":"wgh_...","rotate_after_days":30}`. A missing or zero
`rotate_after_days` means 30; values over 365 are capped at 365. A reply without a
well-formed `host_id` (1 to 64 of `[A-Za-z0-9_-]`) and credential is treated as an error and
nothing is stored.

| Reply | What enrol says |
| --- | --- |
| `401` | The token was not accepted. The server gives no reason (unknown, expired, revoked and used-up tokens look the same); create a new token. |
| `400` | The request was rejected, with the server's `error` text. |
| `404`, `405` | The endpoint does not accept enrolment: check the URL. |
| `408`, `425`, `429`, `5xx` | The server is busy; try again (after `Retry-After` if given). |
| TLS failure | Names the endpoint; certificates are always verified (check the name and the CA, including any TLS-inspecting proxy). |
| Network failure | `cannot reach <endpoint>` with the cause (DNS, refused, timeout). |

## Where the credential is kept

| OS | Store | Notes |
| --- | --- | --- |
| Linux | `/var/lib/wedgetail-agent/credential` | Mode `0600`, owned by the `wedgetail-agent` service account |
| Windows | `%ProgramData%\Wedgetail\state\credential.dpapi` | DPAPI, machine scope; file ACL SYSTEM, Administrators, LocalService |
| macOS | System keychain, service `au.com.yumait.wedgetail-agent`, account `host-credential` | The agent runs as root |

Non-secret facts (host id, endpoint, enrolment time, when the credential was issued, the
rotation period) are kept in `enrolment.json` in the state directory, so `status` can show
them without touching the credential.

**Linux (and other Unix systems).** The file is written atomically: a new temporary file is
created with mode `0600` (it is never wider, not even briefly), fsynced, given to the owner of
the state directory (so a credential written by root during `enrol` is readable by the
service account), then renamed over the old one. The service runs as `wedgetail-agent`, which
has to read and rotate the credential, so the file belongs to that account rather than to
root; root can read it too. Every read refuses a credential that is a symlink, is readable or
writable by group or others, or is owned by anyone other than root or the owner of the state
directory. The state directory is `0750` and the systemd unit sets `UMask=0077`.

**Windows.** The credential is encrypted with `CryptProtectData` in machine scope
(`CRYPTPROTECT_LOCAL_MACHINE`), so both the service (LocalService) and an administrator
running `enrol` can decrypt it, and a copy taken off the machine (a disk image or backup) is
useless. Because any local account could decrypt a machine-scope blob, the file's ACL is
what keeps it private: it is created empty, given a protected DACL that allows only SYSTEM,
Administrators and LocalService (nothing inherited), then written and renamed into place.

**macOS.** The credential is a generic password item in `/Library/Keychains/System.keychain`,
which only root can change; the agent runs as root (see the README). Keychain prompts are
disabled for the agent, which has no one to answer them. The item's access list trusts the
build that created it. Until releases are signed with a stable Apple Developer ID, an upgraded
(differently signed) binary may be refused access to an item made by the previous build:
`status` then shows the credential as unreadable. Enrol again with `--force` (the agent
deletes and recreates the item), or delete it first with
`sudo security delete-generic-password -s au.com.yumait.wedgetail-agent -a host-credential /Library/Keychains/System.keychain`.

There is no file fallback on Windows or macOS: if the OS store is unavailable, the agent
reports the error in `status` and keeps buffering.

## How the agent uses the credential

The agent reads the credential from the store before every request, so a new credential
(from `enrol` or rotation) is used from the next request without a restart. If there is no
credential, events keep buffering on disk (up to the buffer cap) and `status` shows
`not enrolled`.

Neither the token nor the credential is ever logged or printed: their types redact
themselves in `Debug` and `Display` output, error messages never repeat them, and the HTTP
client's errors never include request headers.

## Rotation

A background thread in the agent checks the credential's age every hour (and at start).
When it is `rotate_after_days` old it calls:

```http
POST /v1/agent/rotate
Authorization: Bearer wgh_<current credential>
Content-Length: 0
```

and expects `200` with `{"credential":"wgh_...","previous_valid_until":"<RFC 3339>"}`. The new
credential is stored atomically (readers see the old one or the new one, never neither), then
`credential_issued_at` in `enrolment.json` is updated. The next request uses the new
credential. The server keeps the previous credential valid for 24 hours, so a batch that was
already on its way with the old credential still lands: rotation never drops events.

If rotation fails, the current credential stays in use and the agent tries again with
backoff (1 minute doubling to 1 hour, with jitter; `Retry-After` honoured):

- `401`: the current credential was not accepted (the host was revoked); logged as an error.
- `408`, `425`, `429`, `5xx`, network and TLS errors: retried.
- A malformed reply: nothing is stored; retried.
- The new credential cannot be stored: the old one keeps working during the overlap, and the
  next attempt rotates again with the old one.

## Revocation

Revoking a host in the console takes effect within 60 seconds. From then on the server
answers `401 {"error":"Missing or invalid credential."}`. The agent never drops events on a
`401`: it keeps them in the disk buffer and retries with backoff (1 second doubling to
5 minutes, with jitter), so a revoked host does not flood the endpoint, and the backlog is
sent if the host is enrolled again. `status` shows the last error (`HTTP 401: credential
rejected`).

## Re-enrolling

`wedgetail-agent enrol --force` replaces the stored credential and `enrolment.json` with a
new enrolment. The server registers a new host; revoke the old one in the console if it is
still active. Use it after a revocation, to move a host to another group or install, or after
an unsigned upgrade on macOS (above).

## Transport security

Every request (enrol, rotate, events) uses the same HTTP client:

- HTTPS only; `http://` endpoints are refused when the config is loaded and by the client.
  There is no option to turn this off. Plain HTTP exists only inside the unit tests' own test
  server, compiled into test builds only.
- rustls with the ring provider, so TLS 1.2 and 1.3 only (older versions are not
  implemented). No OpenSSL.
- Certificates are verified by the operating system's verifier (`rustls-platform-verifier`),
  always. There is no "insecure" flag.
- Redirects are not followed; connect timeout 15 seconds, whole-request timeout 120 seconds.

## status

`wedgetail-agent status` starts with the enrolment, without secrets:

```text
enrolment:   host h0st00000001 with https://ingest.example.com (since 2026-10-21T08:00:00Z)
credential:  stored in file /var/lib/wedgetail-agent/credential
rotation:    issued 2026-10-21T08:00:00Z (3 days old), next rotation 2026-11-20T08:00:00Z
```

`status --json` adds the same facts as an `enrolment` object (`enrolled`, `host_id`,
`endpoint`, `enrolled_at`, `credential_issued_at`, `credential_age_days`,
`rotate_after_days`, `next_rotation`, `credential` = `stored`, `missing` or
`unreadable: ...`, and `credential_store`).

## Removing a host

Revoke the host in the console, then uninstall. Purging removes the credential: on Linux
`dpkg --purge` deletes `/var/lib/wedgetail-agent`; on macOS
`sudo packaging/macos/uninstall.sh --purge` deletes the state directory and the keychain item.
On Windows the state directory (including `credential.dpapi`) is kept after uninstalling;
delete `%ProgramData%\Wedgetail\state` to remove it.
