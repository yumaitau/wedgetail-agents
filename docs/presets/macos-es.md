# `macos-es`: Endpoint Security events (phase 2, not built)

Status: **entitlement not yet applied for.** Nothing in this release reads Endpoint Security
(ES). This page is the plan, so the work can start once Apple grants the entitlement.

## Why ES

The unified log (`macos-core`) and the OpenBSM trail (`macos-audit`) are what an ordinary
signed daemon can read. Apple deprecated OpenBSM in macOS 11, and unified log messages are
written for Apple's own debugging: their wording changes between releases and personal data
in them is often `<private>`. The Endpoint Security framework is Apple's supported interface
for security tools. It delivers structured, typed events for process execution, logins,
privilege changes and persistence, with the full process, code signing and user context of
each, and it is what EDR products use.

## Events (notify only)

The extension subscribes to these `ES_EVENT_TYPE_NOTIFY_*` events and nothing else:

| Event | What it shows | macOS |
| --- | --- | --- |
| `NOTIFY_EXEC` | every process start: path, arguments, code signing (team id, signing id, cdhash, platform binary), parent and responsible process | 10.15 |
| `NOTIFY_FORK`, `NOTIFY_EXIT` | process tree and lifetime | 10.15 |
| `NOTIFY_OPENSSH_LOGIN`, `NOTIFY_OPENSSH_LOGOUT` | SSH logins (success and failure), user, source address | 13 |
| `NOTIFY_LW_SESSION_LOGIN`, `_LOGOUT`, `_LOCK`, `_UNLOCK` | console login, logout, screen lock and unlock | 13 |
| `NOTIFY_SCREENSHARING_ATTACH`, `_DETACH` | Screen Sharing sessions, viewer address, authentication type | 13 |
| `NOTIFY_SUDO`, `NOTIFY_SU` | privilege use, success and failure, command | 14 |
| `NOTIFY_AUTHENTICATION` | password, Touch ID, token and auto-unlock authentications | 13 |
| `NOTIFY_BTM_LAUNCH_ITEM_ADD`, `_REMOVE` | login items, launch agents and daemons added or removed | 13 |
| `NOTIFY_XP_MALWARE_DETECTED`, `_REMEDIATED` | XProtect detections | 13 |
| `NOTIFY_PROFILE_ADD`, `_REMOVE` | configuration profiles installed or removed | 14 |
| `NOTIFY_TCC_MODIFY` | privacy (TCC) permission granted, changed or revoked | 15 |

`AUTH_EXEC` and every other `AUTH_*` event are **out of scope**: the agent never blocks or
delays anything on the host. Subscribing to `NOTIFY_EXEC` instead of `AUTH_EXEC` also means a
slow or stuck extension cannot hang process launches, and ES cannot kill the client for
missing an authorisation deadline.

Each event becomes one wire line with `source_type = "macos.es"` and `fields` taken from the
`es_message_t` (event type, time, process and target process with code signing details,
event-specific data). The schema is designed when the extension is built; it will follow the
names Apple uses in `EndpointSecurity/ESMessage.h`, in snake case.

## Design

```text
+--------------------------------------+        XPC (Mach service,        +---------------------------+
| Wedgetail ES system extension        |  audit-token checked, one way)   | wedgetail-agent daemon    |
| au.com.yumait.wedgetail-agent.es     | -------------------------------> | (root, launchd)           |
| - es_new_client, notify events only  |   batches of encoded events      | rule pipeline, buffer,    |
| - mutes the agent and itself         |                                  | shipper (unchanged)       |
| - no network, no files               |                                  |                           |
+--------------------------------------+                                  +---------------------------+
          ^ installed and approved through a host app bundle + MDM (system extension policy)
```

- **A separate, signed system extension**, not code inside the agent binary. The ES client
  entitlement is only granted to system extensions approved by the user or by MDM, and keeping
  ES in its own small process keeps the agent's privileges unchanged and the extension's
  attack surface minimal. The extension is written in Swift or C against the
  `EndpointSecurity` framework (the only supported API; Rust FFI adds risk without benefit
  here) and does three things only: subscribe, encode, forward.
- **Packaging.** System extensions live inside an app bundle
  (`/Applications/Wedgetail Agent.app/Contents/Library/SystemExtensions/...`), are activated
  with `OSSystemExtensionRequest`, and are approved by MDM with a System Extension policy
  (`com.apple.system-extension-policy`, team id and bundle id) plus a PPPC payload granting the
  extension Full Disk Access (`SystemPolicyAllFiles`), which ES requires. The `.pkg` gains the
  app bundle; the agent binary and launchd daemon stay as they are.
- **Transport.** The extension forwards events to the agent over XPC to a Mach service the
  agent's launchd daemon publishes. The agent checks the peer's audit token and code signing
  requirement (team id and extension bundle id) before accepting events, and the extension
  checks the agent the same way. The channel is one way: the agent sends nothing to the
  extension but acknowledgements, so there is still no remote command path.
- **Back pressure.** ES events are not persisted by the system. The extension keeps a bounded
  in-memory queue; when the agent is down or slow it drops the oldest events and reports the
  count, which the agent adds to the heartbeat (`dropped.es_queue_full`).
- **Volume.** `NOTIFY_EXEC`/`FORK`/`EXIT` are the busy events (thousands per minute on a
  developer Mac). The extension uses `es_mute_process` for itself and the agent, and supports
  muting by path prefix and team id from the agent's rule configuration
  (`type = "macos_es"`, `events = [...]`, `mute_paths = [...]`). The low-volume events are on
  by default; process events are opt-in within the preset.
- **No kernel extension.** ES is a user space framework; nothing here loads kernel code.
- **Signing.** Developer ID Application certificate, hardened runtime, notarised and stapled,
  like the agent. The ES entitlement is tied to the Developer ID team and provisioning
  profile, so the extension cannot be built by third parties with the entitlement; the public
  repository builds it without the entitlement for review and testing.

## Entitlement application plan

1. Prerequisites: Apple Developer Program membership for Yuma IT (organisation account,
   D-U-N-S number) and a Developer ID Application certificate. Both are also needed for
   signing and notarising the agent itself (tracked separately).
2. Apply for `com.apple.developer.endpoint-security.client` through Apple's request form for
   Endpoint Security (developer.apple.com, "Request an Endpoint Security entitlement"),
   describing: a security monitoring product for organisations, notify events only (no
   `AUTH_*`), events listed above, deployed by MDM to managed Macs, data sent to the
   customer's own Wedgetail installation. Apple reviews these requests manually; the time
   it takes is not published.
3. After approval: create an App ID with the entitlement and a Developer ID provisioning
   profile for the extension; add it to the signing pipeline next to the agent.
4. Build the extension, CI on `macos-latest` without the entitlement (unit tests of the
   encoder against recorded `es_message_t` fixtures), then signed builds tested on a managed
   test Mac (macOS 14, 15 and current) enrolled in an MDM that pushes the System Extension and
   PPPC profiles.
5. Record in issue yumaitau/wedgetail#244 when the request was sent and Apple's answer, and
   change the status at the top of this page.

Until then, `macos-core` and `macos-audit` are the macOS presets; the PPPC sample in
[`packaging/macos/wedgetail-agent-pppc.mobileconfig`](../../packaging/macos/wedgetail-agent-pppc.mobileconfig)
already grants the agent the Full Disk Access it needs for them.
