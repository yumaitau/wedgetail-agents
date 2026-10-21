# wedgetail_agent

Ansible role for the Wedgetail host agent on Linux: installs the `.deb` or `.rpm`, writes
`agent.toml` and `rules.d`, enrols the host once and runs the systemd service. It can also
remove the agent. Tested in CI on Ubuntu 24.04 (install from a release URL and from a file on
the controller, enrolment against a mock endpoint, idempotency, purge) and linted with
`ansible-lint` (production profile).

Supported: Debian and Ubuntu (apt), RHEL, Rocky, Alma and other RHEL-family hosts (dnf), on
x86_64 and aarch64, with systemd. Ansible 2.15 or later on the controller. Only
`ansible.builtin` modules are used.

## Getting the role

The role is in this repository at `ansible/roles/wedgetail_agent` (it is not on Ansible
Galaxy). Check out the release tag that matches the agent version you deploy, then either
copy the directory into your playbook's `roles/` or add the checkout's `ansible/roles` to
`roles_path` in `ansible.cfg`:

```ini
[defaults]
roles_path = roles:/path/to/wedgetail-agents/ansible/roles
```

## Example playbook

```yaml
- name: Wedgetail agent
  hosts: linux_agents
  become: true
  roles:
    - role: wedgetail_agent
      vars:
        wedgetail_agent_version: 0.1.0
        wedgetail_agent_endpoint: https://abcdefghijklmnopqrstuvwxyz012345.lambda-url.ap-southeast-2.on.aws/
        wedgetail_agent_presets: [auto]
        # From Ansible Vault (ansible-vault encrypt_string), never in plain text.
        wedgetail_agent_enrol_token: "{{ vault_wedgetail_enrol_token }}"
        wedgetail_agent_rules:
          - id: nginx-access
            type: file
            paths: [/var/log/nginx/*.log]
            exclude: ["*.gz"]
            parser: nginx_combined
            tags: {env: prod}
        wedgetail_agent_rules_d:
          app:
            - id: app-errors
              type: journald
              units: [app.service]
              priority_max: 3
```

Remove it (revoke the host in the console first if you purge, which deletes its credential):

```yaml
- name: Remove the Wedgetail agent
  hosts: retired
  become: true
  roles:
    - role: wedgetail_agent
      vars:
        wedgetail_agent_state: absent
        wedgetail_agent_purge: true
```

## What it does

1. **Package.** Works out the release file name for the host
   (`wedgetail-agent_<version>-1_amd64.deb`, `wedgetail-agent-<version>-1.x86_64.rpm`, ...),
   gets its SHA-256 from the release's `SHA256SUMS` (or `wedgetail_agent_sha256`), downloads
   it with that checksum, or copies `wedgetail_agent_package_src` from the controller, and
   checks the SHA-256 of the file on the host again. A mismatch stops the role before
   anything is installed. When `cosign` is on the host (or
   `wedgetail_agent_cosign_verify: always`), it also runs `cosign verify-blob` with the
   release's `.sigstore.json` bundle and the release workflow's identity. The packages are
   not GPG-signed, so dnf's GPG check is turned off for this one local file; SHA256SUMS and
   cosign take its place.
2. **Configuration.** Writes `/etc/wedgetail-agent/agent.toml` (root:wedgetail-agent, 0640)
   from the variables below, and one `rules.d/<name>.toml` per entry in
   `wedgetail_agent_rules_d`, then runs `wedgetail-agent check-config`. A change reloads the
   service (SIGHUP; an invalid file is refused by the agent and the running one kept).
3. **Enrolment.** Only when `wedgetail_agent_enrol_token` is set and
   `/var/lib/wedgetail-agent/enrolment.json` does not exist (or
   `wedgetail_agent_enrol_force` is true). Runs `wedgetail-agent enrol --token-stdin` with the
   token on standard input.
4. **Service.** Enables and starts `wedgetail-agent`.

Running it again changes nothing (CI checks that a second run reports `changed=0`).

## The enrolment token

- It is passed to the agent on **standard input**, never in its arguments (visible to every
  user in the process list) or its environment.
- The task has `no_log: true`: the token is not shown in the output, in callbacks or in the
  module's own log on the host's journal, and a failed enrol shows only the agent's error
  (which never contains the token). The role's argument spec marks it `no_log` too.
- The task turns on **pipelining** (`wedgetail_agent_enrol_pipelining`, default true), so its
  module arguments go to the host over the connection instead of a temporary module file in
  `~/.ansible/tmp`. Pipelining with `become` needs sudo without `requiretty`; if you must
  turn it off, the token sits in that temporary file (readable only by the connecting and
  become users) until the task ends.
- Keep the token in Ansible Vault or a secrets lookup. Use one with a short expiry and a host
  limit, and create a new one for the next rollout.
- A host is enrolled once. Re-enrol (after a revocation, or to move it to another group) with
  `-e wedgetail_agent_enrol_force=true` for one run, with a new token.
- Don't run the role with a token while building a golden image: every clone would share the
  enrolment. Install and configure in the image (`wedgetail_agent_enrol_token: ""`), and enrol
  at first boot.

## Variables

Defaults are in `defaults/main.yml`; `meta/argument_specs.yml` is checked at the start of
the role.

| Variable | Default | Meaning |
| --- | --- | --- |
| `wedgetail_agent_state` | `present` | `present` or `absent` |
| `wedgetail_agent_purge` | `false` | With `absent`: also delete `/etc/wedgetail-agent`, the state directory (credential, unsent events) and the `wedgetail-agent` user and group |
| `wedgetail_agent_version` | `0.1.0` | Release to install |
| `wedgetail_agent_package_revision` | `1` | Package revision in the file name |
| `wedgetail_agent_release_url` | `https://github.com/yumaitau/wedgetail-agents/releases/download/v{{ wedgetail_agent_version }}` | Where the packages, `SHA256SUMS` and bundles are (a mirror for offline hosts) |
| `wedgetail_agent_package_src` | `""` | A `.deb`/`.rpm` on the controller to copy instead of downloading |
| `wedgetail_agent_sha256sums_src` | `""` | `SHA256SUMS` on the controller for that file (default: next to it) |
| `wedgetail_agent_sha256` | `""` | The package's SHA-256, instead of reading `SHA256SUMS` |
| `wedgetail_agent_download_dir` | `/var/cache/wedgetail-agent-install` | Where the package is kept on the host (root, 0700) |
| `wedgetail_agent_cosign_verify` | `auto` | `auto` (when cosign is on the host), `always` or `never` |
| `wedgetail_agent_cosign_bundle_src` | `""` | Bundle on the controller for `wedgetail_agent_package_src` (default `<file>.sigstore.json`) |
| `wedgetail_agent_cosign_identity_regexp` | `^https://github.com/yumaitau/wedgetail-agents/` | Signing identity |
| `wedgetail_agent_cosign_oidc_issuer` | `https://token.actions.githubusercontent.com` | Signing certificate issuer |
| `wedgetail_agent_manage_config` | `true` | Write `agent.toml` and `rules.d` |
| `wedgetail_agent_config_template` | `agent.toml.j2` | Your own template for `agent.toml` |
| `wedgetail_agent_endpoint` | `""` | Ingest URL (https); required with the role's template |
| `wedgetail_agent_presets` | `[auto]` | `auto`, a list of preset ids, or `[]` |
| `wedgetail_agent_disable_rules` | `[]` | Rule ids to switch off |
| `wedgetail_agent_buffer_max_mb` | `256` | Disk buffer cap in MiB |
| `wedgetail_agent_settings` | `{}` | Other `[agent]` settings (`max_open_files`, `state_dir`) |
| `wedgetail_agent_rules` | `[]` | Rules written as `[[rule]]` in `agent.toml` |
| `wedgetail_agent_config_extra` | `""` | TOML text added after `[agent]` (`[limits]`, `[heartbeat]`) |
| `wedgetail_agent_rules_d` | `{}` | `rules.d` files: name (without `.toml`) to a list of rules or TOML text |
| `wedgetail_agent_rules_d_exclusive` | `false` | Delete `rules.d/*.toml` files not in `wedgetail_agent_rules_d` |
| `wedgetail_agent_enrol_token` | `""` | Enrolment token; empty skips enrolment |
| `wedgetail_agent_enrol_force` | `false` | Enrol again over an existing enrolment |
| `wedgetail_agent_enrol_pipelining` | `true` | Pipelining for the enrol task (see above) |
| `wedgetail_agent_state_dir` | `/var/lib/wedgetail-agent` | Where `enrolment.json` is looked for |
| `wedgetail_agent_service_enabled` | `true` | Start at boot |
| `wedgetail_agent_service_state` | `started` | `started` or `stopped` |

Rules are written as YAML and rendered as TOML: strings, numbers, booleans and lists as they
are, mappings as inline tables (`tags = { env = "prod" }`). Every rule field is in
[docs/rules.md](../../../docs/rules.md). Reading root-only logs (auditd, btmp) needs a
systemd drop-in with `CAP_DAC_READ_SEARCH`; add it with your own `ansible.builtin.copy` task
to `/etc/systemd/system/wedgetail-agent.service.d/`.

## Tests

`.github/scripts/ansible-e2e.sh` (the `ansible` CI job) runs `tests/test.yml` against the
runner itself with the package built in the same workflow: a package with the wrong SHA-256
is refused, then install from a local "release" URL, enrolment against the mock ingest
endpoint (`.github/scripts/mock-ingest.py`), `wedgetail-agent status` and the service
checked, two more runs with `changed=0` (release URL and controller file), then
`state: absent` with purge, twice. The RHEL (dnf) path and cosign verification are not run
in CI.
