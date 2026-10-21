#!/usr/bin/env bash
# End-to-end test of the wedgetail_agent Ansible role, for CI only (ubuntu-24.04 runner,
# systemd, passwordless sudo). Never run it on a real host: it trusts a CI-only root
# certificate and installs and purges the agent.
#
#   .github/scripts/ansible-e2e.sh <dir with the .deb>
#
# 1. A mock ingest endpoint (mock-ingest.py) on https://localhost:8443 and the release files
#    (package and SHA256SUMS) served on http://localhost:8080, standing in for a release.
# 2. A package whose SHA-256 does not match is refused and nothing is installed.
# 3. Install from the "release" URL, configure, enrol (token from the environment, on
#    standard input) and start; the service runs, is enrolled and sends to the mock.
# 4. A second run, and a run from a package file on the controller, change nothing.
# 5. state=absent purge=true removes the package, configuration, state and user; a second
#    absent run changes nothing.
set -euo pipefail

dist=$(realpath "$1")
root=$(cd "$(dirname "$0")/../.." && pwd)
work=${RUNNER_TEMP:-/tmp}/wt-ansible
mkdir -p "$work/release"
cd "$root/ansible"

section() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
deb=$(cd "$dist" && ls wedgetail-agent_*_amd64.deb)
version=$(echo "$deb" | sed -E 's/^wedgetail-agent_([^-]+)-([^_]+)_amd64\.deb$/\1/')
revision=$(echo "$deb" | sed -E 's/^wedgetail-agent_([^-]+)-([^_]+)_amd64\.deb$/\2/')
cp "$dist/$deb" "$work/release/"
(cd "$work/release" && sha256sum -- "$deb" > SHA256SUMS && cat SHA256SUMS)

section 'Mock ingest endpoint and release server'
cat > "$work/ca.cnf" <<'EOF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca
[dn]
CN = Wedgetail CI test root (ansible)
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
cat > "$work/leaf.cnf" <<'EOF'
[req]
prompt = no
distinguished_name = dn
[dn]
CN = localhost
[ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost
authorityKeyIdentifier = keyid
EOF
openssl req -x509 -new -newkey rsa:2048 -nodes -keyout "$work/ca.key" -out "$work/ca.pem" -days 2 -config "$work/ca.cnf"
openssl req -new -newkey rsa:2048 -nodes -keyout "$work/leaf.key" -out "$work/leaf.csr" -config "$work/leaf.cnf"
openssl x509 -req -in "$work/leaf.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" -CAcreateserial \
    -out "$work/leaf.pem" -days 2 -extfile "$work/leaf.cnf" -extensions ext
sudo cp "$work/ca.pem" /usr/local/share/ca-certificates/wedgetail-ci-ansible.crt
sudo update-ca-certificates
received="$work/received.ndjson"
: > "$received"
python3 "$root/.github/scripts/mock-ingest.py" 8443 "$work/leaf.pem" "$work/leaf.key" "$received" 2> "$work/mock.log" &
mock=$!
python3 -m http.server 8080 --bind 127.0.0.1 --directory "$work/release" 2> "$work/http.log" &
http=$!
for _ in $(seq 60); do
    if (exec 3<>/dev/tcp/localhost/8443) 2>/dev/null && (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then
        break
    fi
    sleep 0.5
done

export ANSIBLE_FORCE_COLOR=1
playbook() {
    ansible-playbook tests/test.yml \
        -e wedgetail_agent_version="$version" -e wedgetail_agent_package_revision="$revision" \
        -e wedgetail_agent_release_url=http://127.0.0.1:8080 \
        -e wedgetail_agent_endpoint=https://localhost:8443 "$@"
}
# Fails unless the play recap shows changed=0 for localhost.
unchanged() {
    local out
    out=$(playbook "$@" | tee /dev/stderr)
    grep -Eq 'localhost +: ok=[0-9]+ +changed=0 +unreachable=0 +failed=0' <<<"$out" \
        || fail "the run with $* changed something"
}
# Not a real token: the mock accepts any wge_ bearer.
export WEDGETAIL_ENROL_TOKEN="wge_0123456789az_$(printf 'A%.0s' $(seq 43))"

section 'A package that does not match its SHA-256 is refused'
if playbook -e wedgetail_agent_sha256="$(printf '0%.0s' $(seq 64))" > "$work/bad.log" 2>&1; then
    cat "$work/bad.log"; fail 'a package with the wrong SHA-256 was accepted'
fi
# get_url refuses the download (release URL); the role's own check refuses a copied file.
grep -Eq 'did not match|does not match its SHA-256' "$work/bad.log" || { cat "$work/bad.log"; fail 'no checksum error'; }
dpkg -s wedgetail-agent >/dev/null 2>&1 && fail 'the package was installed'
# The token never reaches the output.
grep -q "$WEDGETAIL_ENROL_TOKEN" "$work/bad.log" && fail 'the token is in the output'

section 'Install, configure, enrol and start'
playbook -v | tee "$work/install.log"
grep -q "$WEDGETAIL_ENROL_TOKEN" "$work/install.log" && fail 'the token is in the output'
sudo journalctl --since '-10 min' --no-pager | grep -q "$WEDGETAIL_ENROL_TOKEN" && fail 'the token is in the journal'
systemctl is-active wedgetail-agent
systemctl is-enabled wedgetail-agent
test "$(sudo stat -c '%a %U %G' /etc/wedgetail-agent/agent.toml)" = "640 root wedgetail-agent"
test "$(sudo stat -c '%a %U %G' /etc/wedgetail-agent/rules.d/ci-errors.toml)" = "640 root wedgetail-agent"
sudo cat /etc/wedgetail-agent/agent.toml
sudo test -f /var/lib/wedgetail-agent/enrolment.json
sleep 8
sudo wedgetail-agent status
status=$(sudo wedgetail-agent status --json)
python3 - "$status" <<'PY'
import json, sys
s = json.loads(sys.argv[1])
assert s["enrolment"]["enrolled"] is True, s["enrolment"]
assert s["enrolment"]["host_id"] == "h0st0000ci01", s["enrolment"]
assert s["enrolment"]["endpoint"] == "https://localhost:8443", s["enrolment"]
rules = {c["rule_id"]: c["state"] for c in s["collectors"]}
print(rules)
for rule in ("ci-journal", "ci-journal-errors"):
    assert rules.get(rule) == "running", (rule, rules)
# Only the linux-core preset, without the disabled rule.
assert rules.get("linux-core.kernel") in (None, "disabled"), rules
assert not any(r.startswith("linux-auditd.") for r in rules), rules
PY
# The heartbeat (and any events) arrive at the mock with the host credential.
for _ in $(seq 60); do
    [ -s "$received" ] && break
    sleep 2
done
[ -s "$received" ] || { cat "$work/mock.log"; fail 'nothing received by the mock endpoint'; }
echo "received $(wc -l < "$received") lines"

section 'Second run (release URL) changes nothing'
unchanged
section 'Run from a package file on the controller changes nothing'
unchanged -e wedgetail_agent_package_src="$work/release/$deb"

section 'Remove and purge'
playbook -e wedgetail_agent_state=absent -e wedgetail_agent_purge=true
dpkg -s wedgetail-agent >/dev/null 2>&1 && fail 'the package is still installed'
id wedgetail-agent >/dev/null 2>&1 && fail 'the user is still there'
for path in /etc/wedgetail-agent /var/lib/wedgetail-agent /usr/bin/wedgetail-agent /var/cache/wedgetail-agent-install; do
    test ! -e "$path" || fail "$path is still there"
done
unchanged -e wedgetail_agent_state=absent -e wedgetail_agent_purge=true

section 'Clean up'
kill "$mock" "$http" || true
sudo rm -f /usr/local/share/ca-certificates/wedgetail-ci-ansible.crt
sudo update-ca-certificates --fresh >/dev/null
echo PASS
