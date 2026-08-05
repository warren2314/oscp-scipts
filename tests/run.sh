#!/usr/bin/env bash
# Offline smoke tests for the OSCP toolkit.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_ROOT="$(mktemp -d /tmp/oscp-toolkit-tests.XXXXXX)"
trap 'rm -rf -- "$TEST_ROOT"' EXIT

pass_count=0

pass() {
  pass_count=$((pass_count + 1))
  printf '[PASS] %s\n' "$1"
}

fail() {
  printf '[FAIL] %s\n' "$1" >&2
  exit 1
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local label="$3"
  [[ "$haystack" == *"$needle"* ]] || fail "$label (missing: $needle)"
  pass "$label"
}

mapfile -t scripts < <(find "$REPO_ROOT" -type f -name '*.sh' -not -path '*/.git/*' | sort)
for script in "${scripts[@]}"; do
  bash -n "$script" || fail "bash syntax: ${script#$REPO_ROOT/}"
done
pass "all Bash files pass bash -n"

"$REPO_ROOT/init_oscp.sh" -n smoke -t 192.0.2.10 -b "$TEST_ROOT" >/dev/null
WORKSPACE="$(find "$TEST_ROOT" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -n "$WORKSPACE" && -d "$WORKSPACE" ]] || fail "workspace was not created"
pass "workspace creation"

for required in \
  scripts/oscp.sh scripts/guided.sh scripts/helper.sh scripts/progress.tsv \
  references/AD_PLAYBOOK.md references/WINDOWS_PRIVESC.md \
  references/LATERAL_MOVEMENT.md references/ADVANCED_AD.md \
  reports/progress.tsv; do
  [[ -f "$WORKSPACE/$required" ]] || fail "missing workspace file: $required"
done
[[ -x "$WORKSPACE/scripts/guided.sh" ]] || fail "guided.sh is not executable"
pass "guided interface, tracker, and playbooks are installed"

OSCP="$WORKSPACE/scripts/oscp.sh"

guide_output="$("$OSCP" guide)"
assert_contains "$guide_output" "GUIDED DASHBOARD" "dashboard renders"
assert_contains "$guide_output" "192.0.2.10" "dashboard loads target state"
assert_contains "$guide_output" "./scripts/oscp.sh nmap-full" "dashboard recommends saved-target command"
[[ "$guide_output" != *'nmap-full 192.0.2.10'* ]] || fail "dashboard unnecessarily repeats the saved target"
grep -q $'^target-set\tall\tdone\t' "$WORKSPACE/reports/progress.tsv" || fail "dashboard did not auto-complete target-set"
pass "dashboard auto-completes target task"

context_output="$("$OSCP" context)"
assert_contains "$context_output" "target=192.0.2.10" "context exposes validated saved target"
assert_contains "$context_output" "profile=standalone" "context exposes saved profile"

FAKE_BIN="$TEST_ROOT/fake-bin"
mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/fake-service-tool" <<'EOF'
#!/usr/bin/env bash
printf 'fake %s' "$(basename "$0")"
printf ' %q' "$@"
printf '\n'
EOF
chmod +x "$FAKE_BIN/fake-service-tool"
for tool in smbclient smbmap enum4linux-ng netexec; do
  ln -s fake-service-tool "$FAKE_BIN/$tool"
done

guided_output="$(printf '3\n5\n\nq\n' | env PATH="$FAKE_BIN:$PATH" "$WORKSPACE/scripts/guided.sh" 2>&1)"
assert_contains "$guided_output" "SMB enum complete" "guided SMB action uses saved target"
[[ "$guided_output" != *'Target IP:'* ]] || fail "guided SMB action prompted for an already saved target"
[[ -d "$WORKSPACE/smb/192.0.2.10" ]] || fail "guided SMB action used the wrong target"
pass "guided service action avoids repeated target prompt"

override_output="$(env PATH="$FAKE_BIN:$PATH" "$OSCP" enum-smb 198.51.100.25 2>&1)"
assert_contains "$override_output" "198.51.100.25" "explicit service target overrides saved target"
context_output="$("$OSCP" context)"
assert_contains "$context_output" "target=192.0.2.10" "one-off service override leaves saved target unchanged"

"$OSCP" profile ad >/dev/null
"$OSCP" phase lateral >/dev/null
"$OSCP" focus "validate second host access" >/dev/null
"$OSCP" task done ad-creds >/dev/null
guide_output="$("$OSCP" guide)"
assert_contains "$guide_output" "Profile : ad" "AD profile persists"
assert_contains "$guide_output" "Phase: lateral" "phase persists"
assert_contains "$guide_output" "validate second host access" "focus persists"
pass "task updates persist"

ad_output="$("$OSCP" ad 192.0.2.10 corp.invalid alice TEST_NOT_SECRET)"
assert_contains "$ad_output" "Domain      : corp.invalid" "AD dispatcher forwards domain"
assert_contains "$ad_output" "Username    : alice" "AD dispatcher forwards username"

help_output="$("$OSCP" --help)"
assert_contains "$help_output" "2026.08.05-ad-multihost" "help expands toolkit version"
[[ "$help_output" != *'$TOOLKIT_VERSION'* ]] || fail "help contains literal version variable"
pass "help has no literal version placeholder"

capture_output="$("$OSCP" capture "identity check" -- printf 'user=%s\n' alice 2>&1)"
assert_contains "$capture_output" "user=alice" "manual capture shows command output"
capture_file="$(find "$WORKSPACE/evidence/commands" -maxdepth 1 -type f -name '*_identity_check.txt' -print -quit)"
[[ -n "$capture_file" && -f "$capture_file" ]] || fail "manual capture output file was not created"
grep -q 'user=alice' "$capture_file" || fail "manual capture file is missing command output"
grep -q 'identity check' "$WORKSPACE/notes/04-report-commands.md" || fail "report command index is missing capture label"
grep -q 'evidence/commands/' "$WORKSPACE/notes/04-report-commands.md" || fail "report command index is missing output path"
grep -q 'printf' "$WORKSPACE/commands.log" || fail "commands.log is missing captured command"
pass "manual command capture is indexed"

set +e
failure_output="$("$OSCP" capture "expected failure" -- bash -c 'echo expected-error; exit 7' 2>&1)"
failure_rc=$?
set -e
[[ "$failure_rc" -eq 7 ]] || fail "manual capture did not preserve command exit status"
assert_contains "$failure_output" "expected-error" "failed command output remains visible"
failure_file="$(find "$WORKSPACE/evidence/commands" -maxdepth 1 -type f -name '*_expected_failure.txt' -print -quit)"
[[ -n "$failure_file" && -f "$failure_file" ]] || fail "failed capture output file was not created"
grep -q '\[exit-code: 7\]' "$failure_file" || fail "failed capture file is missing exit status"
pass "failed command capture preserves evidence and exit status"

"$OSCP" set-domain 'https://CORP.INVALID/' >/dev/null
context_output="$("$OSCP" context)"
assert_contains "$context_output" "domain=corp.invalid" "domain is normalized and persisted"

cat >> "$WORKSPACE/.oscp_env" <<'EOF'
OSCP_DISCOVERY_PORTS=53,88,445
OSCP_DISCOVERY_PORTS_WIDE=21,22,80,443
EOF
"$OSCP" set-target 192.0.2.20 192.0.2.0/24 >/dev/null
grep -qx 'OSCP_DISCOVERY_PORTS=53,88,445' "$WORKSPACE/.oscp_env" || fail "custom discovery ports were not preserved"
grep -qx 'OSCP_DISCOVERY_PORTS_WIDE=21,22,80,443' "$WORKSPACE/.oscp_env" || fail "custom wide discovery ports were not preserved"
pass "set-target preserves discovery configuration"

AD_BASE="$TEST_ROOT/ad-workspaces"
mkdir -p "$AD_BASE"
"$REPO_ROOT/init_oscp.sh" -n adsmoke -s 10.0.2.0/24 -b "$AD_BASE" >/dev/null
AD_WORKSPACE="$(find "$AD_BASE" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -n "$AD_WORKSPACE" && -d "$AD_WORKSPACE" ]] || fail "AD workspace was not created"
AD_OSCP="$AD_WORKSPACE/scripts/oscp.sh"
"$AD_OSCP" profile ad >/dev/null

# Reproduce an older workspace that stored the CIDR network address as its DC.
"$AD_OSCP" set-target 10.0.2.0 10.0.2.0/24 >/dev/null
guided_ad_output="$({ echo 1; echo; echo; echo n; echo; echo q; } | "$AD_WORKSPACE/scripts/guided.sh" 2>&1)"
[[ "$guided_ad_output" != *'Target/DC IP:'* ]] || fail "AD setup still asks for a DC before scanning"
assert_contains "$guided_ad_output" "DC selection comes later" "AD setup explains post-scan DC selection"
ad_context="$("$AD_OSCP" context)"
assert_contains "$ad_context" "subnet=10.0.2.0/24" "AD setup saves subnet scope"
assert_contains "$ad_context" "scope_explicit=1" "AD setup confirms exact subnet scope"
! grep -q '^OSCP_TARGET=' "$AD_WORKSPACE/.oscp_env" || fail "AD setup did not clear the legacy network-address target"
! grep -q '^OSCP_DC=' "$AD_WORKSPACE/.oscp_env" || fail "AD setup selected a DC before discovery"
pass "AD setup is subnet-first and repairs legacy network-address targets"

ad_guide="$("$AD_OSCP" guide)"
assert_contains "$ad_guide" "Scope   : 10.0.2.0/24" "AD dashboard displays subnet scope"
assert_contains "$ad_guide" "./scripts/oscp.sh discover" "AD dashboard recommends discovery first"
[[ "$ad_guide" != *'nmap-full 10.0.2.0'* ]] || fail "AD dashboard recommends scanning the network address"

cat > "$FAKE_BIN/sudo" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "chown" ]]; then
  exit 0
fi
exec "$@"
EOF
chmod +x "$FAKE_BIN/sudo"

cat > "$FAKE_BIN/nmap" <<'EOF'
#!/usr/bin/env bash
out=""
target=""
original_args="$*"
while (( $# > 0 )); do
  case "$1" in
    -oA)
      out="$2"
      shift 2
      ;;
    [0-9]*.[0-9]*.[0-9]*.[0-9]*)
      target="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done
[[ -n "$out" ]] || { echo "fake nmap: missing -oA" >&2; exit 2; }
mkdir -p "$(dirname "$out")"
[[ -z "$FAKE_NMAP_LOG" ]] || echo "$original_args" >> "$FAKE_NMAP_LOG"

if [[ "$target" == */* ]]; then
  cat > "$out.gnmap" <<'GNMAP'
Host: 10.0.2.10 () Status: Up
Host: 10.0.2.10 () Ports: 53/open/tcp//domain///, 88/open/tcp//kerberos-sec///, 389/open/tcp//ldap///, 445/open/tcp//microsoft-ds///
Host: 10.0.2.20 () Status: Up
Host: 10.0.2.20 () Ports: 135/open/tcp//msrpc///, 445/open/tcp//microsoft-ds///
Host: 10.0.2.99 () Status: Up
GNMAP
  echo discovery > "$out.nmap"
else
  case "$target" in
    10.0.2.10)
      cat > "$out.nmap" <<'NMAP'
53/tcp open domain
88/tcp open kerberos-sec
389/tcp open ldap
445/tcp open microsoft-ds
NMAP
      ;;
    10.0.2.20)
      cat > "$out.nmap" <<'NMAP'
135/tcp open msrpc
445/tcp open microsoft-ds
3389/tcp open ms-wbt-server
NMAP
      ;;
    *) echo '445/tcp open microsoft-ds' > "$out.nmap" ;;
  esac
  echo "Host: $target () Ports: 445/open/tcp//microsoft-ds///" > "$out.gnmap"
fi
echo '<nmaprun/>' > "$out.xml"
EOF
chmod +x "$FAKE_BIN/nmap"

NMAP_LOG="$TEST_ROOT/fake-nmap.log"
env PATH="$FAKE_BIN:$PATH" OSCP_YES=1 FAKE_NMAP_LOG="$NMAP_LOG" "$AD_OSCP" discover >/dev/null
[[ "$(wc -l < "$AD_WORKSPACE/scans/live_hosts.txt" | tr -d ' ')" == "2" ]] || fail "discovery did not save exactly two responsive hosts"
grep -qx '10.0.2.10' "$AD_WORKSPACE/scans/live_hosts.txt" || fail "discovery missed the DC candidate"
grep -qx '10.0.2.20' "$AD_WORKSPACE/scans/live_hosts.txt" || fail "discovery missed the member host"
! grep -qx '10.0.2.99' "$AD_WORKSPACE/scans/live_hosts.txt" || fail "discovery trusted a -Pn Status: Up line with no open port"
pass "discovery keeps only hosts with observed open ports"

cp "$AD_WORKSPACE/scans/live_hosts.txt" "$TEST_ROOT/live-hosts.good"
echo '10.0.3.50' >> "$AD_WORKSPACE/scans/live_hosts.txt"
: > "$NMAP_LOG"
set +e
scope_guard_output="$(env PATH="$FAKE_BIN:$PATH" OSCP_YES=1 FAKE_NMAP_LOG="$NMAP_LOG" "$AD_OSCP" nmap-full-all 2>&1)"
scope_guard_rc=$?
set -e
[[ "$scope_guard_rc" -ne 0 ]] || fail "batch scan accepted an out-of-scope host"
assert_contains "$scope_guard_output" "outside saved scope" "batch scan reports the out-of-scope host"
[[ ! -s "$NMAP_LOG" ]] || fail "batch scan started before validating the complete host list"
mv "$TEST_ROOT/live-hosts.good" "$AD_WORKSPACE/scans/live_hosts.txt"
pass "batch scan validates all hosts before starting"

: > "$NMAP_LOG"
env PATH="$FAKE_BIN:$PATH" OSCP_YES=1 FAKE_NMAP_LOG="$NMAP_LOG" "$AD_OSCP" nmap-full-all >/dev/null
[[ "$(grep -c -- '-p-' "$NMAP_LOG")" == "2" ]] || fail "full-all did not run one full scan per discovered host"
grep -q '10.0.2.10' "$NMAP_LOG" || fail "full-all did not scan the DC candidate"
grep -q '10.0.2.20' "$NMAP_LOG" || fail "full-all did not scan the member host"
[[ -f "$AD_WORKSPACE/scans/nmap/10.0.2.10_open_ports.txt" ]] || fail "DC candidate port file is missing"
[[ -f "$AD_WORKSPACE/scans/nmap/10.0.2.20_open_ports.txt" ]] || fail "member-host port file is missing"
pass "full-all creates independent scan state for every discovered host"

candidate_output="$("$AD_OSCP" ad-candidates)"
assert_contains "$candidate_output" "10.0.2.10" "candidate table includes discovered DC host"
assert_contains "$candidate_output" "LIKELY DC" "candidate table identifies the Kerberos and LDAP host"

: > "$NMAP_LOG"
env PATH="$FAKE_BIN:$PATH" OSCP_YES=1 FAKE_NMAP_LOG="$NMAP_LOG" "$AD_OSCP" nmap-deep-all >/dev/null
[[ "$(grep -c -- '-sC' "$NMAP_LOG")" == "2" ]] || fail "deep-all did not scan every discovered host"
ad_guide="$("$AD_OSCP" guide)"
assert_contains "$ad_guide" "full 2/2" "AD dashboard reports full-scan coverage"
assert_contains "$ad_guide" "deep 2/2" "AD dashboard reports deep-scan coverage"
assert_contains "$ad_guide" "./scripts/oscp.sh set-dc DC_IP" "AD dashboard requests DC selection only after scans"

set +e
invalid_dc_output="$("$AD_OSCP" set-dc 10.0.2.99 2>&1)"
invalid_dc_rc=$?
set -e
[[ "$invalid_dc_rc" -ne 0 ]] || fail "set-dc accepted a host that was not discovered"
assert_contains "$invalid_dc_output" "not in" "set-dc explains its discovered-host requirement"

"$AD_OSCP" set-dc 10.0.2.10 >/dev/null
"$AD_OSCP" set-target 10.0.2.20 >/dev/null
ad_context="$("$AD_OSCP" context)"
assert_contains "$ad_context" "target=10.0.2.20" "AD active member host can change"
assert_contains "$ad_context" "dc=10.0.2.10" "changing active host preserves selected DC"
"$AD_OSCP" set-domain corp.invalid >/dev/null
ad_default_output="$(OSCP_AD_NO_PROMPT=1 "$AD_OSCP" ad)"
assert_contains "$ad_default_output" "DC / target : 10.0.2.10" "AD helper defaults to selected DC instead of active member"
pass "DC and active member-host state remain separate"

reference_output="$("$OSCP" reference ad)"
assert_contains "$reference_output" "Active Directory Presumed-Breach Playbook" "AD reference is readable"

"$REPO_ROOT/refresh_workspace.sh" "$WORKSPACE" >/dev/null
grep -q $'^ad-creds\tad\tdone\t' "$WORKSPACE/reports/progress.tsv" || fail "refresh overwrote user progress"
[[ -f "$WORKSPACE/scripts/guided.sh" ]] || fail "refresh did not install guided.sh"
find "$WORKSPACE/scripts" -maxdepth 2 -type d -name '.backup_*' | grep -q . || fail "refresh did not create a backup"
pass "refresh updates toolkit files and preserves progress"

printf '\n%d tests passed.\n' "$pass_count"
