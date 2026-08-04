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
grep -q $'^target-set\tall\tdone\t' "$WORKSPACE/reports/progress.tsv" || fail "dashboard did not auto-complete target-set"
pass "dashboard auto-completes target task"

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
assert_contains "$help_output" "2026.08.04-capture" "help expands toolkit version"
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

cat >> "$WORKSPACE/.oscp_env" <<'EOF'
OSCP_DISCOVERY_PORTS=53,88,445
OSCP_DISCOVERY_PORTS_WIDE=21,22,80,443
EOF
"$OSCP" set-target 192.0.2.20 192.0.2.0/24 >/dev/null
grep -qx 'OSCP_DISCOVERY_PORTS=53,88,445' "$WORKSPACE/.oscp_env" || fail "custom discovery ports were not preserved"
grep -qx 'OSCP_DISCOVERY_PORTS_WIDE=21,22,80,443' "$WORKSPACE/.oscp_env" || fail "custom wide discovery ports were not preserved"
pass "set-target preserves discovery configuration"

reference_output="$("$OSCP" reference ad)"
assert_contains "$reference_output" "Active Directory Presumed-Breach Playbook" "AD reference is readable"

"$REPO_ROOT/refresh_workspace.sh" "$WORKSPACE" >/dev/null
grep -q $'^ad-creds\tad\tdone\t' "$WORKSPACE/reports/progress.tsv" || fail "refresh overwrote user progress"
[[ -f "$WORKSPACE/scripts/guided.sh" ]] || fail "refresh did not install guided.sh"
find "$WORKSPACE/scripts" -maxdepth 2 -type d -name '.backup_*' | grep -q . || fail "refresh did not create a backup"
pass "refresh updates toolkit files and preserves progress"

printf '\n%d tests passed.\n' "$pass_count"
