#!/usr/bin/env bash
# init_oscp.sh - create a per-target OSCP workspace and copy helper scripts.
#
# Usage:
#   ./init_oscp.sh -n "NAME" [-s SUBNET] [-t TARGET_IP] [-b BASE_DIR]
#
# Example:
#   ./init_oscp.sh -n "secura" -t 192.168.241.95

set -euo pipefail
umask 077

usage() {
  cat <<'USAGE'
init_oscp.sh - create an OSCP workspace and copy helper scripts.

Usage:
  ./init_oscp.sh -n "NAME" [-s SUBNET] [-t TARGET_IP] [-b BASE_DIR]

Examples:
  ./init_oscp.sh -n secura -t 192.168.241.95
  ./init_oscp.sh -n ad-lab -s 192.168.56.0/24 -b ~/labs/oscp
USAGE
}

is_ipv4() {
  local ip="${1:-}"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.
  local -a octets
  read -r -a octets <<< "$ip"
  local octet
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
  done
}

is_cidr() {
  local cidr="${1:-}"
  [[ "$cidr" == */* ]] || return 1
  local ip="${cidr%/*}"
  local prefix="${cidr#*/}"
  is_ipv4 "$ip" || return 1
  [[ "$prefix" =~ ^[0-9]+$ ]] || return 1
  (( 10#$prefix >= 0 && 10#$prefix <= 32 ))
}

infer_subnet_24() {
  local ip="${1:-}"
  is_ipv4 "$ip" || return 1
  echo "${ip%.*}.0/24"
}

sanitize_name() {
  local raw="${1:?name required}"
  local clean
  clean="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/_/g; s/^_+//; s/_+$//')"
  [[ -n "$clean" ]] || clean="target"
  printf '%s\n' "$clean"
}

NAME=""
SUBNET=""
TARGET=""
BASE_DIR="."

while getopts ":n:s:t:b:h" opt; do
  case "$opt" in
    n) NAME="$OPTARG" ;;
    s) SUBNET="$OPTARG" ;;
    t) TARGET="$OPTARG" ;;
    b) BASE_DIR="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "[-] Unknown option: -$OPTARG" >&2; usage >&2; exit 1 ;;
    :) echo "[-] Option -$OPTARG requires an argument." >&2; usage >&2; exit 1 ;;
  esac
done

[[ -n "$NAME" ]] || { echo "[-] -n is required" >&2; usage >&2; exit 1; }

if [[ -n "$TARGET" ]] && ! is_ipv4 "$TARGET"; then
  echo "[-] Invalid target IPv4 address: $TARGET" >&2
  exit 1
fi

if [[ -n "$SUBNET" ]] && ! is_cidr "$SUBNET"; then
  echo "[-] Invalid subnet CIDR: $SUBNET" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPL_DIR="$SCRIPT_DIR/templates"

for required in oscp.sh cmds.sh helper.sh guided.sh progress.tsv; do
  [[ -f "$TEMPL_DIR/$required" ]] || { echo "[-] Missing $TEMPL_DIR/$required" >&2; exit 1; }
done
for required in AD_PLAYBOOK.md WINDOWS_PRIVESC.md LATERAL_MOVEMENT.md ADVANCED_AD.md; do
  [[ -f "$TEMPL_DIR/references/$required" ]] || { echo "[-] Missing $TEMPL_DIR/references/$required" >&2; exit 1; }
done

DATE_TAG="$(date +%Y%m%d_%H%M)"
SAFE_NAME="$(sanitize_name "$NAME")"
ROOT="${BASE_DIR%/}/${DATE_TAG}_${SAFE_NAME}"

if [[ -e "$ROOT" ]]; then
  echo "[-] Workspace already exists: $ROOT" >&2
  exit 1
fi

mkdir -p \
  "$ROOT/scans/discovery" \
  "$ROOT/scans/nmap" \
  "$ROOT/scans/vuln" \
  "$ROOT/ftp" \
  "$ROOT/ldap" \
  "$ROOT/ad" \
  "$ROOT/smb" \
  "$ROOT/rpc" \
  "$ROOT/snmp" \
  "$ROOT/web" \
  "$ROOT/winrm" \
  "$ROOT/loot" \
  "$ROOT/cracks" \
  "$ROOT/creds" \
  "$ROOT/exploits" \
  "$ROOT/screenshots" \
  "$ROOT/evidence" \
  "$ROOT/proof" \
  "$ROOT/pivots" \
  "$ROOT/privesc/linux" \
  "$ROOT/privesc/windows" \
  "$ROOT/notes" \
  "$ROOT/scripts" \
  "$ROOT/output" \
  "$ROOT/reports" \
  "$ROOT/references" \
  "$ROOT/transfer/tools"

touch "$ROOT/hosts.txt" "$ROOT/creds.txt" "$ROOT/todo.txt" "$ROOT/loot/hashes.txt" "$ROOT/commands.log"
touch "$ROOT/evidence/screenshots.md"

cat > "$ROOT/creds/creds.csv" <<'EOF'
time,service,user,password_or_hash,source,tested,notes
EOF
chmod 600 "$ROOT/creds/creds.csv"

cat > "$ROOT/notes.md" <<EOF
# ${NAME} - Notes

**Start:** $(date -u +"%Y-%m-%d %H:%M UTC")
**Scope:** ${SUBNET:-<add subnet>} ${TARGET:-}
**Rules:** Work only inside your authorised lab or exam scope.

---

## Operating Rules

- Keep one terminal pane for notes and one for current commands.
- Save command output to the workspace, not only terminal scrollback.
- For every interesting finding, record source, command, evidence path, and next action.
- Prefer proving a path manually before running noisy scanners.
- Keep this as static local tooling; do not use an LLM/chatbot during the exam or report phase.
- Do not use automatic exploitation, mass vulnerability scanning, SQLmap-style automation, or restricted tool features.
- Verify the live exam guide and control panel before relying on any rule or point tracker.

---

## Methodology Checklist

- [ ] Confirm scope and target IP/subnet.
- [ ] Run discovery sweep if working a subnet.
- [ ] Run full TCP scan for each target.
- [ ] Run deep TCP scan against discovered ports.
- [ ] Run UDP top ports where time allows.
- [ ] Enumerate every exposed service, not only web.
- [ ] Identify versions, anonymous access, default creds, writable locations, and auth boundaries.
- [ ] Get foothold and immediately record how it was obtained.
- [ ] Run local enumeration and map privilege escalation paths.
- [ ] Capture proof, command history, screenshots, and exploit notes.
- [ ] Write a reproducible finding with impact, evidence, and remediation.

---

## Service Matrix

| Port | Service | Version | Anonymous/default access | Key evidence | Next action |
| --- | --- | --- | --- | --- | --- |
| | | | | | |

---

## Credentials

| Username | Secret/hash | Source | Valid on | Notes |
| --- | --- | --- | --- | --- |
| | | | | |

---

## Findings

### Finding Template

- **Title:**
- **Affected host/service:**
- **Impact:**
- **Evidence:**
- **Reproduction:**
- **Fix:**

---

## Quick Log
<!--OSCP_LOG-->

---
EOF

cat > "$ROOT/notes/00-summary.md" <<EOF
# ${NAME} - ${TARGET:-<target>}

## Status

- [ ] TCP full scan complete
- [ ] TCP deep scan complete
- [ ] UDP top ports checked where time allows
- [ ] Web enum complete
- [ ] SMB enum complete
- [ ] Initial access documented
- [ ] Privilege escalation documented
- [ ] local.txt submitted
- [ ] proof.txt submitted
- [ ] Screenshots captured
- [ ] Report notes complete

## Current Theory

## Creds Found

## Flags

## Next Actions

1.
2.
3.
EOF

cat > "$ROOT/notes/01-enum.md" <<'EOF'
# Enumeration Notes

## TCP

## UDP

## Web

## SMB

## AD Indicators

## Interesting Findings
EOF

cat > "$ROOT/notes/02-exploitation.md" <<'EOF'
# Exploitation Notes

Record only manual, scoped attack steps you can reproduce in the report.

## Initial Access Path

## Commands

## Evidence
EOF

cat > "$ROOT/notes/03-privesc.md" <<'EOF'
# Privilege Escalation Notes

## Local Enumeration

## Credential Reuse

## Misconfigurations

## Proof
EOF

cat > "$ROOT/notes/04-report-commands.md" <<'EOF'
# Report Command Log

Commands recorded with `./scripts/oscp.sh capture` are appended here in order.
Add any other important commands manually, and keep raw output in the generated scan/service folders.
EOF

cat > "$ROOT/reports/findings.md" <<EOF
# ${NAME} - Findings Draft

Use this as a clean reporting draft. Keep raw notes in ../notes.md and command output in the service folders.

## Executive Summary

<one paragraph summary>

## Attack Path

1. <initial access>
2. <privilege escalation>
3. <proof/evidence>

## Findings

### 1. <Finding Title>

**Host:** ${TARGET:-<ip>}
**Severity:** <Low/Medium/High/Critical>

**Description**

<what is wrong>

**Evidence**

\`\`\`text
<commands and concise output>
\`\`\`

**Impact**

<what an attacker can do>

**Remediation**

<specific fix>
EOF

cat > "$ROOT/reports/scoring.md" <<'EOF'
# Score Tracker

Use the exam control panel and current official guide as the source of truth.
This file is a default OSCP+ tracker template, not an authority on live rules.

## Standalone 1

- [ ] local.txt - 10
- [ ] proof.txt - 10

## Standalone 2

- [ ] local.txt - 10
- [ ] proof.txt - 10

## Standalone 3

- [ ] local.txt - 10
- [ ] proof.txt - 10

## AD

- [ ] machine #1 - 10
- [ ] machine #2 - 10
- [ ] machine #3 - 20

## Total

- Current points:
- Passing target: 70/100
- Control panel checked:
EOF

cat > "$ROOT/evidence/screenshots.md" <<EOF
# Screenshot Evidence Index

Use \`./scripts/oscp.sh screenshot "label"\` to capture report evidence with a timestamp, target IP, and companion metadata file.

| Time | Target | Label | Screenshot | Metadata |
| --- | --- | --- | --- | --- |
EOF

install -m 0600 "$TEMPL_DIR/progress.tsv" "$ROOT/reports/progress.tsv"
printf 'standalone\n' > "$ROOT/reports/profile.txt"
printf 'setup\n' > "$ROOT/reports/phase.txt"

ENV_SUBNET="$SUBNET"

{
  echo "# OSCP toolkit workspace state"
  [[ -n "$TARGET" ]] && printf 'OSCP_TARGET=%s\n' "$TARGET"
  [[ -n "$ENV_SUBNET" ]] && printf 'OSCP_SUBNET=%s\n' "$ENV_SUBNET"
  [[ -n "$ENV_SUBNET" ]] && echo "OSCP_SCOPE_EXPLICIT=1"
  echo "OSCP_WORDLIST=/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
  echo "OSCP_VHOST_WORDLIST=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
} > "$ROOT/.oscp_env"
chmod 600 "$ROOT/.oscp_env"

install -m 0755 "$TEMPL_DIR/oscp.sh" "$ROOT/scripts/oscp.sh"
install -m 0755 "$TEMPL_DIR/cmds.sh" "$ROOT/scripts/cmds.sh"
install -m 0755 "$TEMPL_DIR/helper.sh" "$ROOT/scripts/helper.sh"
install -m 0755 "$TEMPL_DIR/guided.sh" "$ROOT/scripts/guided.sh"
install -m 0644 "$TEMPL_DIR/progress.tsv" "$ROOT/scripts/progress.tsv"
for reference in AD_PLAYBOOK.md WINDOWS_PRIVESC.md LATERAL_MOVEMENT.md ADVANCED_AD.md; do
  install -m 0644 "$TEMPL_DIR/references/$reference" "$ROOT/references/$reference"
done

cat > "$ROOT/README.txt" <<EOF
Workspace: ${NAME}
Created: $(date)
Path: ${ROOT}

Guided workflow (recommended):
  cd "${ROOT}"
  ./scripts/guided.sh

Advanced interactive workflow:
  ./scripts/helper.sh

CLI workflow:
  ./scripts/oscp.sh status
  ./scripts/oscp.sh guide
  ./scripts/oscp.sh set-target <ip> [cidr]
  ./scripts/oscp.sh set-subnet <cidr>
  ./scripts/oscp.sh discover
  ./scripts/oscp.sh nmap-full-all
  ./scripts/oscp.sh nmap-deep-all
  ./scripts/oscp.sh ad-candidates
  ./scripts/oscp.sh set-dc <ip>
  ./scripts/oscp.sh nmap-full
  ./scripts/oscp.sh nmap-deep
  ./scripts/oscp.sh suggest
  ./scripts/oscp.sh enum-all

Common logging:
  ./scripts/oscp.sh note "found anonymous SMB share"
  ./scripts/oscp.sh cred "bob:Password123 (SMB on 192.168.56.10)"
  ./scripts/oscp.sh add-cred smb bob 'Password123' 'anonymous share config'
  ./scripts/oscp.sh ad <dc-ip> <domain.local> <user>   # prompts for password
  ./scripts/oscp.sh hash "<hash> (source/type)"
  ./scripts/oscp.sh win-privs
  ./scripts/oscp.sh win-privs privesc/windows/whoami_priv.txt
  ./scripts/oscp.sh screenshot "proof shell with ip address visible"
  ./scripts/oscp.sh proof local
  ./scripts/oscp.sh stuck
  ./scripts/oscp.sh score
  ./scripts/oscp.sh tools

One-shot baseline:
  ./scripts/cmds.sh
EOF

chmod 700 "$ROOT"
echo "[+] Created workspace at: $ROOT"
echo "[+] Next: cd \"$ROOT\" && ./scripts/guided.sh"
