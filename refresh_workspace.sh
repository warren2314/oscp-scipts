#!/usr/bin/env bash
# refresh_workspace.sh - update copied scripts inside an existing workspace.
#
# Usage:
#   ./refresh_workspace.sh /path/to/workspace
#   ./refresh_workspace.sh .                    # from inside a workspace
#   ./refresh_workspace.sh --force /path        # skip workspace marker check

set -euo pipefail
umask 077

FORCE=0
TARGET="."

usage() {
  cat <<'USAGE'
refresh_workspace.sh - refresh copied OSCP toolkit scripts in a workspace.

Usage:
  ./refresh_workspace.sh [--force] [WORKSPACE_DIR]

Examples:
  ./refresh_workspace.sh ~/oscp/20260525_1556_filebrowser
  cd ~/oscp/20260525_1556_filebrowser && ~/oscp-toolkit/refresh_workspace.sh .

This keeps a timestamped backup under scripts/.backup_<timestamp>/, then updates
the command runners, guided interface, progress template, and reference playbooks.
USAGE
}

die() {
  echo "[-] $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      TARGET="$1"
      shift
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPL_DIR="$SCRIPT_DIR/templates"

for required in oscp.sh helper.sh guided.sh cmds.sh progress.tsv; do
  [[ -f "$TEMPL_DIR/$required" ]] || die "Missing template: $TEMPL_DIR/$required"
done
for required in AD_PLAYBOOK.md WINDOWS_PRIVESC.md LATERAL_MOVEMENT.md ADVANCED_AD.md; do
  [[ -f "$TEMPL_DIR/references/$required" ]] || die "Missing reference template: $TEMPL_DIR/references/$required"
done

[[ -d "$TARGET" ]] || die "Workspace directory not found: $TARGET"
ROOT="$(cd "$TARGET" && pwd)"

if [[ "$FORCE" -ne 1 && ! -f "$ROOT/.oscp_env" && ! -f "$ROOT/notes.md" ]]; then
  die "This does not look like an OSCP workspace: $ROOT. Use --force to refresh anyway."
fi

mkdir -p "$ROOT/scripts"

STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP="$ROOT/scripts/.backup_$STAMP"
mkdir -p "$BACKUP"

for script in oscp.sh helper.sh guided.sh cmds.sh progress.tsv; do
  if [[ -f "$ROOT/scripts/$script" ]]; then
    cp -p "$ROOT/scripts/$script" "$BACKUP/$script"
  fi
  case "$script" in
    progress.tsv) install -m 0644 "$TEMPL_DIR/$script" "$ROOT/scripts/$script" ;;
    *) install -m 0755 "$TEMPL_DIR/$script" "$ROOT/scripts/$script" ;;
  esac
done

mkdir -p "$ROOT/ad" "$ROOT/creds" "$ROOT/proof" "$ROOT/notes" "$ROOT/reports" \
  "$ROOT/evidence" "$ROOT/privesc/linux" "$ROOT/privesc/windows" "$ROOT/references" "$ROOT/transfer/tools"

mkdir -p "$BACKUP/references"
for reference in AD_PLAYBOOK.md WINDOWS_PRIVESC.md LATERAL_MOVEMENT.md ADVANCED_AD.md; do
  if [[ -f "$ROOT/references/$reference" ]]; then
    cp -p "$ROOT/references/$reference" "$BACKUP/references/$reference"
  fi
  install -m 0644 "$TEMPL_DIR/references/$reference" "$ROOT/references/$reference"
done

if [[ ! -f "$ROOT/reports/progress.tsv" ]]; then
  install -m 0600 "$TEMPL_DIR/progress.tsv" "$ROOT/reports/progress.tsv"
fi
[[ -f "$ROOT/reports/profile.txt" ]] || printf 'standalone\n' > "$ROOT/reports/profile.txt"
[[ -f "$ROOT/reports/phase.txt" ]] || printf 'setup\n' > "$ROOT/reports/phase.txt"

if [[ ! -f "$ROOT/creds/creds.csv" ]]; then
  cat > "$ROOT/creds/creds.csv" <<'EOF'
time,service,user,password_or_hash,source,tested,notes
EOF
fi

if [[ ! -f "$ROOT/commands.log" ]]; then
  : > "$ROOT/commands.log"
fi

if [[ ! -f "$ROOT/reports/scoring.md" ]]; then
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
fi

echo "[+] Refreshed workspace scripts:"
echo "    $ROOT/scripts"
echo "[+] Backup:"
echo "    $BACKUP"
echo "[+] Start menu:"
echo "    cd \"$ROOT\" && ./scripts/guided.sh"
