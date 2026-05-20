#!/usr/bin/env bash
# install_oscp_toolkit.sh
#
# Install the OSCP training toolkit on Kali or another Debian-like system.
#
# Usage:
#   ./install_oscp_toolkit.sh
#   ./install_oscp_toolkit.sh --check-only
#   ./install_oscp_toolkit.sh --install-missing
#   ./install_oscp_toolkit.sh --no-alias
#
# What it does:
#   1. Copies init_oscp.sh and templates/ to ~/oscp-toolkit/
#   2. Optionally adds an oscp-init alias to ~/.bashrc and ~/.zshrc
#   3. Runs a tool and wordlist health check
#   4. Installs missing apt packages only when --install-missing is used

set -euo pipefail

INSTALL_DIR="${HOME}/oscp-toolkit"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CHECK_ONLY=0
INSTALL_MISSING=0
ADD_ALIAS=1

usage() {
  awk '
    NR == 1 { next }
    /^#/ { sub(/^# ?/, ""); print; next }
    NF { exit }
  ' "$0"
}

for arg in "$@"; do
  case "$arg" in
    --check-only) CHECK_ONLY=1 ;;
    --install-missing) INSTALL_MISSING=1 ;;
    --no-alias) ADD_ALIAS=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[-] Unknown argument: $arg" >&2; usage >&2; exit 1 ;;
  esac
done

require_source_file() {
  local rel="${1:?relative path required}"
  [[ -f "$SRC_DIR/$rel" ]] || { echo "[-] Missing source file: $SRC_DIR/$rel" >&2; exit 1; }
}

copy_toolkit() {
  require_source_file "init_oscp.sh"
  require_source_file "templates/oscp.sh"
  require_source_file "templates/cmds.sh"
  require_source_file "templates/helper.sh"

  echo "[*] Installing toolkit into: $INSTALL_DIR"
  mkdir -p "$INSTALL_DIR/templates"

  install -m 0755 "$SRC_DIR/init_oscp.sh" "$INSTALL_DIR/init_oscp.sh"
  install -m 0755 "$SRC_DIR/templates/oscp.sh" "$INSTALL_DIR/templates/oscp.sh"
  install -m 0755 "$SRC_DIR/templates/cmds.sh" "$INSTALL_DIR/templates/cmds.sh"
  install -m 0755 "$SRC_DIR/templates/helper.sh" "$INSTALL_DIR/templates/helper.sh"

  if [[ -f "$SRC_DIR/README.md" ]]; then
    install -m 0644 "$SRC_DIR/README.md" "$INSTALL_DIR/README.md"
  fi

  echo "[+] Files installed."

  if [[ "$ADD_ALIAS" -eq 1 ]]; then
    local alias_line="alias oscp-init='${INSTALL_DIR}/init_oscp.sh'"
    local rc
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
      [[ -f "$rc" ]] || continue
      if ! grep -qF "$alias_line" "$rc"; then
        {
          echo ""
          echo "# OSCP toolkit"
          echo "$alias_line"
        } >> "$rc"
        echo "[+] Added alias to $rc"
      fi
    done
    echo "[*] New terminal command: oscp-init -n boxname -t <ip>"
  fi
}

cmd_exists() {
  command -v "$1" >/dev/null 2>&1
}

add_missing_pkg() {
  local pkg="${1:-}"
  [[ -n "$pkg" && "$pkg" != "-" ]] || return 0
  missing_pkgs+=("$pkg")
}

check_tool() {
  local cmd="${1:?command required}"
  local pkg="${2:?package required}"
  local why="${3:?reason required}"

  if cmd_exists "$cmd"; then
    printf " [OK]   %-24s %s\n" "$cmd" "$why"
    present_count=$((present_count + 1))
  else
    printf " [MISS] %-24s %s  (apt: %s)\n" "$cmd" "$why" "$pkg"
    add_missing_pkg "$pkg"
  fi
}

check_any_tool() {
  local label="${1:?label required}"
  local why="${2:?reason required}"
  shift 2

  local found=0
  local spec cmd pkg
  for spec in "$@"; do
    cmd="${spec%%:*}"
    pkg="${spec#*:}"
    if cmd_exists "$cmd"; then
      found=1
      printf " [OK]   %-24s %s\n" "$cmd" "$why"
      present_count=$((present_count + 1))
      break
    fi
  done

  if [[ "$found" -eq 0 ]]; then
    printf " [MISS] %-24s %s\n" "$label" "$why"
    local added=0
    for spec in "$@"; do
      pkg="${spec#*:}"
      if [[ "$added" -eq 0 && "$pkg" != "-" ]]; then
        add_missing_pkg "$pkg"
        added=1
      fi
    done
  fi
}

unique_packages() {
  local pkg
  local out=()
  for pkg in "$@"; do
    [[ -n "$pkg" && "$pkg" != "-" ]] || continue
    if [[ " ${out[*]} " != *" $pkg "* ]]; then
      out+=("$pkg")
    fi
  done
  if (( ${#out[@]} > 0 )); then
    printf '%s\n' "${out[@]}"
  fi
}

print_health_check() {
  missing_pkgs=()
  present_count=0

  echo "============================================================"
  echo " OSCP TOOL HEALTH CHECK"
  echo "============================================================"
  echo " Host: $(hostname)  User: ${USER:-unknown}  $(uname -srm)"
  if cmd_exists lsb_release; then
    echo " Distro: $(lsb_release -ds 2>/dev/null || echo unknown)"
  fi
  echo "------------------------------------------------------------"
  echo " Core"
  check_tool nmap nmap "TCP/UDP scanning"
  check_tool curl curl "HTTP requests and headers"
  check_tool git git "tooling and exploit review"
  check_tool python3 python3 "quick scripts and HTTP server"
  check_any_tool "netcat/ncat" "listeners and manual TCP checks" "nc:netcat-traditional" "ncat:ncat"
  check_tool rlwrap rlwrap "stable interactive shells"
  check_tool tmux tmux "exam session management"
  check_tool tcpdump tcpdump "traffic validation"
  check_any_tool "screenshot tool" "report evidence capture" "gnome-screenshot:gnome-screenshot" "xfce4-screenshooter:xfce4-screenshooter" "flameshot:flameshot" "scrot:scrot"

  echo "------------------------------------------------------------"
  echo " Web"
  check_any_tool "dir brute force" "content discovery" "feroxbuster:feroxbuster" "ffuf:ffuf" "gobuster:gobuster"
  check_tool whatweb whatweb "web fingerprinting"
  check_tool nikto nikto "web misconfiguration checks"

  echo "------------------------------------------------------------"
  echo " SMB / AD / Windows"
  check_tool smbclient smbclient "SMB shares"
  check_tool rpcclient smbclient "RPC null-session checks"
  check_tool smbmap smbmap "SMB permissions"
  check_tool enum4linux-ng enum4linux-ng "SMB/Windows enumeration"
  check_any_tool "netexec/cme" "SMB/AD credential checks" "netexec:netexec" "crackmapexec:crackmapexec"
  check_tool impacket-secretsdump python3-impacket "Impacket scripts"
  check_tool ldapsearch ldap-utils "LDAP enumeration"
  check_tool evil-winrm evil-winrm "WinRM shell access"
  check_tool responder responder "LLMNR/NBT-NS lab testing"
  check_tool snmpwalk snmp "SNMP enumeration"

  echo "------------------------------------------------------------"
  echo " Passwords / Pivoting"
  check_tool hydra hydra "online password attacks"
  check_tool john john "hash cracking"
  check_tool hashcat hashcat "GPU/CPU hash cracking"
  check_tool chisel chisel "HTTP tunneling"
  check_tool ssh openssh-client "SSH access and tunneling"

  echo "------------------------------------------------------------"
  echo " Wordlists"
  local seclists_paths=(
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
  )
  local fallback_paths=(
    "/usr/share/wordlists/dirb/common.txt:dirb"
  )
  local rockyou_paths=(
    "/usr/share/wordlists/rockyou.txt"
    "/usr/share/wordlists/rockyou.txt.gz"
  )

  local path entry pkg seclists_found=0 fallback_found=0 rockyou_found=0
  for path in "${seclists_paths[@]}"; do
    if [[ -e "$path" ]]; then
      printf " [OK]   %s\n" "$path"
      seclists_found=1
    else
      printf " [HINT] %s not found\n" "$path"
    fi
  done
  if [[ "$seclists_found" -eq 0 ]]; then
    add_missing_pkg seclists
  fi

  for entry in "${fallback_paths[@]}"; do
    path="${entry%%:*}"
    pkg="${entry##*:}"
    if [[ -e "$path" ]]; then
      printf " [OK]   %s\n" "$path"
      fallback_found=1
    else
      printf " [HINT] %s not found  (apt: %s)\n" "$path" "$pkg"
    fi
  done
  if [[ "$seclists_found" -eq 0 && "$fallback_found" -eq 0 ]]; then
    add_missing_pkg dirb
  fi

  for path in "${rockyou_paths[@]}"; do
    if [[ -e "$path" ]]; then
      printf " [OK]   %s\n" "$path"
      rockyou_found=1
    else
      printf " [HINT] %s not found\n" "$path"
    fi
  done
  if [[ "$rockyou_found" -eq 0 ]]; then
    add_missing_pkg wordlists
  fi

  if [[ "$rockyou_found" -eq 0 ]]; then
    echo " [HINT] If rockyou.txt.gz exists after install, run: sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz"
  fi

  mapfile -t unique_missing < <(unique_packages "${missing_pkgs[@]}")

  echo "------------------------------------------------------------"
  echo " SUMMARY"
  echo " Present checks : $present_count"
  echo " Missing pkgs   : ${#unique_missing[@]}"
  if (( ${#unique_missing[@]} > 0 )); then
    echo " Packages       : ${unique_missing[*]}"
  fi

  echo "------------------------------------------------------------"
  if (( ${#unique_missing[@]} == 0 )); then
    echo " VERDICT: Toolkit dependencies look ready."
  elif (( ${#unique_missing[@]} <= 5 )); then
    echo " VERDICT: Mostly ready. Install the missing packages; no rebuild needed."
  else
    echo " VERDICT: Several tools are missing. Use --install-missing or rebuild Kali if"
    echo "          the machine is generally stale or broken."
  fi
  echo "============================================================"
}

if [[ "$CHECK_ONLY" -eq 0 ]]; then
  copy_toolkit
  echo
fi

print_health_check

if (( INSTALL_MISSING == 1 )); then
  if (( ${#unique_missing[@]} == 0 )); then
    echo "[+] Nothing to install."
    exit 0
  fi

  echo
  echo "[*] Missing packages: ${unique_missing[*]}"
  read -r -p "[?] Install with apt now? [y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    sudo apt update
    sudo apt install -y "${unique_missing[@]}"
    echo "[+] Install complete. Re-run: $0 --check-only"
  else
    echo "[-] Skipped package install."
  fi
fi
