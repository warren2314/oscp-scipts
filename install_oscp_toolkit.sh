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
  require_source_file "refresh_workspace.sh"
  require_source_file "install_oscp_toolkit.sh"
  require_source_file "templates/oscp.sh"
  require_source_file "templates/cmds.sh"
  require_source_file "templates/helper.sh"

  echo "[*] Installing toolkit into: $INSTALL_DIR"
  mkdir -p "$INSTALL_DIR/templates"

  install -m 0755 "$SRC_DIR/init_oscp.sh" "$INSTALL_DIR/init_oscp.sh"
  install -m 0755 "$SRC_DIR/refresh_workspace.sh" "$INSTALL_DIR/refresh_workspace.sh"
  install -m 0755 "$SRC_DIR/install_oscp_toolkit.sh" "$INSTALL_DIR/install_oscp_toolkit.sh"
  install -m 0755 "$SRC_DIR/templates/oscp.sh" "$INSTALL_DIR/templates/oscp.sh"
  install -m 0755 "$SRC_DIR/templates/cmds.sh" "$INSTALL_DIR/templates/cmds.sh"
  install -m 0755 "$SRC_DIR/templates/helper.sh" "$INSTALL_DIR/templates/helper.sh"

  if [[ -f "$SRC_DIR/bootstrap_kali_oscp_plus.sh" ]]; then
    install -m 0755 "$SRC_DIR/bootstrap_kali_oscp_plus.sh" "$INSTALL_DIR/bootstrap_kali_oscp_plus.sh"
  fi

  if [[ -f "$SRC_DIR/README.md" ]]; then
    install -m 0644 "$SRC_DIR/README.md" "$INSTALL_DIR/README.md"
  fi

  echo "[+] Files installed."

  if [[ "$ADD_ALIAS" -eq 1 ]]; then
    local alias_line="alias oscp-init='${INSTALL_DIR}/init_oscp.sh'"
    local refresh_alias_line="alias oscp-refresh='${INSTALL_DIR}/refresh_workspace.sh'"
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
      if ! grep -qF "$refresh_alias_line" "$rc"; then
        {
          echo ""
          echo "# OSCP toolkit workspace refresh"
          echo "$refresh_alias_line"
        } >> "$rc"
        echo "[+] Added refresh alias to $rc"
      fi
    done
    echo "[*] New terminal command: oscp-init -n boxname -t <ip>"
    echo "[*] Refresh an old workspace: oscp-refresh /path/to/workspace"
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

first_existing_file() {
  local pattern match
  for pattern in "$@"; do
    if [[ -f "$pattern" ]]; then
      printf '%s\n' "$pattern"
      return 0
    fi
    while IFS= read -r match; do
      [[ -f "$match" ]] || continue
      printf '%s\n' "$match"
      return 0
    done < <(compgen -G "$pattern" 2>/dev/null || true)
  done
  return 1
}

expand_user_path() {
  local path="${1:-}"
  case "$path" in
    "~") path="$HOME" ;;
    "~/"*) path="$HOME/${path#~/}" ;;
  esac
  printf '%s\n' "$path"
}

tool_search_dirs() {
  local -a dirs extra_dirs
  local raw dir seen=" "

  [[ -n "${OSCP_TOOLS_DIR:-}" ]] && dirs+=("$OSCP_TOOLS_DIR")
  if [[ -n "${OSCP_EXTRA_TOOL_DIRS:-}" ]]; then
    IFS=':' read -r -a extra_dirs <<< "$OSCP_EXTRA_TOOL_DIRS"
    dirs+=("${extra_dirs[@]}")
  fi

  dirs+=(
    "$HOME/Documents/OffSec/Scripts"
    "$HOME/Documents/OffSec/Scripts/oscp-ad"
    "$HOME/Documents/OffSec/Scripts/Ghostpack-CompiledBinaries"
    "$HOME/Documents/OffSec/Scripts/Powershell"
    "$HOME/Documents/OffSec/Scripts/PowerShell"
    "$HOME/Documents/OffSec/Scripts/LinEnum"
    "$HOME/Documents/OffSec/Scripts/PSExec"
    "$HOME/tools"
    "$HOME/Scripts"
  )

  for raw in "${dirs[@]}"; do
    [[ -n "$raw" ]] || continue
    dir="$(expand_user_path "$raw")"
    [[ -n "$dir" ]] || continue
    case "$seen" in
      *" $dir "*) continue ;;
    esac
    seen="${seen}${dir} "
    printf '%s\n' "$dir"
  done
}

tool_file_candidates() {
  local rel dir
  for rel in "$@"; do
    case "$rel" in
      /*|~/*)
        expand_user_path "$rel"
        ;;
      *)
        while IFS= read -r dir; do
          printf '%s/%s\n' "$dir" "$rel"
        done < <(tool_search_dirs)
        ;;
    esac
  done
}

check_file_any() {
  local label="${1:?label required}"
  local why="${2:?reason required}"
  shift 2

  local found
  if found="$(first_existing_file "$@")"; then
    printf " [OK]   %-24s %s\n" "$label" "$why"
    printf "        %s\n" "$found"
    present_count=$((present_count + 1))
  else
    printf " [HINT] %-24s %s\n" "$label" "$why"
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
  local -a candidates

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
  check_tool docker docker.io "containerised lab tooling"
  check_tool docker-compose docker-compose "multi-container lab services"
  check_any_tool "screenshot tool" "report evidence capture" "gnome-screenshot:gnome-screenshot" "xfce4-screenshooter:xfce4-screenshooter" "flameshot:flameshot" "scrot:scrot"

  echo "------------------------------------------------------------"
  echo " Web"
  check_any_tool "dir brute force" "content discovery" "feroxbuster:feroxbuster" "ffuf:ffuf" "gobuster:gobuster"
  check_tool ffuf ffuf "vhost and subdomain checks"
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
  check_tool ldapdomaindump ldapdomaindump "LDAP dump after valid AD creds"
  check_tool evil-winrm evil-winrm "WinRM shell access"
  check_tool certipy-ad certipy-ad "AD CS enumeration and abuse checks"
  check_tool certi certi "lightweight AD CS certificate helper"
  check_tool bloodyAD bloodyad "AD object and privilege path checks"
  check_tool kerbrute kerbrute "Kerberos user/password validation"
  check_tool coercer coercer "coerced-auth lab testing; verify live rules"
  check_tool krbrelayx krbrelayx "Kerberos relay helper; verify live rules"
  check_tool mitm6 mitm6 "IPv6 spoofing lab testing; verify live rules"
  check_tool responder responder "LLMNR/NBT-NS lab testing"
  check_tool snmpwalk snmp "SNMP enumeration"
  check_any_tool "bloodhound" "BloodHound GUI" "bloodhound:bloodhound" "bloodhound-ce:-"
  check_tool bloodhound-setup bloodhound "BloodHound CE initial setup helper"
  check_any_tool "BloodHound ingestor" "BloodHound collection from Kali" "bloodhound-ce-python:bloodhound-ce-python" "bloodhound-python:bloodhound.py"
  check_tool sharphound sharphound "BloodHound CE collector"
  check_tool rubeus rubeus "Kerberos helper; verify live rules"
  mapfile -t candidates < <(tool_file_candidates "PowerView.ps1" "oscp-ad/PowerView.ps1" "Powershell/PowerView.ps1" "PowerShell/PowerView.ps1")
  check_file_any "PowerView.ps1" "stageable Windows AD recon script" \
    "${candidates[@]}" \
    /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 \
    /usr/share/powersploit/Recon/PowerView.ps1 \
    /opt/PowerSploit/Recon/PowerView.ps1
  mapfile -t candidates < <(tool_file_candidates "FindUserSession.ps1" "oscp-ad/FindUserSession.ps1")
  check_file_any "FindUserSession.ps1" "stageable Windows AD session helper" "${candidates[@]}"
  mapfile -t candidates < <(tool_file_candidates "ADAutoEnum.ps1" "oscp-ad/ADAutoEnum.ps1")
  check_file_any "ADAutoEnum.ps1" "stageable AD enumeration script" "${candidates[@]}"
  mapfile -t candidates < <(tool_file_candidates "SharpHound.exe" "*SharpHound*.exe" "Collectors/SharpHound.exe" "Ghostpack-CompiledBinaries/*SharpHound*.exe")
  check_file_any "SharpHound" "stageable BloodHound collector" \
    "${candidates[@]}" \
    /usr/share/windows-resources/bloodhound/SharpHound.exe \
    /usr/lib/bloodhound/resources/app/Collectors/SharpHound.exe \
    /usr/share/bloodhound/Collectors/SharpHound.exe \
    /opt/SharpHound*/SharpHound.exe
  mapfile -t candidates < <(tool_file_candidates "Rubeus.exe" "*Rubeus*.exe" "Ghostpack-CompiledBinaries/*Rubeus*.exe")
  check_file_any "Rubeus.exe" "stageable Kerberos helper" \
    "${candidates[@]}" \
    /usr/share/windows-resources/rubeus/Rubeus.exe \
    /usr/share/rubeus/Rubeus.exe \
    /opt/Rubeus*/Rubeus.exe
  mapfile -t candidates < <(tool_file_candidates "PrintSpoofer.exe" "*PrintSpoofer*.exe")
  check_file_any "PrintSpoofer.exe" "stageable Windows privilege helper" \
    "${candidates[@]}" \
    /usr/share/windows-resources/PrintSpoofer/PrintSpoofer.exe \
    /usr/share/windows-resources/PrintSpoofer.exe \
    /opt/PrintSpoofer*/PrintSpoofer.exe
  mapfile -t candidates < <(tool_file_candidates "winPEASx64.exe" "winPEASany.exe" "winPEAS.exe" "winPEAS.ps1" "WinPeasOb.ps1" "winPEAS.ps1.1" "*winPEAS*.exe" "*winPEAS*.ps1")
  check_file_any "PEAS" "stageable Windows privilege enumeration" "${candidates[@]}"
  mapfile -t candidates < <(tool_file_candidates "linpeas.sh" "LinEnum.sh" "LinEnum/linenum.sh" "LinEnum/LinEnum.sh" "LinEnum/*.sh")
  check_file_any "linpeas/LinEnum" "stageable Linux privilege enumeration" "${candidates[@]}"
  mapfile -t candidates < <(tool_file_candidates "agent.exe" "ligolo-ng_agent*_windows_amd64.zip" "ligolo-ng_proxy*_linux_amd64.tar.gz")
  check_file_any "Ligolo/agent" "stageable pivot helper files" "${candidates[@]}"
  mapfile -t candidates < <(tool_file_candidates "mimikatz.exe" "*mimikatz*.exe" "x64/mimikatz.exe")
  check_file_any "Mimikatz" "sensitive stageable credential tool; opt-in staging only" \
    "${candidates[@]}" \
    /usr/share/windows-resources/mimikatz/x64/mimikatz.exe \
    /usr/share/mimikatz/x64/mimikatz.exe \
    /opt/mimikatz*/x64/mimikatz.exe
  check_any_tool "Empire" "restricted C2-style tooling; verify live rules" "powershell-empire:-" "empire-server:-" "empire:-"
  check_any_tool "Covenant" "restricted C2-style tooling; verify live rules" "covenant:-" "Covenant:-"

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
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
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
