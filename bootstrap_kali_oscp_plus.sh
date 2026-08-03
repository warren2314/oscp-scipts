#!/usr/bin/env bash
# bootstrap_kali_oscp_plus.sh
#
# Rebuild a fresh Kali machine for authorised OSCP+/PEN-200 style lab and exam
# prep. It installs a focused Kali toolset, creates an easy-to-use OffSec folder,
# stages common helper files, and installs this local oscp-toolkit when present.
#
# Usage:
#   chmod +x bootstrap_kali_oscp_plus.sh
#   ./bootstrap_kali_oscp_plus.sh --yes
#   ./bootstrap_kali_oscp_plus.sh --large --yes
#   ./bootstrap_kali_oscp_plus.sh --no-download-extras
#
# Notes:
#   - Run this on your fresh Kali install, not during the live exam.
#   - Installing a tool does not make every feature of that tool exam-allowed.
#   - Verify the live OffSec guide before your exam.

set -euo pipefail
umask 077
shopt -s globstar nullglob

BASE_DIR="$HOME/Documents/OffSec"
ASSUME_YES=0
DRY_RUN=0
SKIP_UPGRADE=0
DOWNLOAD_EXTRAS=1
INSTALL_TOOLKIT=1
INSTALL_LARGE=0
INSTALL_EVERYTHING=0
INCLUDE_SENSITIVE=0

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || realpath "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s\n' "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

usage() {
  cat <<'USAGE'
bootstrap_kali_oscp_plus.sh - rebuild a fresh Kali box for OSCP+/PEN-200 prep.

Default behavior:
  - apt update, optionally full-upgrade
  - install an OSCP-focused package set from Kali repositories
  - create ~/Documents/OffSec/{Tools,Transfer,Wordlists,Workspaces,Notes}
  - download/update a small set of common lab helper scripts
  - stage local helper files into ~/Documents/OffSec/Transfer/tools
  - install this oscp-toolkit into ~/oscp-toolkit when repo files are present
  - add ~/.oscp_plus_aliases to Bash/Zsh startup files

Usage:
  ./bootstrap_kali_oscp_plus.sh [options]

Options:
  --yes                  Do not prompt; assume yes for installs.
  --dry-run              Print what would run without changing the system.
  --base-dir DIR         Use DIR instead of ~/Documents/OffSec.
  --no-upgrade           Skip apt full-upgrade.
  --no-download-extras   Skip GitHub/raw helper downloads.
  --no-toolkit           Do not install the local oscp-toolkit.
  --large                Also install kali-linux-large.
  --everything           Also install kali-linux-everything. Very large.
  --include-sensitive    Stage sensitive credential tooling if already installed.
  -h, --help             Show this help.

Recommended fresh Kali flow:
  ./bootstrap_kali_oscp_plus.sh --yes
  source ~/.oscp_plus_aliases
  oscp-health
  oscp-new -n first-box -t 192.168.56.10 -b "$OFFSEC_HOME/Workspaces"
USAGE
}

log() { printf '[*] %s\n' "$*"; }
ok() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die() { printf '[-] %s\n' "$*" >&2; exit 1; }

set_paths() {
  TOOLS_DIR="$BASE_DIR/Tools"
  LINUX_TOOLS_DIR="$TOOLS_DIR/linux"
  WINDOWS_TOOLS_DIR="$TOOLS_DIR/windows"
  POWERSHELL_TOOLS_DIR="$TOOLS_DIR/powershell"
  WORDLISTS_DIR="$BASE_DIR/Wordlists"
  WORKSPACES_DIR="$BASE_DIR/Workspaces"
  NOTES_DIR="$BASE_DIR/Notes"
  TRANSFER_DIR="$BASE_DIR/Transfer"
  STAGE_DIR="$TRANSFER_DIR/tools"
  ALIASES_FILE="$HOME/.oscp_plus_aliases"
}

for arg in "$@"; do
  case "$arg" in
    --yes) ASSUME_YES=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --no-upgrade) SKIP_UPGRADE=1 ;;
    --no-download-extras) DOWNLOAD_EXTRAS=0 ;;
    --no-toolkit) INSTALL_TOOLKIT=0 ;;
    --large) INSTALL_LARGE=1 ;;
    --everything) INSTALL_EVERYTHING=1 ;;
    --include-sensitive) INCLUDE_SENSITIVE=1 ;;
    -h|--help) usage; exit 0 ;;
  esac
done

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-dir)
      [[ $# -ge 2 ]] || die "--base-dir needs a path"
      BASE_DIR="${2%/}"
      shift 2
      ;;
    --yes|--dry-run|--no-upgrade|--no-download-extras|--no-toolkit|--large|--everything|--include-sensitive|-h|--help)
      shift
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

set_paths

confirm() {
  local question="$*"
  if (( ASSUME_YES == 1 )); then
    return 0
  fi
  local ans
  read -r -p "[?] ${question} [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

run_cmd() {
  if (( DRY_RUN == 1 )); then
    printf '[dry-run]'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

run_sudo() {
  if (( DRY_RUN == 1 )); then
    printf '[dry-run]'
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
      printf ' %q' "$@"
    else
      printf ' sudo'
      printf ' %q' "$@"
    fi
    printf '\n'
    return 0
  fi

  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

unique_items() {
  local item
  local seen=" "
  for item in "$@"; do
    [[ -n "$item" ]] || continue
    case "$seen" in
      *" $item "*) ;;
      *)
        seen="${seen}${item} "
        printf '%s\n' "$item"
        ;;
    esac
  done
}

package_installed() {
  (( DRY_RUN == 1 )) && return 1
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}

package_available() {
  (( DRY_RUN == 1 )) && return 0
  apt-cache show "$1" >/dev/null 2>&1
}

warn_if_not_kali() {
  if [[ -r /etc/os-release ]] && ! grep -qi '^ID=kali' /etc/os-release; then
    warn "This does not look like Kali Linux. The script can run on Debian-like systems, but some Kali packages may be unavailable."
  fi
}

apt_refresh() {
  log "Refreshing apt package lists"
  run_sudo apt update

  if (( SKIP_UPGRADE == 1 )); then
    warn "Skipping apt full-upgrade because --no-upgrade was used."
    return 0
  fi

  if confirm "Run apt full-upgrade now? Recommended on a fresh Kali install."; then
    run_sudo env DEBIAN_FRONTEND=noninteractive apt -y full-upgrade
  else
    warn "Skipped full-upgrade."
  fi
}

install_packages() {
  local -a requested=() available=() unavailable=() already=()
  mapfile -t requested < <(unique_items "$@")

  local pkg
  for pkg in "${requested[@]}"; do
    if package_installed "$pkg"; then
      already+=("$pkg")
    elif package_available "$pkg"; then
      available+=("$pkg")
    else
      unavailable+=("$pkg")
    fi
  done

  log "Requested packages : ${#requested[@]}"
  log "Already installed  : ${#already[@]}"
  log "Available to add   : ${#available[@]}"
  log "Unavailable/skipped: ${#unavailable[@]}"

  if (( ${#unavailable[@]} > 0 )); then
    warn "Skipped packages not found in current apt repositories:"
    printf '    %s\n' "${unavailable[@]}" >&2
  fi

  if (( ${#available[@]} == 0 )); then
    ok "No missing apt packages from the requested set."
    return 0
  fi

  printf '\nPackages to install:\n'
  printf '  %s\n' "${available[@]}"
  printf '\n'

  if confirm "Install these ${#available[@]} packages with apt?"; then
    run_sudo env DEBIAN_FRONTEND=noninteractive apt install -y "${available[@]}"
  else
    warn "Skipped apt package installation."
  fi
}

make_layout() {
  log "Creating OffSec folder layout at $BASE_DIR"
  run_cmd mkdir -p \
    "$LINUX_TOOLS_DIR" \
    "$WINDOWS_TOOLS_DIR" \
    "$POWERSHELL_TOOLS_DIR" \
    "$WORDLISTS_DIR" \
    "$WORKSPACES_DIR" \
    "$NOTES_DIR" \
    "$STAGE_DIR"
}

link_if_exists() {
  local src="${1:?source required}"
  local dest="${2:?destination required}"
  [[ -e "$src" ]] || return 0

  if (( DRY_RUN == 1 )); then
    printf '[dry-run] ln -sfn %q %q\n' "$src" "$dest"
    return 0
  fi

  if [[ -L "$dest" || ! -e "$dest" ]]; then
    ln -sfn "$src" "$dest"
  else
    warn "Not replacing existing non-symlink: $dest"
  fi
}

link_common_paths() {
  link_if_exists /usr/share/seclists "$WORDLISTS_DIR/SecLists"
  link_if_exists /usr/share/wordlists "$WORDLISTS_DIR/Kali-wordlists"
  link_if_exists /usr/share/exploitdb "$TOOLS_DIR/exploitdb"
  link_if_exists /usr/share/windows-resources "$TOOLS_DIR/windows-resources"
  link_if_exists /usr/share/nishang "$TOOLS_DIR/nishang"
  link_if_exists /usr/share/powersploit "$TOOLS_DIR/powersploit"
  link_if_exists /usr/share/peass "$TOOLS_DIR/peass"
}

first_glob_match() {
  local pattern match
  for pattern in "$@"; do
    while IFS= read -r match; do
      [[ -f "$match" ]] || continue
      printf '%s\n' "$match"
      return 0
    done < <(compgen -G "$pattern" 2>/dev/null || true)
  done
  return 1
}

copy_first() {
  local label="${1:?label required}"
  local dest="${2:?destination required}"
  local mode="${3:?mode required}"
  shift 3

  [[ -f "$dest" ]] && return 0

  local src
  if src="$(first_glob_match "$@")"; then
    log "Staging $label"
    run_cmd install -m "$mode" "$src" "$dest"
  else
    warn "Could not find $label locally yet."
  fi
}

copy_to_transfer_if_exists() {
  local src="${1:?source required}"
  local mode="${2:?mode required}"
  [[ -f "$src" ]] || return 0
  run_cmd install -m "$mode" "$src" "$STAGE_DIR/$(basename "$src")"
}

stage_known_local_files() {
  log "Staging local helper files when available"

  copy_first "PowerView.ps1" "$POWERSHELL_TOOLS_DIR/PowerView.ps1" 0644 \
    /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 \
    /usr/share/powersploit/Recon/PowerView.ps1 \
    /opt/PowerSploit/Recon/PowerView.ps1

  copy_first "SharpHound.exe" "$WINDOWS_TOOLS_DIR/SharpHound.exe" 0644 \
    /usr/share/windows-resources/bloodhound/SharpHound.exe \
    /usr/lib/bloodhound/resources/app/Collectors/SharpHound.exe \
    /usr/share/bloodhound/Collectors/SharpHound.exe \
    '/usr/share/bloodhound*/Collectors/SharpHound.exe' \
    '/opt/SharpHound*/SharpHound.exe'

  copy_first "SharpHound.ps1" "$POWERSHELL_TOOLS_DIR/SharpHound.ps1" 0644 \
    /usr/share/windows-resources/bloodhound/SharpHound.ps1 \
    /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1 \
    /usr/share/bloodhound/Collectors/SharpHound.ps1 \
    '/usr/share/bloodhound*/Collectors/SharpHound.ps1' \
    '/opt/SharpHound*/SharpHound.ps1'

  copy_first "linpeas.sh" "$LINUX_TOOLS_DIR/linpeas.sh" 0755 \
    /usr/share/peass/linpeas/linpeas.sh \
    '/usr/share/peass/**/*linpeas*.sh' \
    '/opt/PEASS*/linpeas.sh'

  copy_first "winPEASx64.exe" "$WINDOWS_TOOLS_DIR/winPEASx64.exe" 0644 \
    /usr/share/peass/winpeas/winPEASx64.exe \
    '/usr/share/peass/**/*winPEAS*x64*.exe' \
    '/opt/PEASS*/winPEASx64.exe'

  copy_first "winPEASany.exe" "$WINDOWS_TOOLS_DIR/winPEASany.exe" 0644 \
    /usr/share/peass/winpeas/winPEASany.exe \
    '/usr/share/peass/**/*winPEAS*any*.exe' \
    '/opt/PEASS*/winPEASany.exe'

  copy_first "LinEnum.sh" "$LINUX_TOOLS_DIR/LinEnum.sh" 0755 \
    /usr/share/linenum/LinEnum.sh \
    /usr/share/LinEnum/LinEnum.sh \
    '/opt/LinEnum*/LinEnum.sh'

  copy_first "linux-smart-enumeration" "$LINUX_TOOLS_DIR/lse.sh" 0755 \
    /usr/share/linux-smart-enumeration/lse.sh \
    '/opt/linux-smart-enumeration*/lse.sh'

  copy_first "chisel Windows amd64" "$WINDOWS_TOOLS_DIR/chisel_amd64.exe" 0644 \
    /usr/share/windows-resources/binaries/chisel_amd64.exe \
    '/usr/share/chisel-common-binaries/*windows_amd64.exe'

  copy_first "ligolo-ng Windows agent" "$WINDOWS_TOOLS_DIR/ligolo-ng_agent_amd64.exe" 0644 \
    /usr/share/windows-resources/binaries/ligolo-ng_agent_amd64.exe \
    '/usr/share/ligolo-ng-common-binaries/*agent*windows*amd64*.exe'

  if (( INCLUDE_SENSITIVE == 1 )); then
    copy_first "mimikatz.exe" "$WINDOWS_TOOLS_DIR/mimikatz.exe" 0644 \
      /usr/share/windows-resources/mimikatz/x64/mimikatz.exe \
      /usr/share/mimikatz/x64/mimikatz.exe \
      '/opt/mimikatz*/x64/mimikatz.exe'
  else
    warn "Sensitive credential tooling is not staged by default. Use --include-sensitive only if your rules and scope permit it."
  fi

  copy_to_transfer_if_exists "$POWERSHELL_TOOLS_DIR/PowerView.ps1" 0644
  copy_to_transfer_if_exists "$POWERSHELL_TOOLS_DIR/SharpHound.ps1" 0644
  copy_to_transfer_if_exists "$WINDOWS_TOOLS_DIR/SharpHound.exe" 0644
  copy_to_transfer_if_exists "$LINUX_TOOLS_DIR/linpeas.sh" 0755
  copy_to_transfer_if_exists "$LINUX_TOOLS_DIR/LinEnum.sh" 0755
  copy_to_transfer_if_exists "$LINUX_TOOLS_DIR/lse.sh" 0755
  copy_to_transfer_if_exists "$WINDOWS_TOOLS_DIR/winPEASx64.exe" 0644
  copy_to_transfer_if_exists "$WINDOWS_TOOLS_DIR/winPEASany.exe" 0644
  copy_to_transfer_if_exists "$WINDOWS_TOOLS_DIR/chisel_amd64.exe" 0644
  copy_to_transfer_if_exists "$WINDOWS_TOOLS_DIR/ligolo-ng_agent_amd64.exe" 0644
  copy_to_transfer_if_exists "$WINDOWS_TOOLS_DIR/mimikatz.exe" 0644
}

download_file() {
  local url="${1:?url required}"
  local dest="${2:?dest required}"
  local mode="${3:?mode required}"

  if [[ -f "$dest" ]]; then
    ok "Already present: $dest"
    return 0
  fi

  log "Downloading $(basename "$dest")"
  if (( DRY_RUN == 1 )); then
    printf '[dry-run] curl -fsSL --retry 3 --connect-timeout 20 -o %q %q\n' "$dest" "$url"
    return 0
  fi

  local tmp="${dest}.tmp.$$"
  if curl -fsSL --retry 3 --connect-timeout 20 -o "$tmp" "$url"; then
    mv "$tmp" "$dest"
    chmod "$mode" "$dest"
    ok "Downloaded: $dest"
  else
    rm -f "$tmp"
    warn "Download failed: $url"
  fi
}

download_extra_helpers() {
  (( DOWNLOAD_EXTRAS == 1 )) || return 0

  if ! command -v curl >/dev/null 2>&1; then
    warn "curl is not available; skipping extra helper downloads."
    return 0
  fi

  log "Downloading common lab helper files into $TOOLS_DIR"
  download_file "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" "$LINUX_TOOLS_DIR/linpeas.sh" 0755
  download_file "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" "$WINDOWS_TOOLS_DIR/winPEASx64.exe" 0644
  download_file "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe" "$WINDOWS_TOOLS_DIR/winPEASany.exe" 0644
  download_file "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" "$LINUX_TOOLS_DIR/pspy64" 0755
  download_file "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32" "$LINUX_TOOLS_DIR/pspy32" 0755
  download_file "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" "$LINUX_TOOLS_DIR/LinEnum.sh" 0755
  download_file "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh" "$LINUX_TOOLS_DIR/lse.sh" 0755

  copy_to_transfer_if_exists "$LINUX_TOOLS_DIR/linpeas.sh" 0755
  copy_to_transfer_if_exists "$LINUX_TOOLS_DIR/pspy64" 0755
  copy_to_transfer_if_exists "$LINUX_TOOLS_DIR/pspy32" 0755
  copy_to_transfer_if_exists "$LINUX_TOOLS_DIR/LinEnum.sh" 0755
  copy_to_transfer_if_exists "$LINUX_TOOLS_DIR/lse.sh" 0755
  copy_to_transfer_if_exists "$WINDOWS_TOOLS_DIR/winPEASx64.exe" 0644
  copy_to_transfer_if_exists "$WINDOWS_TOOLS_DIR/winPEASany.exe" 0644
}

install_local_toolkit() {
  (( INSTALL_TOOLKIT == 1 )) || return 0

  if [[ ! -f "$SCRIPT_DIR/install_oscp_toolkit.sh" || ! -f "$SCRIPT_DIR/init_oscp.sh" || ! -d "$SCRIPT_DIR/templates" ]]; then
    warn "Local oscp-toolkit repo files were not found next to this script; skipping toolkit install."
    return 0
  fi

  log "Installing local oscp-toolkit into ~/oscp-toolkit"
  if (( DRY_RUN == 1 )); then
    printf '[dry-run] bash %q --no-alias\n' "$SCRIPT_DIR/install_oscp_toolkit.sh"
    return 0
  fi

  bash "$SCRIPT_DIR/install_oscp_toolkit.sh" --no-alias || warn "Toolkit installer returned a non-zero status."
  mkdir -p "$HOME/oscp-toolkit"
  install -m 0755 "$SCRIPT_DIR/install_oscp_toolkit.sh" "$HOME/oscp-toolkit/install_oscp_toolkit.sh"
  install -m 0755 "$SCRIPT_PATH" "$HOME/oscp-toolkit/bootstrap_kali_oscp_plus.sh"
}

write_aliases() {
  log "Writing shell helper aliases to $ALIASES_FILE"
  if (( DRY_RUN == 1 )); then
    printf '[dry-run] write %q and source it from shell rc files\n' "$ALIASES_FILE"
    return 0
  fi

  cat > "$ALIASES_FILE" <<EOF
# OSCP+/PEN-200 local helper aliases.
# Generated by bootstrap_kali_oscp_plus.sh

export OFFSEC_HOME="$BASE_DIR"
export OSCP_TOOLS_DIR="$TOOLS_DIR"
export OSCP_EXTRA_TOOL_DIRS="$LINUX_TOOLS_DIR:$WINDOWS_TOOLS_DIR:$POWERSHELL_TOOLS_DIR:$STAGE_DIR"

alias cdoffsec='cd "\$OFFSEC_HOME"'
alias oscp-work='cd "\$OFFSEC_HOME/Workspaces"'
alias oscp-tools='cd "\$OFFSEC_HOME/Tools"'
alias oscp-stage='cd "\$OFFSEC_HOME/Transfer"'
alias oscp-new='\$HOME/oscp-toolkit/init_oscp.sh'
alias oscp-refresh='\$HOME/oscp-toolkit/refresh_workspace.sh'
alias oscp-health='\$HOME/oscp-toolkit/install_oscp_toolkit.sh --check-only'

oscp-serve() {
  local port="\${1:-8000}"
  python3 -m http.server "\$port" --directory "\$OFFSEC_HOME/Transfer"
}

oscp-vpn() {
  sudo openvpn "\$@"
}
EOF
  chmod 600 "$ALIASES_FILE"

  local rc line
  line='[ -f "$HOME/.oscp_plus_aliases" ] && . "$HOME/.oscp_plus_aliases"'
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    touch "$rc"
    if ! grep -qF "$line" "$rc"; then
      {
        printf '\n# OSCP+/PEN-200 helper aliases\n'
        printf '%s\n' "$line"
      } >> "$rc"
      ok "Configured $rc"
    fi
  done
}

write_readme() {
  log "Writing quick-start notes"
  if (( DRY_RUN == 1 )); then
    printf '[dry-run] write %q\n' "$BASE_DIR/README_FIRST.txt"
    return 0
  fi

  cat > "$BASE_DIR/README_FIRST.txt" <<EOF
OSCP+/PEN-200 Fresh Kali Quick Start
====================================

Folder layout
-------------
Base folder : $BASE_DIR
Tools       : $TOOLS_DIR
Transfer    : $TRANSFER_DIR
Wordlists   : $WORDLISTS_DIR
Workspaces  : $WORKSPACES_DIR

First commands
--------------
source ~/.oscp_plus_aliases
oscp-health
oscp-new -n first-box -t 192.168.56.10 -b "\$OFFSEC_HOME/Workspaces"
cd "\$OFFSEC_HOME/Workspaces"
cd <new-workspace> && ./scripts/guided.sh

Useful aliases/functions
------------------------
cdoffsec       cd into $BASE_DIR
oscp-work      cd into workspaces
oscp-tools     cd into staged tools
oscp-stage     cd into the transfer folder
oscp-serve     serve $TRANSFER_DIR over HTTP, default port 8000
oscp-vpn FILE  run sudo openvpn FILE
oscp-health    run the toolkit dependency health check
oscp-new       create a target workspace

Exam-rule reminders
-------------------
- Use this setup before the exam, then work from static local notes/tooling.
- Verify the current OffSec exam guide and control panel before relying on any rule.
- Do not use LLM/chatbot help during the live exam or report phase.
- Do not use automatic exploitation tools or mass vulnerability scanners where forbidden.
- Metasploit modules and Meterpreter are restricted. msfvenom and multi/handler have separate allowances in the official guide.
- Responder poisoning/spoofing is prohibited in the exam. Other installed tools remain subject to the live restrictions for the exact feature and action used.
- Installing a package does not mean every feature in that package is exam-allowed.

Staged helper files
-------------------
The transfer folder is for tools you intentionally serve to a lab/exam target:
  $STAGE_DIR

Start a server:
  oscp-serve 8000

Then use the exact transfer method appropriate to your authorised target.

Docker
------
The bootstrap installs Kali's docker.io package and docker-compose, enables the
docker service where systemd is available, and adds your user to the docker group.

After the first run, log out and back in before using Docker without sudo:
  docker run hello-world
  docker compose version

The docker group is effectively root-equivalent. Keep that in mind on shared systems.
EOF
}

configure_docker() {
  log "Configuring Docker"

  local docker_user="${SUDO_USER:-${USER:-}}"

  if (( DRY_RUN == 1 )); then
    printf '[dry-run] sudo systemctl enable docker --now\n'
    if [[ -n "$docker_user" && "$docker_user" != "root" ]]; then
      printf '[dry-run] sudo usermod -aG docker %q\n' "$docker_user"
    fi
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    warn "docker command not found after package install; skipping Docker service setup."
    return 0
  fi

  if getent group docker >/dev/null 2>&1; then
    :
  else
    run_sudo groupadd docker || warn "Could not create docker group."
  fi

  if [[ -n "$docker_user" && "$docker_user" != "root" ]]; then
    if id -nG "$docker_user" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
      ok "$docker_user is already in the docker group."
    else
      run_sudo usermod -aG docker "$docker_user" || warn "Could not add $docker_user to the docker group."
      warn "Log out and back in before using docker without sudo."
    fi
  else
    warn "Could not determine a non-root user to add to the docker group."
  fi

  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files docker.service >/dev/null 2>&1; then
    if run_sudo systemctl enable docker --now; then
      ok "Docker service enabled and started."
    else
      warn "Could not enable/start Docker with systemctl. Start it manually with: sudo systemctl enable docker --now"
    fi
  elif command -v service >/dev/null 2>&1; then
    if run_sudo service docker start; then
      ok "Docker service started."
    else
      warn "Could not start Docker with service. Start it manually after reboot."
    fi
  else
    warn "No supported service manager found. Start Docker manually after reboot."
  fi
}

health_summary() {
  log "Tool availability summary"
  local cmd
  for cmd in \
    nmap rustscan ffuf feroxbuster gobuster whatweb nikto burpsuite \
    smbclient enum4linux-ng smbmap ldapsearch netexec nxc evil-winrm \
    impacket-secretsdump bloodhound bloodhound-setup bloodhound-ce-python \
    bloodhound-python sharphound certipy-ad certi bloodyAD coercer \
    ldapdomaindump ldd2bloodhound kerbrute krbrelayx rubeus responder mitm6 \
    john hashcat hydra searchsploit msfvenom chisel ligolo-proxy \
    docker docker-compose containerd python3 tmux rlwrap openvpn; do
    if command -v "$cmd" >/dev/null 2>&1; then
      printf ' [OK]   %s\n' "$cmd"
    else
      printf ' [MISS] %s\n' "$cmd"
    fi
  done

  printf '\nStaged files:\n'
  if [[ -d "$STAGE_DIR" ]]; then
    find "$STAGE_DIR" -maxdepth 1 -type f -printf '  %f\n' 2>/dev/null | sort || true
  fi
}

KALI_META_PACKAGES=(
  kali-linux-default
)

CORE_PACKAGES=(
  apt-transport-https
  ca-certificates
  curl
  wget
  git
  jq
  unzip
  zip
  p7zip-full
  unrar
  vim
  nano
  tmux
  screen
  rlwrap
  netcat-traditional
  ncat
  socat
  openssl
  python3
  python3-pip
  python3-venv
  pipx
  ruby
  ruby-dev
  golang-go
  build-essential
  make
  gcc
  g++
  gdb
  ltrace
  strace
  default-jdk
  openvpn
  wireguard-tools
  proxychains4
  sshuttle
  autossh
  openssh-client
  freerdp3-x11
  freerdp2-x11
  remmina
  xclip
  xsel
)

RECON_PACKAGES=(
  nmap
  rustscan
  fping
  dnsutils
  dnsenum
  dnsrecon
  fierce
  whois
  nbtscan
  enum4linux-ng
  smbclient
  smbmap
  nfs-common
  ldap-utils
  ldapdomaindump
  snmp
  onesixtyone
  snmpcheck
  smtp-user-enum
  swaks
  ike-scan
  whatweb
  wafw00f
  sslscan
  sslyze
  testssl.sh
)

WEB_PACKAGES=(
  burpsuite
  nikto
  dirb
  dirbuster
  ffuf
  feroxbuster
  gobuster
  wfuzz
  seclists
  wordlists
  cewl
  wpscan
  cadaver
  davtest
  joomscan
  chromium
)

AD_WINDOWS_PACKAGES=(
  impacket-scripts
  python3-impacket
  netexec
  crackmapexec
  evil-winrm
  evil-winrm-py
  bloodhound
  bloodhound-ce-python
  bloodhound.py
  sharphound
  neo4j
  certipy-ad
  certi
  bloodyad
  coercer
  ldeep
  lapsdumper
  kerbrute
  kerberoast
  krbrelayx
  rubeus
  responder
  mitm6
  powersploit
  nishang
  windows-binaries
  windows-privesc-check
)

PRIVESC_EXPLOIT_PACKAGES=(
  exploitdb
  metasploit-framework
  msfpc
  shellnoob
  peass
  pspy
  linux-exploit-suggester
  linux-smart-enumeration
  unix-privesc-check
  libcap2-bin
  binutils
  nasm
  radare2
  rizin
)

CRACKING_PACKAGES=(
  john
  hashcat
  hashid
  hash-identifier
  hydra
  medusa
  ncrack
  fcrackzip
  pdfcrack
  rarcrack
  chntpw
)

PIVOT_TRANSFER_PACKAGES=(
  chisel
  chisel-common-binaries
  ligolo-ng
  ligolo-ng-common-binaries
  putty-tools
)

CONTAINER_PACKAGES=(
  docker.io
  docker-compose
  containerd
)

REPORTING_PACKAGES=(
  flameshot
  xfce4-screenshooter
  scrot
  maim
  imagemagick
  libreoffice
  pandoc
  sqlitebrowser
  mdbtools
  default-mysql-client
  postgresql-client
  redis-tools
)

OPTIONAL_META_PACKAGES=()
(( INSTALL_LARGE == 1 )) && OPTIONAL_META_PACKAGES+=(kali-linux-large)
(( INSTALL_EVERYTHING == 1 )) && OPTIONAL_META_PACKAGES+=(kali-linux-everything)

main() {
  if (( INSTALL_EVERYTHING == 1 )); then
    warn "kali-linux-everything is huge and includes many tools you will not need for OSCP+."
    confirm "Continue with kali-linux-everything?" || die "Aborted."
  fi

  warn_if_not_kali
  make_layout
  apt_refresh

  install_packages \
    "${KALI_META_PACKAGES[@]}" \
    "${OPTIONAL_META_PACKAGES[@]}" \
    "${CORE_PACKAGES[@]}" \
    "${RECON_PACKAGES[@]}" \
    "${WEB_PACKAGES[@]}" \
    "${AD_WINDOWS_PACKAGES[@]}" \
    "${PRIVESC_EXPLOIT_PACKAGES[@]}" \
    "${CRACKING_PACKAGES[@]}" \
    "${PIVOT_TRANSFER_PACKAGES[@]}" \
    "${CONTAINER_PACKAGES[@]}" \
    "${REPORTING_PACKAGES[@]}"

  make_layout
  link_common_paths
  stage_known_local_files
  if (( DOWNLOAD_EXTRAS == 1 )); then
    download_extra_helpers
    stage_known_local_files
  fi
  install_local_toolkit
  write_aliases
  write_readme
  configure_docker
  health_summary

  printf '\n'
  ok "Fresh Kali OSCP+ prep is complete."
  printf 'Next: source %q\n' "$ALIASES_FILE"
  printf 'Then: oscp-health\n'
  printf 'Quick-start notes: %s\n' "$BASE_DIR/README_FIRST.txt"
}

main
