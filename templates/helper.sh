#!/usr/bin/env bash
# helper.sh - interactive menu wrapper around oscp.sh.
#
# Run from a workspace with:
#   ./scripts/helper.sh

set -uo pipefail
umask 077

TOOLKIT_VERSION="2026.05.27-buddy"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OSCP="$SCRIPT_DIR/oscp.sh"
ENV_FILE="$ROOT_DIR/.oscp_env"

[[ -x "$OSCP" ]] || { echo "[-] $OSCP not found or not executable"; exit 1; }

if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  BOLD="$(tput bold 2>/dev/null || true)"
  DIM="$(tput dim 2>/dev/null || true)"
  RESET="$(tput sgr0 2>/dev/null || true)"
  CYAN="$(tput setaf 6 2>/dev/null || true)"
  GREEN="$(tput setaf 2 2>/dev/null || true)"
  YELLOW="$(tput setaf 3 2>/dev/null || true)"
  RED="$(tput setaf 1 2>/dev/null || true)"
else
  BOLD=""; DIM=""; RESET=""; CYAN=""; GREEN=""; YELLOW=""; RED=""
fi

strip_outer_quotes() {
  local val="${1:-}"
  if [[ "${val:0:1}" == '"' && "${val: -1}" == '"' ]]; then
    val="${val:1:${#val}-2}"
  elif [[ "${val:0:1}" == "'" && "${val: -1}" == "'" ]]; then
    val="${val:1:${#val}-2}"
  fi
  printf '%s\n' "$val"
}

load_env() {
  OSCP_TARGET="${OSCP_TARGET:-}"
  OSCP_SUBNET="${OSCP_SUBNET:-}"
  OSCP_DOMAIN="${OSCP_DOMAIN:-}"
  [[ -f "$ENV_FILE" ]] || return 0

  local line key val
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    val="$(strip_outer_quotes "${line#*=}")"
    case "$key" in
      OSCP_TARGET) OSCP_TARGET="$val" ;;
      OSCP_SUBNET) OSCP_SUBNET="$val" ;;
      OSCP_DOMAIN) OSCP_DOMAIN="$val" ;;
      OSCP_WORDLIST) OSCP_WORDLIST="$val" ;;
    esac
  done < "$ENV_FILE"
}

press_enter() {
  echo
  read -r -p "${DIM}Press Enter to return to the menu...${RESET}"
}

prompt() {
  local label="$1"
  local default="${2:-}"
  local val
  if [[ -n "$default" ]]; then
    read -r -p "${BOLD}${label}${RESET} [$default]: " val
    val="${val:-$default}"
  else
    read -r -p "${BOLD}${label}${RESET}: " val
  fi
  echo "$val"
}

confirm() {
  local question="$1"
  local ans
  read -r -p "${YELLOW}${question} [y/N]:${RESET} " ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

target_prompt() {
  load_env
  prompt "Target IP" "${OSCP_TARGET:-}"
}

draw_header() {
  load_env
  # Clear screen and scrollback where the terminal supports it. This avoids old
  # VPN/scanner output showing through the menu on translucent terminals.
  printf '\033[H\033[2J\033[3J'
  echo "${CYAN}${BOLD}============================================================${RESET}"
  echo "${CYAN}${BOLD}  OSCP Helper v${TOOLKIT_VERSION}${RESET}     ${DIM}workspace: $(basename "$ROOT_DIR")${RESET}"
  echo "${CYAN}${BOLD}============================================================${RESET}"

  printf "  Target : %s\n" "${OSCP_TARGET:-${RED}<not set>${RESET}}"
  printf "  Subnet : %s\n" "${OSCP_SUBNET:-${RED}<not set>${RESET}}"

  local live_count=0
  [[ -s "$ROOT_DIR/scans/live_hosts.txt" ]] && live_count=$(wc -l < "$ROOT_DIR/scans/live_hosts.txt")

  local creds=0 hashes=0
  [[ -s "$ROOT_DIR/creds.txt" ]] && creds=$(wc -l < "$ROOT_DIR/creds.txt")
  [[ -s "$ROOT_DIR/loot/hashes.txt" ]] && hashes=$(wc -l < "$ROOT_DIR/loot/hashes.txt")

  printf "  Live   : %-11s Creds : %-5s Hashes: %s\n" "${live_count} host(s)" "$creds" "$hashes"
  echo "${CYAN}${BOLD}------------------------------------------------------------${RESET}"
}

draw_menu() {
  cat <<MENU
  ${BOLD}SETUP${RESET}
    1) Set target / subnet
    2) Status

  ${BOLD}DISCOVERY${RESET}
    3) Discover live hosts (AD-focused ports)
    4) Discover live hosts (wide ports)
    5) Show live hosts

  ${BOLD}NMAP${RESET}
    6) Full TCP scan on target ${GREEN}(run first per box)${RESET}
    7) Deep scan on saved ports
    8) UDP top-100 on target
    9) Optional nmap vuln scripts
   10) Show saved open ports

  ${BOLD}SERVICE ENUM${RESET}
   11) Enum all detected services
   12) Web enum on all common web ports
   13) Web enum for one port
   14) SMB enum
   15) LDAP enum
   16) SNMP enum
   17) WinRM enum

  ${BOLD}WORKFLOW${RESET}
   18) Quick baseline (full, deep, enum-all)
   19) Add note
   20) Log credential
   21) Log hash
   22) Show last 20 notes
   23) Screenshot evidence
   24) Start file-transfer HTTP server
   25) Start listener
   26) Search workspace output
   27) Custom oscp.sh command
   28) Shell in workspace root

  ${BOLD}BUDDY HELPERS${RESET}
   29) Suggest next manual checks
   30) Log structured credential
   31) AD command block
   32) Linux post-shell checklist
   33) Windows post-shell checklist
   34) Windows privilege triage
   35) Proof checklist
   36) Stuck checklist
   37) Score tracker

    q) Quit
MENU
}

action_set_target() {
  load_env
  local ip cidr
  ip="$(prompt "Target IP" "${OSCP_TARGET:-}")"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP given.${RESET}"; return; }
  cidr="$(prompt "Subnet CIDR (blank = auto /24)" "${OSCP_SUBNET:-}")"
  if [[ -n "$cidr" ]]; then
    "$OSCP" set-target "$ip" "$cidr"
  else
    "$OSCP" set-target "$ip"
  fi
}

action_status() { "$OSCP" status; }
action_discover() { "$OSCP" discover; }
action_discover_wide() { "$OSCP" discover-wide; }
action_show_live() { "$OSCP" show-live; }

action_nmap_full() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  "$OSCP" nmap-full "$ip"
}

action_nmap_deep() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  "$OSCP" nmap-deep "$ip"
}

action_nmap_udp() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  echo "${DIM}UDP can take several minutes.${RESET}"
  confirm "Continue?" || return
  "$OSCP" nmap-udp "$ip"
}

action_nmap_vuln() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  echo "${DIM}This runs nmap vuln scripts against saved ports. Use only in authorised scope.${RESET}"
  confirm "Continue?" || return
  "$OSCP" nmap-vuln "$ip"
}

action_ports() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  "$OSCP" ports "$ip"
}

action_enum_all() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  "$OSCP" enum-all "$ip"
}

action_web_all() {
  local ip domain
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  domain="$(prompt "Domain for FUZZ.<domain> checks (blank = skip)" "${OSCP_DOMAIN:-}")"
  "$OSCP" web-all "$ip" "$domain"
}

action_web_one() {
  local ip port domain
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  port="$(prompt "Port" "80")"
  [[ -z "$port" ]] && { echo "${RED}[-] No port.${RESET}"; return; }
  domain="$(prompt "Domain for FUZZ.<domain> checks (blank = skip)" "${OSCP_DOMAIN:-}")"
  "$OSCP" enum-web "$ip" "$port" "$domain"
}

action_smb() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  "$OSCP" enum-smb "$ip"
}

action_ldap() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  "$OSCP" enum-ldap "$ip"
}

action_snmp() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  "$OSCP" enum-snmp "$ip"
}

action_winrm() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  "$OSCP" enum-winrm "$ip"
}

action_quick() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  echo "${DIM}Quick baseline runs full TCP scan, deep scan, then service enum.${RESET}"
  confirm "Continue?" || return
  "$OSCP" quick "$ip"
}

action_suggest() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && { echo "${RED}[-] No IP.${RESET}"; return; }
  "$OSCP" suggest "$ip"
}

action_note() {
  local msg
  msg="$(prompt "Note" "")"
  [[ -z "$msg" ]] && { echo "${RED}[-] Empty note skipped.${RESET}"; return; }
  "$OSCP" note "$msg"
}

action_cred() {
  echo "${DIM}Format: user:pass (source), e.g. bob:Password123 (SMB on 192.168.56.10)${RESET}"
  local entry
  entry="$(prompt "Credential" "")"
  [[ -z "$entry" ]] && { echo "${RED}[-] Empty credential skipped.${RESET}"; return; }
  "$OSCP" cred "$entry"
}

action_add_cred() {
  local service user secret source
  service="$(prompt "Service" "smb")"
  user="$(prompt "Username" "")"
  secret="$(prompt "Password or hash" "")"
  source="$(prompt "Source" "manual")"
  [[ -z "$service" || -z "$user" || -z "$secret" ]] && { echo "${RED}[-] Service, username, and secret are required.${RESET}"; return; }
  "$OSCP" add-cred "$service" "$user" "$secret" "$source"
}

action_hash() {
  echo "${DIM}Format: <hash> (type/source), e.g. <NTLM> (secretsdump on DC)${RESET}"
  local entry
  entry="$(prompt "Hash entry" "")"
  [[ -z "$entry" ]] && { echo "${RED}[-] Empty hash skipped.${RESET}"; return; }
  "$OSCP" hash "$entry"
}

action_show_notes() {
  local notes="$ROOT_DIR/notes.md"
  if [[ ! -f "$notes" ]]; then
    echo "${YELLOW}[!] No notes.md yet.${RESET}"
    return
  fi
  echo "${BOLD}Last 20 log entries:${RESET}"
  grep -E '^- [0-9]{2}:[0-9]{2} - ' "$notes" 2>/dev/null | tail -n 20 || echo "${DIM}(no log entries yet)${RESET}"
}

action_screenshot() {
  local label ip mode
  label="$(prompt "Evidence label" "proof with ip visible")"
  [[ -z "$label" ]] && { echo "${RED}[-] Empty label skipped.${RESET}"; return; }
  ip="$(target_prompt)"
  mode="$(prompt "Mode: full, area, or window" "${OSCP_SCREENSHOT_MODE:-full}")"
  [[ -z "$mode" ]] && mode="full"
  OSCP_SCREENSHOT_MODE="$mode" "$OSCP" screenshot "$label" "$ip"
}

action_ad() {
  local ip
  ip="$(target_prompt)"
  [[ -z "$ip" ]] && ip="TARGET"
  "$OSCP" ad "$ip"
}

action_loot_linux() { "$OSCP" loot-linux; }
action_loot_windows() { "$OSCP" loot-windows; }

action_win_privs() {
  local file
  echo "${DIM}Optional: pass a saved whoami /priv output file to highlight risky privileges.${RESET}"
  file="$(prompt "whoami /priv file (blank = guide only)" "")"
  if [[ -n "$file" ]]; then
    "$OSCP" win-privs "$file"
  else
    "$OSCP" win-privs
  fi
}

action_proof() {
  local type
  type="$(prompt "Proof type: local or proof" "local")"
  "$OSCP" proof "$type"
}

action_stuck() { "$OSCP" stuck; }
action_score() { "$OSCP" score; }

action_serve() {
  local port
  port="$(prompt "Port" "8000")"
  [[ -z "$port" ]] && return
  "$OSCP" serve "$port"
}

action_listener() {
  local port
  port="$(prompt "Port" "4444")"
  [[ -z "$port" ]] && return
  "$OSCP" listener "$port"
}

action_loot_search() {
  local term
  term="$(prompt "Search term" "")"
  [[ -z "$term" ]] && return
  "$OSCP" loot-search "$term"
}

action_custom() {
  echo "${DIM}Examples: nmap-full 192.168.56.10 | enum-web 192.168.56.10 8080 | note found creds${RESET}"
  local -a args
  read -r -p "${BOLD}oscp.sh>${RESET} " -a args
  [[ "${#args[@]}" -eq 0 ]] && return
  "$OSCP" "${args[@]}"
}

action_shell() {
  echo "${DIM}Opening a shell in $ROOT_DIR. Type exit to return.${RESET}"
  ( cd "$ROOT_DIR" && "${SHELL:-bash}" )
}

while true; do
  draw_header
  draw_menu
  echo
  read -r -p "${BOLD}choose>${RESET} " choice

  case "$choice" in
    1) action_set_target ;;
    2) action_status ;;
    3) action_discover ;;
    4) action_discover_wide ;;
    5) action_show_live ;;
    6) action_nmap_full ;;
    7) action_nmap_deep ;;
    8) action_nmap_udp ;;
    9) action_nmap_vuln ;;
    10) action_ports ;;
    11) action_enum_all ;;
    12) action_web_all ;;
    13) action_web_one ;;
    14) action_smb ;;
    15) action_ldap ;;
    16) action_snmp ;;
    17) action_winrm ;;
    18) action_quick ;;
    19) action_note ;;
    20) action_cred ;;
    21) action_hash ;;
    22) action_show_notes ;;
    23) action_screenshot ;;
    24) action_serve ;;
    25) action_listener ;;
    26) action_loot_search ;;
    27) action_custom ;;
    28) action_shell ;;
    29) action_suggest ;;
    30) action_add_cred ;;
    31) action_ad ;;
    32) action_loot_linux ;;
    33) action_loot_windows ;;
    34) action_win_privs ;;
    35) action_proof ;;
    36) action_stuck ;;
    37) action_score ;;
    q|Q|"") echo "bye."; exit 0 ;;
    *) echo "${RED}[-] Unknown option: $choice${RESET}" ;;
  esac

  press_enter
done
