#!/usr/bin/env bash
# guided.sh - compact, progress-oriented interface for the OSCP toolkit.

set -uo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OSCP="$SCRIPT_DIR/oscp.sh"
ADVANCED="$SCRIPT_DIR/helper.sh"

[[ -x "$OSCP" ]] || { echo "[-] $OSCP not found or not executable" >&2; exit 1; }

if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  BOLD="$(tput bold 2>/dev/null || true)"
  RESET="$(tput sgr0 2>/dev/null || true)"
  CYAN="$(tput setaf 6 2>/dev/null || true)"
  YELLOW="$(tput setaf 3 2>/dev/null || true)"
else
  BOLD=""; RESET=""; CYAN=""; YELLOW=""
fi

SAVED_TARGET=""
SAVED_SUBNET=""
SAVED_DC=""
SAVED_DOMAIN=""
SAVED_SCOPE_EXPLICIT="0"
SAVED_PROFILE="standalone"

load_saved_context() {
  local key value
  SAVED_TARGET=""
  SAVED_SUBNET=""
  SAVED_DC=""
  SAVED_DOMAIN=""
  SAVED_SCOPE_EXPLICIT="0"
  SAVED_PROFILE="standalone"
  while IFS='=' read -r key value; do
    case "$key" in
      target) SAVED_TARGET="$value" ;;
      subnet) SAVED_SUBNET="$value" ;;
      dc) SAVED_DC="$value" ;;
      domain) SAVED_DOMAIN="$value" ;;
      scope_explicit) SAVED_SCOPE_EXPLICIT="$value" ;;
      profile) SAVED_PROFILE="$value" ;;
    esac
  done < <("$OSCP" context)
  [[ "$SAVED_PROFILE" == "standalone" || "$SAVED_PROFILE" == "ad" ]] || SAVED_PROFILE="standalone"
}

pause() {
  echo
  read -r -p "Press Enter to continue..."
}

prompt() {
  local label="$1"
  local default="${2:-}"
  local value
  if [[ -n "$default" ]]; then
    read -r -p "$label [$default]: " value
    value="${value:-$default}"
  else
    read -r -p "$label: " value
  fi
  printf '%s\n' "$value"
}

confirm() {
  local answer
  read -r -p "$1 [y/N]: " answer
  [[ "$answer" =~ ^[Yy]$ ]]
}

setup_workspace() {
  local profile target subnet subnet_default
  load_saved_context
  profile="$(prompt "Profile (standalone or ad)" "$SAVED_PROFILE")"
  "$OSCP" profile "$profile" || return

  if [[ "$profile" == "ad" ]]; then
    subnet="$(prompt "Exact AD subnet CIDR" "$SAVED_SUBNET")"
    [[ -n "$subnet" ]] || { echo "[-] An AD subnet CIDR is required."; return; }
    "$OSCP" set-subnet "$subnet" || return
    echo "[+] DC selection comes later, after every discovered host is scanned."
  else
    target="$(prompt "Target IP" "$SAVED_TARGET")"
    [[ -n "$target" ]] || return
    subnet_default=""
    [[ "$target" == "$SAVED_TARGET" ]] && subnet_default="$SAVED_SUBNET"
    subnet="$(prompt "Subnet CIDR (optional; blank = this IP only)" "$subnet_default")"
    if [[ -n "$subnet" ]]; then
      "$OSCP" set-target "$target" "$subnet"
    else
      "$OSCP" set-target "$target"
    fi
  fi
  if confirm "Have you verified this target/subnet and its objectives in the control panel/scope?"; then
    "$OSCP" task done scope-confirmed >/dev/null || true
  fi
}

scan_menu() {
  local choice ip
  load_saved_context
  if [[ "$SAVED_PROFILE" == "ad" ]]; then
    cat <<'MENU'
  1) Discover hosts on the saved AD subnet (start here)
  2) Full TCP scan every discovered host
  3) Deep service scan every discovered host
  4) Light top-1000 service scan across all discovered hosts
  5) Show hosts and likely DC candidates
  6) Select and save the DC
  7) UDP top-100 scan on the selected DC/active host
  b) Back
MENU
    read -r -p "scan> " choice
    case "$choice" in
      1) "$OSCP" discover ;;
      2) "$OSCP" nmap-full-all ;;
      3) "$OSCP" nmap-deep-all ;;
      4) "$OSCP" nmap-live ;;
      5) "$OSCP" ad-candidates ;;
      6)
        "$OSCP" ad-candidates || return
        ip="$(prompt "DC IP from the discovered list" "$SAVED_DC")"
        [[ -n "$ip" ]] && "$OSCP" set-dc "$ip"
        ;;
      7) confirm "UDP can take several minutes. Continue?" && "$OSCP" nmap-udp ;;
      b|B|"") return ;;
      *) echo "[-] Unknown option" ;;
    esac
    return
  fi

  cat <<'MENU'
  1) Full TCP scan
  2) Deep scan on saved ports
  3) UDP top-100 scan
  4) Show saved ports
  b) Back
MENU
  read -r -p "scan> " choice
  case "$choice" in
    1) "$OSCP" nmap-full ;;
    2) "$OSCP" nmap-deep ;;
    3) confirm "UDP can take several minutes. Continue?" && "$OSCP" nmap-udp ;;
    4) "$OSCP" ports ;;
    b|B|"") return ;;
    *) echo "[-] Unknown option" ;;
  esac
}

enum_menu() {
  local choice ip port domain
  load_saved_context
  cat <<'MENU'
  1) Suggest manual checks from saved ports
  2) Enumerate detected services
  3) Enumerate all common web ports
  4) Enumerate one web port
  5) SMB enumeration
  6) LDAP enumeration
  b) Back
MENU
  read -r -p "enum> " choice
  case "$choice" in
    1) "$OSCP" suggest ;;
    2) confirm "Run service-aware enumeration now?" && "$OSCP" enum-all ;;
    3) "$OSCP" web-all ;;
    4)
      if [[ -n "$SAVED_TARGET" ]]; then
        ip="$SAVED_TARGET"
      else
        ip="$(prompt "Target IP" "")"
      fi
      [[ -n "$ip" ]] || { echo "[-] Set a target first."; return; }
      port="$(prompt "Port" "80")"
      domain="$SAVED_DOMAIN"
      "$OSCP" enum-web "$ip" "$port" "$domain"
      ;;
    5) "$OSCP" enum-smb ;;
    6) "$OSCP" enum-ldap ;;
    b|B|"") return ;;
    *) echo "[-] Unknown option" ;;
  esac
}

log_menu() {
  local choice value service user secret source
  cat <<'MENU'
  1) Add a concise note
  2) Log a structured credential
  3) Log a hash
  4) Set current focus
  b) Back
MENU
  read -r -p "log> " choice
  case "$choice" in
    1) value="$(prompt "Note" "")"; [[ -n "$value" ]] && "$OSCP" note "$value" ;;
    2)
      service="$(prompt "Service" "smb")"
      user="$(prompt "Username" "")"
      read -r -s -p "Password or hash: " secret; echo
      source="$(prompt "Source" "manual")"
      [[ -n "$service" && -n "$user" && -n "$secret" ]] && "$OSCP" add-cred "$service" "$user" "$secret" "$source"
      ;;
    3) value="$(prompt "Hash and source/type" "")"; [[ -n "$value" ]] && "$OSCP" hash "$value" ;;
    4) value="$(prompt "What are you working on now?" "")"; "$OSCP" focus "$value" ;;
    b|B|"") return ;;
    *) echo "[-] Unknown option" ;;
  esac
}

ad_workflow() {
  local default_ip="" default_domain="" ip domain user secret principal
  load_saved_context
  default_ip="$SAVED_DC"
  default_domain="$SAVED_DOMAIN"
  if [[ -n "$default_ip" ]]; then
    ip="$default_ip"
  else
    if [[ ! -s "$ROOT_DIR/scans/live_hosts.txt" ]]; then
      echo "[-] No discovered hosts yet. Use Scanning -> Discover hosts first."
      return
    fi
    "$OSCP" ad-candidates || return
    ip="$(prompt "DC IP from the discovered list" "")"
    [[ -n "$ip" ]] || return
    "$OSCP" set-dc "$ip" || return
  fi
  if [[ -n "$default_domain" ]]; then
    domain="$default_domain"
  else
    domain="$(prompt "Domain FQDN" "")"
  fi
  user="$(prompt "Supplied username" "")"
  [[ -n "$ip" && -n "$domain" && -n "$user" ]] || { echo "[-] Selected DC, domain, and username are required."; return; }
  "$OSCP" set-domain "$domain" >/dev/null || return
  read -r -s -p "Supplied password (blank = command placeholders): " secret; echo
  "$OSCP" profile ad >/dev/null
  if [[ -n "$secret" ]] && confirm "Log this supplied credential in the workspace?"; then
    principal="${domain}\\${user}"
    "$OSCP" add-cred ad "$principal" "$secret" "exam supplied / presumed breach"
  fi
  if [[ -n "$secret" ]]; then
    "$OSCP" ad "$ip" "$domain" "$user" "$secret"
  else
    OSCP_AD_NO_PROMPT=1 "$OSCP" ad "$ip" "$domain" "$user"
  fi
}

post_shell_menu() {
  local choice file
  cat <<'MENU'
  1) Linux post-shell checklist
  2) Windows post-shell checklist
  3) Windows privilege triage
  4) Stage post-shell tools
  5) Open Windows privilege-escalation playbook
  b) Back
MENU
  read -r -p "post-shell> " choice
  case "$choice" in
    1) "$OSCP" loot-linux ;;
    2) "$OSCP" loot-windows ;;
    3) file="$(prompt "Saved whoami /priv file (optional)" "")"; "$OSCP" win-privs "$file" ;;
    4) "$OSCP" tools stage ;;
    5) "$OSCP" reference windows ;;
    b|B|"") return ;;
    *) echo "[-] Unknown option" ;;
  esac
}

evidence_menu() {
  local choice label type
  cat <<'MENU'
  1) Capture indexed screenshot
  2) Create local/proof checklist
  3) Show score tracker
  4) Mark a task done
  b) Back
MENU
  read -r -p "evidence> " choice
  case "$choice" in
    1) label="$(prompt "Evidence label" "proof with ip visible")"; "$OSCP" screenshot "$label" ;;
    2) type="$(prompt "Type (local or proof)" "local")"; "$OSCP" proof "$type" ;;
    3) "$OSCP" score ;;
    4) "$OSCP" task list; echo; type="$(prompt "Task id" "")"; [[ -n "$type" ]] && "$OSCP" task done "$type" ;;
    b|B|"") return ;;
    *) echo "[-] Unknown option" ;;
  esac
}

tracking_menu() {
  local choice value
  cat <<'MENU'
  1) Set phase
  2) Set focus
  3) Mark task done
  4) Mark task skipped
  5) Reopen task
  6) List tasks
  b) Back
MENU
  read -r -p "track> " choice
  case "$choice" in
    1) value="$(prompt "Phase (setup/enum/foothold/privesc/lateral/proof/report/done)" "enum")"; "$OSCP" phase "$value" ;;
    2) value="$(prompt "Current focus" "")"; "$OSCP" focus "$value" ;;
    3) "$OSCP" task list; value="$(prompt "Task id" "")"; "$OSCP" task done "$value" ;;
    4) "$OSCP" task list; value="$(prompt "Task id" "")"; "$OSCP" task skip "$value" ;;
    5) "$OSCP" task list; value="$(prompt "Task id" "")"; "$OSCP" task undo "$value" ;;
    6) "$OSCP" task list ;;
    b|B|"") return ;;
    *) echo "[-] Unknown option" ;;
  esac
}

reference_menu() {
  local choice
  cat <<'MENU'
  1) Active Directory playbook
  2) Windows privilege escalation
  3) Lateral movement
  4) Advanced AD decision points
  b) Back
MENU
  read -r -p "reference> " choice
  case "$choice" in
    1) "$OSCP" reference ad ;;
    2) "$OSCP" reference windows ;;
    3) "$OSCP" reference lateral ;;
    4) "$OSCP" reference advanced-ad ;;
    b|B|"") return ;;
    *) echo "[-] Unknown option" ;;
  esac
}

while true; do
  load_saved_context
  printf '\033[H\033[2J'
  echo "${CYAN}${BOLD}OSCP GUIDED WORKSPACE${RESET}  $(basename "$ROOT_DIR")"
  echo
  "$OSCP" guide
  cat <<MENU

${BOLD}Choose one small next action:${RESET}
  1) Set up scope and profile
  2) Scanning
  3) Service enumeration
  4) Notes, credentials, hashes, and focus
  5) AD presumed-breach workflow
  6) Post-shell and privilege escalation
  7) Evidence, proof, and scoring
  8) Progress tracking
  9) Reference playbooks
  a) Advanced 38-option helper
  q) Quit
MENU
  read -r -p "guided> " choice
  case "$choice" in
    1) setup_workspace ;;
    2) scan_menu ;;
    3) enum_menu ;;
    4) log_menu ;;
    5) ad_workflow ;;
    6) post_shell_menu ;;
    7) evidence_menu ;;
    8) tracking_menu ;;
    9) reference_menu ;;
    a|A) [[ -x "$ADVANCED" ]] && "$ADVANCED" ;;
    q|Q|"") echo "bye."; exit 0 ;;
    *) echo "${YELLOW}Unknown option.${RESET}" ;;
  esac
  pause
done
