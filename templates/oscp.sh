#!/usr/bin/env bash
# oscp.sh - OSCP workspace runner.
#
# This script is intended for authorised training labs and exam-scoped targets.
# It favours repeatable enumeration, saved evidence, and simple commands you can
# trust under pressure.

set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCANS_DIR="$ROOT_DIR/scans"
DISC_DIR="$SCANS_DIR/discovery"
NMAP_DIR="$SCANS_DIR/nmap"
VULN_DIR="$SCANS_DIR/vuln"
WEB_DIR="$ROOT_DIR/web"
SMB_DIR="$ROOT_DIR/smb"
FTP_DIR="$ROOT_DIR/ftp"
LDAP_DIR="$ROOT_DIR/ldap"
RPC_DIR="$ROOT_DIR/rpc"
SNMP_DIR="$ROOT_DIR/snmp"
WINRM_DIR="$ROOT_DIR/winrm"
AD_DIR="$ROOT_DIR/ad"
LOOT_DIR="$ROOT_DIR/loot"
CREDS_DIR="$ROOT_DIR/creds"
PROOF_DIR="$ROOT_DIR/proof"
TRANSFER_DIR="$ROOT_DIR/transfer"
SCREENSHOTS_DIR="$ROOT_DIR/screenshots"
EVIDENCE_DIR="$ROOT_DIR/evidence"
LIVE_HOSTS="$SCANS_DIR/live_hosts.txt"
ENV_FILE="$ROOT_DIR/.oscp_env"
HOSTS_FILE="$ROOT_DIR/hosts.txt"
CREDS_FILE="$ROOT_DIR/creds.txt"
CREDS_CSV="$CREDS_DIR/creds.csv"
NOTES_FILE="$ROOT_DIR/notes.md"
HASHES_FILE="$LOOT_DIR/hashes.txt"
COMMANDS_LOG="$ROOT_DIR/commands.log"
SCORING_FILE="$ROOT_DIR/reports/scoring.md"
SCREENSHOT_INDEX="$EVIDENCE_DIR/screenshots.md"

mkdir -p "$DISC_DIR" "$NMAP_DIR" "$VULN_DIR" "$WEB_DIR" "$SMB_DIR" "$FTP_DIR" \
  "$LDAP_DIR" "$RPC_DIR" "$SNMP_DIR" "$WINRM_DIR" "$AD_DIR" "$LOOT_DIR" \
  "$CREDS_DIR" "$PROOF_DIR" "$TRANSFER_DIR" "$SCREENSHOTS_DIR" "$EVIDENCE_DIR"

DEFAULT_DISCOVERY_PORTS="53,80,88,135,139,389,443,445,464,593,636,3268,3269,3389,5985,5986"
DEFAULT_DISCOVERY_PORTS_WIDE="21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,3000,3128,3306,3389,5000,5432,5601,5900,5985,5986,6379,8000,8008,8080,8081,8443,8888,9000,9090,9200,11211,27017,50000"
COMMON_WEB_PORTS="80 81 443 444 591 593 800 801 808 880 1080 3000 3001 5000 5001 5601 7001 8000 8008 8080 8081 8082 8088 8090 8443 8834 8888 8983 9000 9043 9090 9200 9443 10000 10443 50000"

ts() { date +"%Y%m%d_%H%M%S"; }
die() { echo "[-] $*" >&2; exit 1; }
warn() { echo "[!] $*" >&2; }
info() { echo "[*] $*"; }
ok() { echo "[+] $*"; }

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

require_ipv4() {
  local value="${1:-}"
  local label="${2:-IP}"
  is_ipv4 "$value" || die "Invalid $label: $value"
}

require_cidr() {
  local value="${1:-}"
  is_cidr "$value" || die "Invalid CIDR: $value"
}

infer_subnet_24() {
  local ip="${1:-}"
  is_ipv4 "$ip" || return 1
  echo "${ip%.*}.0/24"
}

strip_outer_quotes() {
  local val="${1:-}"
  if [[ "${val:0:1}" == '"' && "${val: -1}" == '"' ]]; then
    val="${val:1:${#val}-2}"
  elif [[ "${val:0:1}" == "'" && "${val: -1}" == "'" ]]; then
    val="${val:1:${#val}-2}"
  fi
  printf '%s\n' "$val"
}

normalize_domain() {
  local domain="${1:-}"
  domain="${domain#http://}"
  domain="${domain#https://}"
  domain="${domain%%/*}"
  domain="${domain%%:*}"
  domain="${domain#.}"
  domain="${domain%.}"
  printf '%s\n' "$domain"
}

default_vhost_wordlist() {
  local path
  for path in \
    "${OSCP_VHOST_WORDLIST:-}" \
    /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    /usr/share/seclists/Discovery/DNS/namelist.txt \
    /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt; do
    [[ -n "$path" && -f "$path" ]] && { printf '%s\n' "$path"; return 0; }
  done
  return 1
}

load_env_file() {
  [[ -f "$ENV_FILE" ]] || return 0

  local line key val
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    val="${line#*=}"
    val="$(strip_outer_quotes "$val")"

    case "$key" in
      OSCP_TARGET)
        if is_ipv4 "$val"; then OSCP_TARGET="$val"; else warn "Ignoring invalid OSCP_TARGET in .oscp_env"; fi
        ;;
      OSCP_SUBNET)
        if is_cidr "$val"; then OSCP_SUBNET="$val"; else warn "Ignoring invalid OSCP_SUBNET in .oscp_env"; fi
        ;;
      OSCP_WORDLIST)
        [[ -n "$val" ]] && OSCP_WORDLIST="$val"
        ;;
      OSCP_DOMAIN)
        [[ -n "$val" ]] && OSCP_DOMAIN="$val"
        ;;
      OSCP_VHOST_WORDLIST)
        [[ -n "$val" ]] && OSCP_VHOST_WORDLIST="$val"
        ;;
      OSCP_DISCOVERY_PORTS|OSCP_DISCOVERY_PORTS_WIDE)
        if [[ "$val" =~ ^[0-9,]+$ ]]; then
          printf -v "$key" '%s' "$val"
        else
          warn "Ignoring invalid $key in .oscp_env"
        fi
        ;;
    esac
  done < "$ENV_FILE"
}

save_env_file() {
  local target="${1:-}"
  local subnet="${2:-}"

  [[ -n "$target" ]] && require_ipv4 "$target" "target"
  [[ -n "$subnet" ]] && require_cidr "$subnet"

  {
    echo "# OSCP toolkit workspace state"
    [[ -n "$target" ]] && printf 'OSCP_TARGET=%s\n' "$target"
    [[ -n "$subnet" ]] && printf 'OSCP_SUBNET=%s\n' "$subnet"
    [[ -n "${OSCP_DOMAIN:-}" ]] && printf 'OSCP_DOMAIN=%s\n' "$OSCP_DOMAIN"
    printf 'OSCP_WORDLIST=%s\n' "${OSCP_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt}"
    printf 'OSCP_VHOST_WORDLIST=%s\n' "${OSCP_VHOST_WORDLIST:-/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt}"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  ok "Saved $ENV_FILE"
}

run_sudo() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

fix_scan_perms() {
  local base="${1:?missing nmap output base}"
  local owner="${SUDO_USER:-${USER:-}}"
  [[ -n "$owner" ]] || return 0

  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    chown "$owner:$owner" "${base}".* 2>/dev/null || true
  else
    sudo chown "$owner:$owner" "${base}".* 2>/dev/null || true
  fi
}

command_line() {
  printf '$'
  printf ' %q' "$@"
  printf '\n'
}

log_command() {
  local outfile="${1:-}"
  shift || true
  [[ "$#" -gt 0 ]] || return 0

  {
    printf '[%s] ' "$(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    command_line "$@"
    [[ -n "$outfile" ]] && printf '  output: %s\n' "${outfile#$ROOT_DIR/}"
  } >> "$COMMANDS_LOG"
}

run_capture() {
  local label="${1:?label required}"
  local outfile="${2:?output file required}"
  shift 2

  mkdir -p "$(dirname "$outfile")"
  info "$label -> $outfile"
  log_command "$outfile" "$@"

  set +e
  {
    command_line "$@"
    echo
    "$@"
  } > "$outfile" 2>&1
  local rc=$?
  set -e

  if (( rc != 0 )); then
    echo >> "$outfile"
    echo "[exit-code: $rc]" >> "$outfile"
    warn "$label exited with code $rc; output still saved"
  fi
  return 0
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

append_new_ips_to_hosts_txt() {
  local src_file="${1:?source file required}"
  touch "$HOSTS_FILE"
  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    if ! awk -v ip="$ip" '$1==ip {found=1} END{exit found?0:1}' "$HOSTS_FILE"; then
      printf "%-15s  # <hostname/role>\n" "$ip" >> "$HOSTS_FILE"
    fi
  done < "$src_file"
}

note() {
  local msg="$*"
  [[ -n "$msg" ]] || die "note needs a message"
  touch "$NOTES_FILE"
  local line="- $(date +"%H:%M") - $msg"

  if grep -q '<!--OSCP_LOG-->' "$NOTES_FILE"; then
    local tmp
    tmp="$(mktemp "$ROOT_DIR/.notes.XXXXXX")"
    awk -v ins="$line" '
      { print }
      $0=="<!--OSCP_LOG-->" { print ins }
    ' "$NOTES_FILE" > "$tmp"
    mv "$tmp" "$NOTES_FILE"
  else
    { echo; echo "## Quick Log"; echo "$line"; } >> "$NOTES_FILE"
  fi
  ok "Noted: $line"
}

cred() {
  local entry="$*"
  [[ -n "$entry" ]] || die "cred needs an entry, e.g. 'bob:Password123 (SMB on 192.168.56.10)'"
  touch "$CREDS_FILE"
  echo "$(date +"%Y-%m-%d %H:%M") - $entry" >> "$CREDS_FILE"
  ok "Credential logged"
  note "Cred: $entry"
}

add_cred_structured() {
  local service="${1:-}"
  local user="${2:-}"
  local secret="${3:-}"
  local source="${4:-manual}"

  [[ -n "$service" && -n "$user" && -n "$secret" ]] || die "usage: add-cred SERVICE USER PASSWORD_OR_HASH [SOURCE]"
  load_env_file
  local target="${OSCP_TARGET:-TARGET}"

  ensure_creds_csv
  {
    csv_cell "$(date -Iseconds)"; printf ','
    csv_cell "$service"; printf ','
    csv_cell "$user"; printf ','
    csv_cell "$secret"; printf ','
    csv_cell "$source"; printf ','
    csv_cell "no"; printf ','
    csv_cell ""
    printf '\n'
  } >> "$CREDS_CSV"

  echo "$(date +"%Y-%m-%d %H:%M") - $service - $user:$secret ($source)" >> "$CREDS_FILE"
  note "Cred: $service $user from $source"

  ok "Credential logged:"
  echo "  $CREDS_CSV"
  echo
  cat <<EOF
[TRY MANUAL REUSE]
ssh '$user@$target'
smbclient -L '//$target' -U '$user%$secret'
netexec smb '$target' -u '$user' -p '$secret'
netexec winrm '$target' -u '$user' -p '$secret'
evil-winrm -i '$target' -u '$user' -p '$secret'
EOF
}

guess_hash_type() {
  local entry="$*"
  [[ -n "$entry" ]] || die "hash-guess needs a hash value"

  local h="${entry%%[[:space:]]*}"
  h="${h#<}"
  h="${h%>}"

  echo "[HASH GUESS]"
  if [[ "$h" =~ ^\$krb5tgs\$23\$ ]]; then
    echo "Likely Kerberoast TGS"
    echo "hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt"
    echo "john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hash.txt"
  elif [[ "$h" =~ ^\$krb5asrep\$23\$ ]]; then
    echo "Likely AS-REP roast"
    echo "hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt"
    echo "john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt hash.txt"
  elif [[ "$h" =~ ^\$2[aby]\$ ]]; then
    echo "Likely bcrypt"
    echo "hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt"
    echo "john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt"
  elif [[ "$h" =~ ^\$6\$ ]]; then
    echo "Likely SHA-512 crypt"
    echo "hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt"
    echo "john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt"
  elif [[ "$h" =~ ^\$P\$|^\$H\$ ]]; then
    echo "Likely phpass / WordPress"
    echo "hashcat -m 400 hash.txt /usr/share/wordlists/rockyou.txt"
    echo "john --format=phpass --wordlist=/usr/share/wordlists/rockyou.txt hash.txt"
  elif [[ "$h" =~ ^[A-Fa-f0-9]{32}$ ]]; then
    echo "Could be raw MD5 or NTLM depending on context"
    echo "MD5 : hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt"
    echo "NTLM: hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt"
  elif [[ "$h" =~ ^[A-Fa-f0-9]{40}$ ]]; then
    echo "Likely SHA1"
    echo "hashcat -m 100 hash.txt /usr/share/wordlists/rockyou.txt"
  elif [[ "$h" =~ ^[A-Fa-f0-9]{64}$ ]]; then
    echo "Likely SHA256"
    echo "hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt"
  else
    echo "Unknown from pattern alone. Use context plus hashid/name-that-hash manually."
  fi
}

log_hash() {
  local entry="$*"
  [[ -n "$entry" ]] || die "hash needs the hash text"
  touch "$HASHES_FILE"
  echo "$(date +"%Y-%m-%d %H:%M") - $entry" >> "$HASHES_FILE"
  ok "Hash logged to $HASHES_FILE"
  note "Hash logged ($(printf '%s' "$entry" | head -c 40)...)"
  echo
  guess_hash_type "$entry"
}

confirm_scope() {
  local scope="${1:-}"
  echo "[*] Workspace : $ROOT_DIR"
  echo "[*] Scope     : $scope"
  echo "[*] Target    : ${OSCP_TARGET:-<none>}"
  echo "[*] Reminder  : continue only for authorised lab/exam scope"
  [[ "${OSCP_YES:-}" == "1" ]] && return 0
  read -r -p "[?] Proceed? [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]] || die "Aborted"
}

target_or_default() {
  local ip_arg="${1:-}"
  load_env_file
  local target="${ip_arg:-${OSCP_TARGET:-${TARGET:-}}}"
  [[ -n "$target" ]] || die "No target. Set OSCP_TARGET or pass an IP."
  require_ipv4 "$target" "target"
  printf '%s\n' "$target"
}

ports_file_for() {
  local target="${1:?target required}"
  printf '%s/%s_open_ports.txt\n' "$NMAP_DIR" "$target"
}

get_ports_for_target() {
  local target="${1:?target required}"
  local file
  file="$(ports_file_for "$target")"
  [[ -s "$file" ]] || return 1
  tr -d '[:space:]' < "$file"
}

ports_as_lines() {
  local ports="${1:-}"
  [[ -n "$ports" ]] || return 0
  tr ',' '\n' <<< "$ports" | awk 'NF {print $1}' | sort -n -u
}

sanitize_label() {
  local raw="${1:-screenshot}"
  local clean
  clean="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/_/g; s/^_+//; s/_+$//')"
  [[ -n "$clean" ]] || clean="screenshot"
  printf '%s\n' "$clean"
}

md_cell() {
  local value="${1:-}"
  value="${value//|/\\|}"
  value="${value//$'\n'/ }"
  printf '%s\n' "$value"
}

csv_cell() {
  local value="${1:-}"
  value="${value//\"/\"\"}"
  printf '"%s"' "$value"
}

ensure_creds_csv() {
  mkdir -p "$CREDS_DIR"
  if [[ ! -f "$CREDS_CSV" ]]; then
    echo 'time,service,user,password_or_hash,source,tested,notes' > "$CREDS_CSV"
    chmod 600 "$CREDS_CSV"
  fi
}

has_tcp_port() {
  local ports="${1:-}"
  local needle="${2:?port required}"
  grep -qx "$needle" < <(ports_as_lines "$ports")
}

is_web_port() {
  local port="${1:-}"
  [[ " $COMMON_WEB_PORTS " == *" $port "* ]]
}

url_for_port() {
  local ip="${1:?ip required}"
  local port="${2:?port required}"
  local proto="http"
  case "$port" in
    443|4443|8443|8834|9443|10443) proto="https" ;;
  esac
  printf '%s://%s:%s\n' "$proto" "$ip" "$port"
}

usage() {
  cat <<'USAGE'
oscp.sh - OSCP workspace runner

Setup:
  ./scripts/oscp.sh set-target <IP> [CIDR]
  ./scripts/oscp.sh status

Discovery and scanning:
  ./scripts/oscp.sh discover [CIDR]            # AD-focused live-host sweep
  ./scripts/oscp.sh discover-wide [CIDR]       # wider live-host sweep
  ./scripts/oscp.sh nmap-live                  # -sC -sV against live_hosts.txt
  ./scripts/oscp.sh nmap-full [IP]             # full TCP scan, saves port list
  ./scripts/oscp.sh nmap-deep [IP]             # scripts/versions on found ports
  ./scripts/oscp.sh nmap-udp [IP]              # top-100 UDP
  ./scripts/oscp.sh nmap-vuln [IP]             # optional nmap vuln scripts
  ./scripts/oscp.sh ports [IP]                 # show saved open TCP ports

Service enumeration:
  ./scripts/oscp.sh enum-all [IP]              # service enum based on nmap-full
  ./scripts/oscp.sh suggest [IP]               # print next manual checks
  ./scripts/oscp.sh enum-web <IP> <PORT> [DOMAIN]
  ./scripts/oscp.sh web-all [IP] [DOMAIN]
  ./scripts/oscp.sh enum-smb <IP>
  ./scripts/oscp.sh enum-ftp <IP> [PORT]
  ./scripts/oscp.sh enum-ssh <IP> [PORT]
  ./scripts/oscp.sh enum-rpc <IP>
  ./scripts/oscp.sh enum-ldap <IP>
  ./scripts/oscp.sh enum-snmp <IP>
  ./scripts/oscp.sh enum-winrm <IP>

Workflow helpers:
  ./scripts/oscp.sh quick [IP]                 # nmap-full, nmap-deep, enum-all
  ./scripts/oscp.sh ad [IP]                    # AD command blocks/checklist
  ./scripts/oscp.sh loot-linux                 # Linux post-shell checklist
  ./scripts/oscp.sh loot-windows               # Windows post-shell checklist
  ./scripts/oscp.sh proof [local|proof]        # proof screenshot/checklist file
  ./scripts/oscp.sh stuck                      # anti-tunnel-vision checklist
  ./scripts/oscp.sh score                      # scoring tracker template
  ./scripts/oscp.sh serve [PORT]               # HTTP server from transfer/
  ./scripts/oscp.sh listener <PORT>            # nc listener, rlwrap if present
  ./scripts/oscp.sh loot-search <TERM>
  ./scripts/oscp.sh screenshot ["LABEL"] [IP]    # capture indexed evidence

Logging:
  ./scripts/oscp.sh note "message"
  ./scripts/oscp.sh cred "user:pass (source)"
  ./scripts/oscp.sh add-cred SERVICE USER PASS_OR_HASH [SOURCE]
  ./scripts/oscp.sh hash "<hash> (type/source)"       # log and suggest crack mode
  ./scripts/oscp.sh hash-guess "<hash>"               # suggest crack mode only

Environment:
  .oscp_env supports OSCP_TARGET, OSCP_SUBNET, OSCP_DOMAIN, OSCP_WORDLIST,
  OSCP_VHOST_WORDLIST, OSCP_DISCOVERY_PORTS, OSCP_DISCOVERY_PORTS_WIDE.
  OSCP_YES=1 skips confirmation prompts.
USAGE
}

_run_discover() {
  local subnet_arg="${1:-}"
  local ports="${2:?ports required}"

  load_env_file
  local target="${OSCP_TARGET:-${TARGET:-}}"
  local subnet="${subnet_arg:-${OSCP_SUBNET:-${SUBNET:-}}}"
  if [[ -z "$subnet" && -n "$target" ]]; then
    subnet="$(infer_subnet_24 "$target" || true)"
  fi
  [[ -n "$subnet" ]] || die "No subnet. Set OSCP_SUBNET or OSCP_TARGET."
  require_cidr "$subnet"
  [[ "$ports" =~ ^[0-9,]+$ ]] || die "Invalid port list: $ports"

  confirm_scope "$subnet"

  local stamp out
  stamp="$(ts)"
  out="$DISC_DIR/tcp_discovery_${stamp}"

  info "Discovery ports: $ports"
  run_sudo nmap -Pn -n -sS -T4 --open --min-rate 2000 -p "$ports" "$subnet" -oA "$out"
  fix_scan_perms "$out"

  awk '/Status: Up/{print $2}' "${out}.gnmap" | sort -u | tee "$LIVE_HOSTS" >/dev/null
  append_new_ips_to_hosts_txt "$LIVE_HOSTS"
  note "Discovery $subnet -> $(basename "$out").[nmap|gnmap|xml]"
  ok "Discovery saved: ${out}.[nmap|gnmap|xml]"
  ok "Live hosts: $LIVE_HOSTS"
}

discover() {
  local ports="${OSCP_DISCOVERY_PORTS:-$DEFAULT_DISCOVERY_PORTS}"
  _run_discover "${1:-}" "$ports"
}

discover_wide() {
  local ports="${OSCP_DISCOVERY_PORTS_WIDE:-$DEFAULT_DISCOVERY_PORTS_WIDE}"
  _run_discover "${1:-}" "$ports"
}

nmap_live() {
  load_env_file
  [[ -s "$LIVE_HOSTS" ]] || die "$LIVE_HOSTS missing or empty. Run discover first."
  local stamp out
  stamp="$(ts)"
  out="$NMAP_DIR/live_scv_top1000_${stamp}"
  run_sudo nmap -sC -sV -Pn -n --reason -iL "$LIVE_HOSTS" -oA "$out"
  fix_scan_perms "$out"
  note "Nmap live -> $(basename "$out").[nmap|gnmap|xml]"
  ok "Live scan saved: ${out}.[nmap|gnmap|xml]"
}

nmap_full() {
  local target
  target="$(target_or_default "${1:-}")"

  local stamp out ports_file
  stamp="$(ts)"
  out="$NMAP_DIR/${target}_full_${stamp}"
  ports_file="$(ports_file_for "$target")"

  info "Full TCP scan on $target"
  run_sudo nmap -p- -Pn -n -T4 --min-rate 2000 --open --reason "$target" -oA "$out"
  fix_scan_perms "$out"

  awk -F'[ /]' '/^[0-9]+\/tcp +open/{print $1}' "${out}.nmap" | paste -sd, - > "$ports_file"
  local found
  found="$(tr -d '[:space:]' < "$ports_file")"

  ok "Open TCP ports: ${found:-<none>}"
  ok "Saved port list: $ports_file"
  note "Nmap full $target -> ports: ${found:-<none>}"
}

nmap_deep() {
  local target
  target="$(target_or_default "${1:-}")"

  local ports=""
  if ports="$(get_ports_for_target "$target")"; then
    info "Using saved ports: $ports"
  else
    warn "No saved full-scan ports for $target. Falling back to top 1000."
  fi

  local stamp out
  stamp="$(ts)"
  out="$NMAP_DIR/${target}_deep_${stamp}"
  if [[ -n "$ports" ]]; then
    run_sudo nmap -sC -sV -A --version-all -Pn -n --reason -p "$ports" "$target" -oA "$out"
  else
    run_sudo nmap -sC -sV -A --version-all -Pn -n --reason "$target" -oA "$out"
  fi
  fix_scan_perms "$out"
  note "Nmap deep $target -> $(basename "$out").[nmap|gnmap|xml]"
  ok "Deep scan saved: ${out}.[nmap|gnmap|xml]"
}

nmap_udp() {
  local target
  target="$(target_or_default "${1:-}")"
  local stamp out
  stamp="$(ts)"
  out="$NMAP_DIR/${target}_udp100_${stamp}"
  info "UDP top-100 scan on $target"
  run_sudo nmap -sU --top-ports 100 -Pn -n --reason "$target" -oA "$out"
  fix_scan_perms "$out"
  note "Nmap UDP $target -> $(basename "$out").[nmap|gnmap|xml]"
  ok "UDP scan saved: ${out}.[nmap|gnmap|xml]"
}

nmap_vuln() {
  local target
  target="$(target_or_default "${1:-}")"
  local ports=""
  ports="$(get_ports_for_target "$target" || true)"
  [[ -n "$ports" ]] || die "No saved ports for $target. Run nmap-full first."

  local stamp out
  stamp="$(ts)"
  out="$VULN_DIR/${target}_vuln_${stamp}"
  info "Optional nmap vuln scripts on $target ports $ports"
  run_sudo nmap -sV --script vuln -Pn -n -p "$ports" "$target" -oA "$out"
  fix_scan_perms "$out"
  note "Nmap vuln $target -> $(basename "$out").[nmap|gnmap|xml]"
  ok "Vuln scan saved: ${out}.[nmap|gnmap|xml]"
}

show_ports() {
  local target ports
  target="$(target_or_default "${1:-}")"
  if ports="$(get_ports_for_target "$target")"; then
    echo "$ports"
  else
    die "No saved port list for $target. Run nmap-full first."
  fi
}

web_triage() {
  local ip="${1:-}"
  local port="${2:-}"
  local domain_arg="${3:-}"
  [[ -n "$ip" && -n "$port" ]] || die "usage: enum-web <IP> <PORT>"
  require_ipv4 "$ip" "web target"
  [[ "$port" =~ ^[0-9]+$ ]] || die "Invalid port: $port"

  load_env_file

  local url outdir wordlist vhost_wordlist domain
  url="$(url_for_port "$ip" "$port")"
  outdir="$WEB_DIR/${ip}_${port}"
  mkdir -p "$outdir"
  domain="$(normalize_domain "${domain_arg:-${OSCP_DOMAIN:-}}")"

  wordlist="${OSCP_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt}"
  if [[ ! -f "$wordlist" && -f /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt ]]; then
    wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
  elif [[ ! -f "$wordlist" && -f /usr/share/wordlists/dirb/common.txt ]]; then
    wordlist="/usr/share/wordlists/dirb/common.txt"
  fi

  info "Web triage: $url"
  info "Output: $outdir"
  [[ -n "$domain" ]] && info "Domain: $domain"

  local -a pids=()
  if need_cmd whatweb; then
    ( whatweb -a 3 "$url" > "$outdir/whatweb.txt" 2>&1 ) &
    pids+=("$!")
  else
    warn "whatweb not found; skipping fingerprint"
  fi

  if need_cmd nikto; then
    ( nikto -h "$url" -nointeractive > "$outdir/nikto.txt" 2>&1 ) &
    pids+=("$!")
  else
    warn "nikto not found; skipping web misconfiguration checks"
  fi

  ( curl -skI --max-time 15 "$url" > "$outdir/headers.txt" 2>&1 ) &
  pids+=("$!")

  run_capture "HTTP nmap scripts" "$outdir/nmap_http_scripts.txt" \
    run_sudo nmap -sV -Pn -n -p "$port" --script http-title,http-server-header,http-methods,http-robots.txt "$ip"

  if [[ -f "$wordlist" ]]; then
    info "Wordlist: $wordlist"
    if need_cmd feroxbuster; then
      ( feroxbuster -u "$url" -w "$wordlist" -k -q -t 30 -o "$outdir/ferox.txt" > "$outdir/ferox.console.txt" 2>&1 ) &
      pids+=("$!")
    elif need_cmd ffuf; then
      ( ffuf -u "$url/FUZZ" -w "$wordlist" -ac -k -of csv -o "$outdir/ffuf.csv" > "$outdir/ffuf.console.txt" 2>&1 ) &
      pids+=("$!")
    elif need_cmd gobuster; then
      ( gobuster dir -u "$url" -w "$wordlist" -k -q -t 30 -o "$outdir/gobuster.txt" > "$outdir/gobuster.console.txt" 2>&1 ) &
      pids+=("$!")
    else
      warn "No feroxbuster, ffuf, or gobuster found; skipping content discovery"
    fi
  else
    warn "No usable wordlist found; skipping content discovery"
  fi

  if need_cmd ffuf; then
    if vhost_wordlist="$(default_vhost_wordlist)"; then
      info "Vhost wordlist: $vhost_wordlist"
      ( ffuf -u "$url/" -H "Host: FUZZ" -w "$vhost_wordlist" -ac -of csv -o "$outdir/ffuf_vhosts.csv" > "$outdir/ffuf_vhosts.console.txt" 2>&1 ) &
      pids+=("$!")

      if [[ -n "$domain" ]]; then
        ( ffuf -u "$url/" -H "Host: FUZZ.$domain" -w "$vhost_wordlist" -ac -of csv -o "$outdir/ffuf_subdomains.csv" > "$outdir/ffuf_subdomains.console.txt" 2>&1 ) &
        pids+=("$!")
      else
        warn "No OSCP_DOMAIN or enum-web domain argument; skipping FUZZ.<domain> subdomain checks"
      fi
    else
      warn "No usable DNS/vhost wordlist found; skipping ffuf vhost checks"
    fi
  else
    warn "ffuf not found; skipping vhost and subdomain checks"
  fi

  local pid
  for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  note "Web enum $url -> $outdir"
  ok "Web triage complete: $outdir"
}

web_all() {
  local target ports port domain any=0
  target="$(target_or_default "${1:-}")"
  domain="$(normalize_domain "${2:-${OSCP_DOMAIN:-}}")"
  ports="$(get_ports_for_target "$target" || true)"
  [[ -n "$ports" ]] || die "No saved port list for $target. Run nmap-full first."

  while IFS= read -r port; do
    if is_web_port "$port"; then
      any=1
      web_triage "$target" "$port" "$domain"
    fi
  done < <(ports_as_lines "$ports")

  [[ "$any" -eq 1 ]] || warn "No common web ports found in saved port list"
}

enum_smb() {
  local ip="${1:-}"
  require_ipv4 "$ip" "SMB target"
  local outdir="$SMB_DIR/$ip"
  mkdir -p "$outdir"

  need_cmd smbclient && run_capture "SMB anonymous share list" "$outdir/smbclient_anonymous.txt" smbclient -L "//$ip/" -N
  need_cmd smbmap && run_capture "SMB map anonymous" "$outdir/smbmap_anonymous.txt" smbmap -H "$ip" -u "" -p ""
  need_cmd enum4linux-ng && run_capture "enum4linux-ng full" "$outdir/enum4linux-ng.txt" enum4linux-ng -A "$ip"

  if need_cmd netexec; then
    run_capture "netexec smb anonymous" "$outdir/netexec_smb_anonymous.txt" netexec smb "$ip" -u "" -p "" --shares
  elif need_cmd crackmapexec; then
    run_capture "crackmapexec smb anonymous" "$outdir/crackmapexec_smb_anonymous.txt" crackmapexec smb "$ip" -u "" -p "" --shares
  else
    warn "netexec/crackmapexec not found; skipping SMB auth check"
  fi

  note "SMB enum $ip -> $outdir"
  ok "SMB enum complete: $outdir"
}

enum_ftp() {
  local ip="${1:-}"
  local port="${2:-21}"
  require_ipv4 "$ip" "FTP target"
  [[ "$port" =~ ^[0-9]+$ ]] || die "Invalid port: $port"
  local outdir="$FTP_DIR/${ip}_${port}"
  mkdir -p "$outdir"

  run_capture "FTP nmap scripts" "$outdir/nmap_ftp.txt" \
    run_sudo nmap -sV -Pn -n -p "$port" --script ftp-anon,ftp-syst,ftp-bounce "$ip"
  run_capture "FTP anonymous listing" "$outdir/curl_anon_listing.txt" \
    curl -sS --connect-timeout 10 "ftp://anonymous:anonymous@${ip}:${port}/"

  note "FTP enum $ip:$port -> $outdir"
  ok "FTP enum complete: $outdir"
}

enum_ssh() {
  local ip="${1:-}"
  local port="${2:-22}"
  require_ipv4 "$ip" "SSH target"
  [[ "$port" =~ ^[0-9]+$ ]] || die "Invalid port: $port"
  local outdir="$ROOT_DIR/output/ssh_${ip}_${port}"
  mkdir -p "$outdir"

  run_capture "SSH nmap scripts" "$outdir/nmap_ssh.txt" \
    run_sudo nmap -sV -Pn -n -p "$port" --script ssh-hostkey,ssh2-enum-algos "$ip"

  note "SSH enum $ip:$port -> $outdir"
  ok "SSH enum complete: $outdir"
}

enum_rpc() {
  local ip="${1:-}"
  require_ipv4 "$ip" "RPC target"
  local outdir="$RPC_DIR/$ip"
  mkdir -p "$outdir"

  need_cmd rpcclient && run_capture "RPC null session srvinfo" "$outdir/rpcclient_srvinfo.txt" rpcclient -U "" -N "$ip" -c srvinfo
  need_cmd rpcclient && run_capture "RPC null session users/groups" "$outdir/rpcclient_users_groups.txt" rpcclient -U "" -N "$ip" -c "enumdomusers; enumdomgroups"
  run_capture "RPC nmap scripts" "$outdir/nmap_rpc.txt" \
    run_sudo nmap -sV -Pn -n -p 111,135,139,445 --script rpc-grind,rpcinfo "$ip"

  note "RPC enum $ip -> $outdir"
  ok "RPC enum complete: $outdir"
}

enum_ldap() {
  local ip="${1:-}"
  require_ipv4 "$ip" "LDAP target"
  local outdir="$LDAP_DIR/$ip"
  mkdir -p "$outdir"

  need_cmd ldapsearch && run_capture "LDAP RootDSE" "$outdir/rootdse.txt" ldapsearch -x -H "ldap://$ip" -s base namingContexts defaultNamingContext dnsHostName
  run_capture "LDAP nmap scripts" "$outdir/nmap_ldap.txt" \
    run_sudo nmap -sV -Pn -n -p 389,636,3268,3269 --script ldap-rootdse,ldap-search "$ip"

  note "LDAP enum $ip -> $outdir"
  ok "LDAP enum complete: $outdir"
}

enum_snmp() {
  local ip="${1:-}"
  require_ipv4 "$ip" "SNMP target"
  local outdir="$SNMP_DIR/$ip"
  mkdir -p "$outdir"

  run_capture "SNMP nmap scripts" "$outdir/nmap_snmp.txt" \
    run_sudo nmap -sU -Pn -n -p 161 --script snmp-info,snmp-interfaces,snmp-processes "$ip"
  if need_cmd snmpwalk; then
    run_capture "SNMP public walk" "$outdir/snmpwalk_public.txt" snmpwalk -v2c -c public -t 5 -r 1 "$ip"
  else
    warn "snmpwalk not found; skipping public community walk"
  fi

  note "SNMP enum $ip -> $outdir"
  ok "SNMP enum complete: $outdir"
}

enum_winrm() {
  local ip="${1:-}"
  require_ipv4 "$ip" "WinRM target"
  local outdir="$WINRM_DIR/$ip"
  mkdir -p "$outdir"

  if need_cmd netexec; then
    run_capture "netexec winrm anonymous" "$outdir/netexec_winrm_anonymous.txt" netexec winrm "$ip" -u "" -p ""
  elif need_cmd crackmapexec; then
    run_capture "crackmapexec winrm anonymous" "$outdir/crackmapexec_winrm_anonymous.txt" crackmapexec winrm "$ip" -u "" -p ""
  else
    warn "netexec/crackmapexec not found; skipping WinRM auth check"
  fi
  run_capture "WinRM nmap scripts" "$outdir/nmap_winrm.txt" \
    run_sudo nmap -sV -Pn -n -p 5985,5986 "$ip"

  note "WinRM enum $ip -> $outdir"
  ok "WinRM enum complete: $outdir"
}

enum_all() {
  local target ports port
  target="$(target_or_default "${1:-}")"
  ports="$(get_ports_for_target "$target" || true)"
  [[ -n "$ports" ]] || die "No saved port list for $target. Run nmap-full first."

  info "Service-aware enumeration for $target ports: $ports"

  local did_smb=0 did_rpc=0 did_ldap=0 did_winrm=0 did_web=0

  while IFS= read -r port; do
    case "$port" in
      21) enum_ftp "$target" "$port" ;;
      22|2222) enum_ssh "$target" "$port" ;;
      111|135)
        if [[ "$did_rpc" -eq 0 ]]; then enum_rpc "$target"; did_rpc=1; fi
        ;;
      139)
        if [[ "$did_rpc" -eq 0 ]]; then enum_rpc "$target"; did_rpc=1; fi
        if [[ "$did_smb" -eq 0 ]]; then enum_smb "$target"; did_smb=1; fi
        ;;
      389|636|3268|3269)
        if [[ "$did_ldap" -eq 0 ]]; then enum_ldap "$target"; did_ldap=1; fi
        ;;
      445)
        if [[ "$did_smb" -eq 0 ]]; then enum_smb "$target"; did_smb=1; fi
        ;;
      5985|5986)
        if [[ "$did_winrm" -eq 0 ]]; then enum_winrm "$target"; did_winrm=1; fi
        ;;
      *)
        if is_web_port "$port"; then
          did_web=1
          web_triage "$target" "$port" "${OSCP_DOMAIN:-}"
        fi
        ;;
    esac
  done < <(ports_as_lines "$ports")

  [[ "$did_web" -eq 1 ]] || warn "No common web ports were enumerated"
  note "Enum-all complete for $target"
  ok "Enum-all complete"
}

latest_deep_scan_for() {
  local target="${1:?target required}"
  ls -t "$NMAP_DIR/${target}_deep_"*.nmap 2>/dev/null | head -n 1 || true
}

suggest_next() {
  local target ports port deep_scan
  target="$(target_or_default "${1:-}")"
  ports="$(get_ports_for_target "$target" || true)"
  [[ -n "$ports" ]] || die "No saved port list for $target. Run nmap-full first."
  deep_scan="$(latest_deep_scan_for "$target")"

  echo "============================================================"
  echo " Service-Based Next Actions"
  echo "============================================================"
  echo "Target: $target"
  echo "Open TCP ports: $ports"
  echo

  if [[ -n "$deep_scan" ]]; then
    echo "[OPEN SERVICE LINES]"
    grep -E "^[0-9]+/tcp[[:space:]]+open" "$deep_scan" || true
    echo
  else
    echo "[SCAN]"
    echo "Run deep scan before trusting service guesses:"
    echo "  ./scripts/oscp.sh nmap-deep $target"
    echo
  fi

  local -a web_ports=()
  while IFS= read -r port; do
    is_web_port "$port" && web_ports+=("$port")
  done < <(ports_as_lines "$ports")

  if (( ${#web_ports[@]} > 0 )); then
    echo "[WEB]"
    echo "Run:"
    for port in "${web_ports[@]}"; do
      echo "  ./scripts/oscp.sh enum-web $target $port"
    done
    cat <<'EOF'
Manual checks:
  - View source, robots.txt, sitemap.xml
  - Login pages, default creds, reset flows
  - Upload forms and extension bypass
  - LFI/path traversal and command injection checks
  - Manual SQL injection checks only
  - Backup/source disclosure: .bak .old .zip .tar.gz ~ .conf .config
  - CMS/version-specific research
Reminder: do not use SQLmap during the exam.

EOF
  fi

  if has_tcp_port "$ports" 445 || has_tcp_port "$ports" 139; then
    cat <<EOF
[SMB]
Run:
  ./scripts/oscp.sh enum-smb $target
Manual checks:
  - Null session and guest access
  - Readable shares and recursive downloads
  - Usernames in filenames or documents
  - Passwords in configs, scripts, backups, and Office files
  - Reuse every credential you find

EOF
  fi

  if has_tcp_port "$ports" 21; then
    cat <<EOF
[FTP]
Run:
  ./scripts/oscp.sh enum-ftp $target 21
Manual checks:
  ftp $target
  anonymous : anonymous
  anonymous : anonymous@
Look for writable directories, web-root overlap, configs, backups, and usernames.

EOF
  fi

  if has_tcp_port "$ports" 22 || has_tcp_port "$ports" 2222; then
    cat <<'EOF'
[SSH]
Low priority for initial access unless you have creds or a key.
Use later for stable shells, tunneling, and credential reuse.

EOF
  fi

  if has_tcp_port "$ports" 25; then
    cat <<EOF
[SMTP]
Possible user enum:
  smtp-user-enum -M VRFY -U users.txt -t $target

EOF
  fi

  if has_tcp_port "$ports" 53; then
    cat <<EOF
[DNS]
Try zone transfer if you know or can infer a domain:
  dig axfr @$target domain.local
  dig axfr @$target domain.htb

EOF
  fi

  if has_tcp_port "$ports" 88 || has_tcp_port "$ports" 389 || has_tcp_port "$ports" 636 || has_tcp_port "$ports" 3268 || has_tcp_port "$ports" 3269; then
    cat <<EOF
[ACTIVE DIRECTORY INDICATOR]
Run:
  ./scripts/oscp.sh ad $target
Look for domain name, users, shares, SPNs, AS-REP roastable users, reused creds, and BloodHound paths once you have creds.

EOF
  fi

  if has_tcp_port "$ports" 5985 || has_tcp_port "$ports" 5986; then
    cat <<EOF
[WINRM]
Run:
  ./scripts/oscp.sh enum-winrm $target
Use after creds:
  evil-winrm -i $target -u USER -p 'PASS'
  evil-winrm -i $target -u USER -H NTLM_HASH

EOF
  fi

  if has_tcp_port "$ports" 3306 || has_tcp_port "$ports" 5432 || has_tcp_port "$ports" 1433; then
    cat <<EOF
[DATABASE]
Check for default creds only when justified by the service and scope.
Prioritize web/app config leaks before guessing database passwords.

EOF
  fi

  cat <<'EOF'
[STUCK RULE]
If you spend 15 minutes on the same idea, change approach.
If you spend 2+ hours on one box with no meaningful progress, move on.
Run:
  ./scripts/oscp.sh stuck
EOF
}

ad_helper() {
  load_env_file
  local target="${1:-${OSCP_TARGET:-TARGET}}"
  if [[ "$target" != "TARGET" ]]; then
    require_ipv4 "$target" "AD target"
  fi
  mkdir -p "$AD_DIR"

  cat <<EOF
[AD ENUMERATION STARTERS]

Confirm domain:
  ldapsearch -x -H ldap://$target -s base namingContexts defaultNamingContext dnsHostName

With creds:
  netexec smb $target -u USER -p 'PASS'
  netexec smb $target -u USER -p 'PASS' --shares
  netexec smb $target -u USER -p 'PASS' --users
  netexec smb $target -u USER -p 'PASS' --groups

Kerberoast:
  impacket-GetUserSPNs DOMAIN/USER:'PASS' -dc-ip $target -request -outputfile ad/kerberoast.txt
  hashcat -m 13100 ad/kerberoast.txt /usr/share/wordlists/rockyou.txt

AS-REP roast:
  impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip $target -format hashcat -outputfile ad/asrep.txt
  hashcat -m 18200 ad/asrep.txt /usr/share/wordlists/rockyou.txt

BloodHound collection after creds:
  bloodhound-python -u USER -p 'PASS' -d DOMAIN -c All -ns $target

WinRM:
  evil-winrm -i $target -u USER -p 'PASS'
  evil-winrm -i $target -u USER -H NTLM_HASH

Pass-the-hash:
  netexec smb TARGET -u USER -H NTLM_HASH
  impacket-wmiexec -hashes :NTLM_HASH DOMAIN/USER@TARGET

[REMINDERS]
- This helper prints commands; it does not choose or execute an attack path.
- Track AD machine points from the live exam control panel and current official guide.
EOF
}

loot_linux() {
  cat <<'EOF'
[PASTE ON LINUX TARGET AFTER SHELL]

Basic:
  id; whoami; hostname; cat /etc/os-release
  ip a
  sudo -l

Credential hunting:
  grep -RiE "pass|passwd|password|pwd|secret|token|key" /var/www /opt /srv /home 2>/dev/null
  find / -name "wp-config.php" 2>/dev/null
  find / -name ".env" 2>/dev/null
  find / -name "config.php" 2>/dev/null
  find / -name "settings.py" 2>/dev/null
  find / -name "database.yml" 2>/dev/null

History and SSH:
  cat ~/.bash_history 2>/dev/null
  cat /home/*/.bash_history 2>/dev/null
  find / -name "id_rsa*" 2>/dev/null
  find / -name "authorized_keys" 2>/dev/null
  ls -la /home/*/.ssh/ 2>/dev/null

Backups:
  find / -name "*.bak" 2>/dev/null
  find / -name "*.old" 2>/dev/null
  find / -name "*.swp" 2>/dev/null
  find / -name "*~" 2>/dev/null
  find / -name "*.zip" 2>/dev/null
  find / -name "*.tar.gz" 2>/dev/null

Privilege escalation:
  find / -perm -4000 -ls 2>/dev/null
  getcap -r / 2>/dev/null
  cat /etc/crontab
  ls -la /etc/cron*
  find / -writable -type f 2>/dev/null
  cat /etc/passwd | grep sh$
  ps aux
  ss -tulpen

Priority: creds > sudo -l > SUID/caps > cron > writable files > kernel exploit last.
EOF
}

loot_windows() {
  cat <<'EOF'
[PASTE ON WINDOWS TARGET AFTER SHELL]

Basic:
  whoami
  whoami /all
  whoami /priv
  hostname
  ipconfig /all
  systeminfo
  net user
  net localgroup administrators

Credential hunting:
  cmdkey /list
  dir /s /b *pass* *cred* *vnc* *.config *.kdbx 2>nul
  dir /s /b web.config 2>nul
  dir /s /b unattend.xml unattended.xml sysprep.inf sysprep.xml 2>nul

PowerShell history:
  type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

Services:
  wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows"

AlwaysInstallElevated:
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

Scheduled tasks and network:
  schtasks /query /fo LIST /v
  netstat -ano

Notes: check saved creds before noisy paths. SeImpersonatePrivilege or writable service paths may matter.
EOF
}

proof_helper() {
  load_env_file
  local type="${1:-local}"
  case "$type" in
    local|proof) ;;
    *) die "usage: proof [local|proof]" ;;
  esac

  mkdir -p "$PROOF_DIR"
  local outfile="$PROOF_DIR/${type}_proof_instructions_$(ts).md"
  cat > "$outfile" <<EOF
# ${type}.txt Proof Checklist

Target: ${OSCP_TARGET:-<target>}
Workspace: $ROOT_DIR

## Linux interactive shell proof

\`\`\`bash
pwd
cat ${type}.txt
whoami
hostname
ip a
\`\`\`

## Windows interactive shell proof

\`\`\`cmd
cd
type ${type}.txt
whoami
hostname
ipconfig
\`\`\`

## Required actions

- [ ] Submit the flag in the control panel before exam end.
- [ ] Capture an interactive shell screenshot, not only a web shell.
- [ ] Make sure the screenshot shows flag content and target IP context.
- [ ] Save screenshot in screenshots/.
- [ ] Add exact commands to notes/report.

Suggested capture:

\`\`\`bash
./scripts/oscp.sh screenshot "${type} proof with ip visible"
\`\`\`
EOF

  note "Created $type proof checklist -> ${outfile#$ROOT_DIR/}"
  ok "Wrote: $outfile"
  echo "Proof must come from an interactive shell where required by the live guide."
}

stuck_helper() {
  load_env_file
  cat <<EOF
[STOP TUNNEL VISION]

Current target: ${OSCP_TARGET:-<not set>}

1. Re-read the deep scan line by line.
2. Did you check every open port?
3. Did you run UDP top ports where time allows?
4. Did you inspect source, robots.txt, sitemap.xml?
5. Did you run small and medium web discovery or equivalent?
6. Did you try extensions: php, txt, bak, old, zip, conf, config?
7. Did you try SMB null and guest?
8. Did you search exact service versions?
9. Did you try every found credential everywhere?
10. Did you look for usernames?
11. Did you check internal-only services after shell?
12. Did you check configs before kernel exploits?
13. Did you take notes good enough for the report?

[15-MINUTE RULE]
If you have spent 15 minutes on the same idea, change approach.

[2-HOUR RULE]
If you have spent 2+ hours on this box with no useful progress, move on.
EOF
}

ensure_scoring_file() {
  if [[ -f "$SCORING_FILE" ]]; then
    return 0
  fi

  mkdir -p "$(dirname "$SCORING_FILE")"
  cat > "$SCORING_FILE" <<'EOF'
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
}

score_helper() {
  ensure_scoring_file
  cat "$SCORING_FILE"
  echo
  echo "[TRACKING FILE]"
  echo "$SCORING_FILE"
}

quick() {
  local target
  target="$(target_or_default "${1:-}")"
  nmap_full "$target"
  nmap_deep "$target"
  enum_all "$target"
}

serve() {
  local port="${1:-8000}"
  [[ "$port" =~ ^[0-9]+$ ]] || die "Invalid port: $port"
  mkdir -p "$TRANSFER_DIR"
  info "Serving $TRANSFER_DIR on port $port"
  cd "$TRANSFER_DIR"
  python3 -m http.server "$port"
}

listener() {
  local port="${1:-}"
  [[ -n "$port" ]] || die "usage: listener <PORT>"
  [[ "$port" =~ ^[0-9]+$ ]] || die "Invalid port: $port"
  if need_cmd rlwrap && need_cmd nc; then
    rlwrap -cAr nc -lvnp "$port"
  elif need_cmd nc; then
    nc -lvnp "$port"
  elif need_cmd ncat; then
    ncat -lvnp "$port"
  else
    die "No nc or ncat found"
  fi
}

loot_search() {
  local term="$*"
  [[ -n "$term" ]] || die "usage: loot-search <TERM>"
  if need_cmd rg; then
    rg -n --hidden --glob '!.git' -- "$term" "$ROOT_DIR" || true
  else
    grep -RIn -- "$term" "$ROOT_DIR" 2>/dev/null || true
  fi
}

capture_screenshot_file() {
  local outfile="${1:?output file required}"
  local mode="${OSCP_SCREENSHOT_MODE:-full}"

  case "$mode" in
    full|area|window) ;;
    *) die "Invalid OSCP_SCREENSHOT_MODE=$mode. Use full, area, or window." ;;
  esac

  if need_cmd gnome-screenshot; then
    case "$mode" in
      full) gnome-screenshot -f "$outfile" ;;
      area) gnome-screenshot -a -f "$outfile" ;;
      window) gnome-screenshot -w -f "$outfile" ;;
    esac
  elif need_cmd xfce4-screenshooter; then
    case "$mode" in
      full) xfce4-screenshooter -f -s "$outfile" ;;
      area) xfce4-screenshooter -r -s "$outfile" ;;
      window) xfce4-screenshooter -w -s "$outfile" ;;
    esac
  elif need_cmd flameshot; then
    case "$mode" in
      full) flameshot full -p "$outfile" ;;
      area) flameshot gui -p "$outfile" ;;
      window) flameshot gui -p "$outfile" ;;
    esac
  elif need_cmd scrot; then
    case "$mode" in
      full) scrot "$outfile" ;;
      area) scrot -s "$outfile" ;;
      window) scrot -u "$outfile" ;;
    esac
  elif need_cmd maim; then
    case "$mode" in
      full) maim "$outfile" ;;
      area) maim -s "$outfile" ;;
      window) maim -i "$(xdotool getactivewindow)" "$outfile" ;;
    esac
  elif need_cmd import; then
    case "$mode" in
      full) import -window root "$outfile" ;;
      area) import "$outfile" ;;
      window) import "$outfile" ;;
    esac
  else
    return 127
  fi
}

ensure_screenshot_index() {
  if [[ ! -f "$SCREENSHOT_INDEX" ]]; then
    cat > "$SCREENSHOT_INDEX" <<'EOF'
# Screenshot Evidence Index

| Time | Target | Label | Screenshot | Metadata |
| --- | --- | --- | --- | --- |
EOF
  fi
}

screenshot_evidence() {
  local label="${1:-evidence}"
  local ip_arg="${2:-}"
  load_env_file

  local target="${ip_arg:-${OSCP_TARGET:-}}"
  if [[ -n "$target" ]]; then
    require_ipv4 "$target" "target"
  else
    target="no-target"
  fi

  local clean stamp base png meta rel_png rel_meta
  clean="$(sanitize_label "$label")"
  stamp="$(ts)"
  base="${stamp}_${target}_${clean}"
  png="$SCREENSHOTS_DIR/${base}.png"
  meta="$EVIDENCE_DIR/${base}.txt"
  rel_png="screenshots/${base}.png"
  rel_meta="evidence/${base}.txt"

  info "Capture mode: ${OSCP_SCREENSHOT_MODE:-full}"
  info "Before capture, make sure the terminal/browser shows the target IP and relevant proof/output."

  if ! capture_screenshot_file "$png"; then
    cat >&2 <<EOF
[-] No supported screenshot tool found or capture failed.
    Install one of: gnome-screenshot, xfce4-screenshooter, flameshot, scrot, maim, imagemagick.
    You can still place a manual screenshot in: $SCREENSHOTS_DIR
EOF
    exit 1
  fi

  cat > "$meta" <<EOF
Screenshot: $rel_png
Label: $label
Target: $target
Workspace: $ROOT_DIR
Local time: $(date +"%Y-%m-%d %H:%M:%S %Z")
UTC time: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Mode: ${OSCP_SCREENSHOT_MODE:-full}

Report reminder:
- Confirm the current exam/report requirements from the official guide.
- Keep the target IP, proof/output, and command context visible where required.
- Store raw command output separately when a screenshot alone is not enough.
EOF

  ensure_screenshot_index
  printf '| %s | %s | %s | %s | %s |\n' \
    "$(date +"%Y-%m-%d %H:%M")" "$(md_cell "$target")" "$(md_cell "$label")" "$rel_png" "$rel_meta" >> "$SCREENSHOT_INDEX"

  note "Screenshot evidence '$label' target=$target -> $rel_png"
  ok "Screenshot saved: $png"
  ok "Metadata saved: $meta"
  ok "Index updated: $SCREENSHOT_INDEX"
}

show_live() {
  [[ -s "$LIVE_HOSTS" ]] && nl -ba "$LIVE_HOSTS" || echo "[-] No live hosts yet."
}

status() {
  load_env_file
  echo "============================================"
  echo " Workspace : $ROOT_DIR"
  echo " Target    : ${OSCP_TARGET:-<not set>}"
  echo " Subnet    : ${OSCP_SUBNET:-<not set>}"
  echo " Domain    : ${OSCP_DOMAIN:-<not set>}"
  echo " Wordlist  : ${OSCP_WORDLIST:-<default>}"
  echo " Vhosts    : ${OSCP_VHOST_WORDLIST:-<default>}"
  echo "--------------------------------------------"
  if [[ -s "$LIVE_HOSTS" ]]; then
    echo " Live hosts: $(wc -l < "$LIVE_HOSTS") in $LIVE_HOSTS"
  else
    echo " Live hosts: none yet"
  fi
  [[ -s "$CREDS_FILE" ]] && echo " Creds     : $(wc -l < "$CREDS_FILE") in creds.txt"
  [[ -s "$HASHES_FILE" ]] && echo " Hashes    : $(wc -l < "$HASHES_FILE") in loot/hashes.txt"
  echo "--------------------------------------------"
  if [[ -f "$NOTES_FILE" ]]; then
    echo " Last 5 notes:"
    grep -E '^- [0-9]{2}:[0-9]{2} - ' "$NOTES_FILE" 2>/dev/null | tail -n 5 | sed 's/^/   /' || true
  fi
  echo "============================================"
}

set_target() {
  local target="${1:-}"
  local subnet="${2:-}"
  load_env_file
  [[ -n "$target" ]] || die "set-target needs an IP"
  require_ipv4 "$target" "target"
  [[ -n "$subnet" ]] || subnet="$(infer_subnet_24 "$target" || true)"
  [[ -n "$subnet" ]] && require_cidr "$subnet"
  save_env_file "$target" "$subnet"
  note "Set target=$target subnet=${subnet:-<none>}"
}

cmd="${1:-}"
case "$cmd" in
  set-target) shift; set_target "${1:-}" "${2:-}" ;;
  discover) shift; discover "${1:-}" ;;
  discover-wide) shift; discover_wide "${1:-}" ;;
  nmap-live) shift; nmap_live ;;
  nmap-full) shift; nmap_full "${1:-}" ;;
  nmap-deep) shift; nmap_deep "${1:-}" ;;
  nmap-udp) shift; nmap_udp "${1:-}" ;;
  nmap-vuln) shift; nmap_vuln "${1:-}" ;;
  ports) shift; show_ports "${1:-}" ;;
  enum-all) shift; enum_all "${1:-}" ;;
  suggest) shift; suggest_next "${1:-}" ;;
  enum-web|web-triage) shift; web_triage "${1:-}" "${2:-}" "${3:-}" ;;
  web-all) shift; web_all "${1:-}" "${2:-}" ;;
  enum-smb) shift; enum_smb "${1:-}" ;;
  enum-ftp) shift; enum_ftp "${1:-}" "${2:-21}" ;;
  enum-ssh) shift; enum_ssh "${1:-}" "${2:-22}" ;;
  enum-rpc) shift; enum_rpc "${1:-}" ;;
  enum-ldap) shift; enum_ldap "${1:-}" ;;
  enum-snmp) shift; enum_snmp "${1:-}" ;;
  enum-winrm) shift; enum_winrm "${1:-}" ;;
  quick) shift; quick "${1:-}" ;;
  ad) shift; ad_helper "${1:-}" ;;
  loot-linux) shift; loot_linux ;;
  loot-windows) shift; loot_windows ;;
  proof) shift; proof_helper "${1:-local}" ;;
  stuck) shift; stuck_helper ;;
  score) shift; score_helper ;;
  serve) shift; serve "${1:-8000}" ;;
  listener) shift; listener "${1:-}" ;;
  loot-search) shift; loot_search "$*" ;;
  screenshot|shot|evidence-shot) shift; screenshot_evidence "${1:-evidence}" "${2:-}" ;;
  show-live) shift; show_live ;;
  status) shift; status ;;
  note) shift; note "$*" ;;
  cred) shift; cred "$*" ;;
  add-cred) shift; add_cred_structured "${1:-}" "${2:-}" "${3:-}" "${4:-manual}" ;;
  hash) shift; log_hash "$*" ;;
  hash-guess) shift; guess_hash_type "$*" ;;
  -h|--help|"") usage ;;
  *) echo "[-] Unknown command: $cmd"; usage; exit 1 ;;
esac
