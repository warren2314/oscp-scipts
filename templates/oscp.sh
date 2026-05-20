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
LOOT_DIR="$ROOT_DIR/loot"
TRANSFER_DIR="$ROOT_DIR/transfer"
SCREENSHOTS_DIR="$ROOT_DIR/screenshots"
EVIDENCE_DIR="$ROOT_DIR/evidence"
LIVE_HOSTS="$SCANS_DIR/live_hosts.txt"
ENV_FILE="$ROOT_DIR/.oscp_env"
HOSTS_FILE="$ROOT_DIR/hosts.txt"
CREDS_FILE="$ROOT_DIR/creds.txt"
NOTES_FILE="$ROOT_DIR/notes.md"
HASHES_FILE="$LOOT_DIR/hashes.txt"
SCREENSHOT_INDEX="$EVIDENCE_DIR/screenshots.md"

mkdir -p "$DISC_DIR" "$NMAP_DIR" "$VULN_DIR" "$WEB_DIR" "$SMB_DIR" "$FTP_DIR" \
  "$LDAP_DIR" "$RPC_DIR" "$SNMP_DIR" "$WINRM_DIR" "$LOOT_DIR" "$TRANSFER_DIR" \
  "$SCREENSHOTS_DIR" "$EVIDENCE_DIR"

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
    printf 'OSCP_WORDLIST=%s\n' "${OSCP_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt}"
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

run_capture() {
  local label="${1:?label required}"
  local outfile="${2:?output file required}"
  shift 2

  mkdir -p "$(dirname "$outfile")"
  info "$label -> $outfile"

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

log_hash() {
  local entry="$*"
  [[ -n "$entry" ]] || die "hash needs the hash text"
  touch "$HASHES_FILE"
  echo "$(date +"%Y-%m-%d %H:%M") - $entry" >> "$HASHES_FILE"
  ok "Hash logged to $HASHES_FILE"
  note "Hash logged ($(printf '%s' "$entry" | head -c 40)...)"
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
  ./scripts/oscp.sh enum-web <IP> <PORT>
  ./scripts/oscp.sh web-all [IP]
  ./scripts/oscp.sh enum-smb <IP>
  ./scripts/oscp.sh enum-ftp <IP> [PORT]
  ./scripts/oscp.sh enum-ssh <IP> [PORT]
  ./scripts/oscp.sh enum-rpc <IP>
  ./scripts/oscp.sh enum-ldap <IP>
  ./scripts/oscp.sh enum-snmp <IP>
  ./scripts/oscp.sh enum-winrm <IP>

Workflow helpers:
  ./scripts/oscp.sh quick [IP]                 # nmap-full, nmap-deep, enum-all
  ./scripts/oscp.sh serve [PORT]               # HTTP server from transfer/
  ./scripts/oscp.sh listener <PORT>            # nc listener, rlwrap if present
  ./scripts/oscp.sh loot-search <TERM>
  ./scripts/oscp.sh screenshot ["LABEL"] [IP]    # capture indexed evidence

Logging:
  ./scripts/oscp.sh note "message"
  ./scripts/oscp.sh cred "user:pass (source)"
  ./scripts/oscp.sh hash "<hash> (type/source)"

Environment:
  .oscp_env supports OSCP_TARGET, OSCP_SUBNET, OSCP_WORDLIST,
  OSCP_DISCOVERY_PORTS, OSCP_DISCOVERY_PORTS_WIDE.
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
  [[ -n "$ip" && -n "$port" ]] || die "usage: enum-web <IP> <PORT>"
  require_ipv4 "$ip" "web target"
  [[ "$port" =~ ^[0-9]+$ ]] || die "Invalid port: $port"

  local url outdir wordlist
  url="$(url_for_port "$ip" "$port")"
  outdir="$WEB_DIR/${ip}_${port}"
  mkdir -p "$outdir"

  wordlist="${OSCP_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt}"
  if [[ ! -f "$wordlist" && -f /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt ]]; then
    wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
  elif [[ ! -f "$wordlist" && -f /usr/share/wordlists/dirb/common.txt ]]; then
    wordlist="/usr/share/wordlists/dirb/common.txt"
  fi

  info "Web triage: $url"
  info "Output: $outdir"

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

  local pid
  for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  note "Web enum $url -> $outdir"
  ok "Web triage complete: $outdir"
}

web_all() {
  local target ports port any=0
  target="$(target_or_default "${1:-}")"
  ports="$(get_ports_for_target "$target" || true)"
  [[ -n "$ports" ]] || die "No saved port list for $target. Run nmap-full first."

  while IFS= read -r port; do
    if is_web_port "$port"; then
      any=1
      web_triage "$target" "$port"
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
          web_triage "$target" "$port"
        fi
        ;;
    esac
  done < <(ports_as_lines "$ports")

  [[ "$did_web" -eq 1 ]] || warn "No common web ports were enumerated"
  note "Enum-all complete for $target"
  ok "Enum-all complete"
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
  echo " Wordlist  : ${OSCP_WORDLIST:-<default>}"
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
  enum-web|web-triage) shift; web_triage "${1:-}" "${2:-}" ;;
  web-all) shift; web_all "${1:-}" ;;
  enum-smb) shift; enum_smb "${1:-}" ;;
  enum-ftp) shift; enum_ftp "${1:-}" "${2:-21}" ;;
  enum-ssh) shift; enum_ssh "${1:-}" "${2:-22}" ;;
  enum-rpc) shift; enum_rpc "${1:-}" ;;
  enum-ldap) shift; enum_ldap "${1:-}" ;;
  enum-snmp) shift; enum_snmp "${1:-}" ;;
  enum-winrm) shift; enum_winrm "${1:-}" ;;
  quick) shift; quick "${1:-}" ;;
  serve) shift; serve "${1:-8000}" ;;
  listener) shift; listener "${1:-}" ;;
  loot-search) shift; loot_search "$*" ;;
  screenshot|shot|evidence-shot) shift; screenshot_evidence "${1:-evidence}" "${2:-}" ;;
  show-live) shift; show_live ;;
  status) shift; status ;;
  note) shift; note "$*" ;;
  cred) shift; cred "$*" ;;
  hash) shift; log_hash "$*" ;;
  -h|--help|"") usage ;;
  *) echo "[-] Unknown command: $cmd"; usage; exit 1 ;;
esac
