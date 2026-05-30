# OSCP Training Toolkit

Small Bash toolkit for authorised OSCP/PEN-200 style lab work. It creates a per-target workspace, runs repeatable enumeration, and keeps outputs organised for notes and reporting.

## Install

```bash
chmod +x install_oscp_toolkit.sh
./install_oscp_toolkit.sh
```

Run a dependency check only:

```bash
./install_oscp_toolkit.sh --check-only
```

Install missing apt packages after review:

```bash
./install_oscp_toolkit.sh --install-missing
```

## Refresh an Existing Workspace

Workspaces contain copied scripts under `./scripts/`. If you update the toolkit after creating a workspace, refresh that workspace:

```bash
oscp-refresh /path/to/workspace
```

Or without the alias:

```bash
~/oscp-toolkit/refresh_workspace.sh /path/to/workspace
```

The refresh keeps a backup in `scripts/.backup_<timestamp>/`.

## Create a Workspace

```bash
oscp-init -n secura -t 192.168.56.10
cd ./YYYYMMDD_HHMM_secura
./scripts/helper.sh
```

Without the alias:

```bash
~/oscp-toolkit/init_oscp.sh -n secura -t 192.168.56.10
```

## Recommended Flow

```bash
./scripts/oscp.sh status
./scripts/oscp.sh nmap-full
./scripts/oscp.sh nmap-deep
./scripts/oscp.sh suggest
./scripts/oscp.sh enum-all
```

For subnet work:

```bash
./scripts/oscp.sh discover
./scripts/oscp.sh nmap-live
```

For a single web service:

```bash
./scripts/oscp.sh enum-web 192.168.56.10 8080
./scripts/oscp.sh enum-web 192.168.56.10 8080 example.local
```

Web enumeration saves HTTP headers, WhatWeb output, Nikto checks when installed, HTTP nmap script output, one directory brute-force run using the first available supported tool, and FFUF virtual-host checks. Pass a domain or set `OSCP_DOMAIN` in `.oscp_env` to also run FFUF `FUZZ.<domain>` subdomain Host header checks.

## Useful Commands

```bash
./scripts/oscp.sh ports
./scripts/oscp.sh web-all
./scripts/oscp.sh enum-smb 192.168.56.10
./scripts/oscp.sh enum-ldap 192.168.56.10
./scripts/oscp.sh ad 192.168.56.10
./scripts/oscp.sh nmap-udp
./scripts/oscp.sh loot-linux
./scripts/oscp.sh loot-windows
./scripts/oscp.sh win-privs
./scripts/oscp.sh win-privs privesc/windows/whoami_priv.txt
./scripts/oscp.sh tools
./scripts/oscp.sh tools stage
./scripts/oscp.sh proof local
./scripts/oscp.sh stuck
./scripts/oscp.sh score
./scripts/oscp.sh loot-search password
./scripts/oscp.sh serve 8000
./scripts/oscp.sh listener 4444
./scripts/oscp.sh screenshot "proof with ip visible"
```

## Logging

```bash
./scripts/oscp.sh note "anonymous SMB share exposes backup.zip"
./scripts/oscp.sh cred "bob:Password123 (SMB on 192.168.56.10)"
./scripts/oscp.sh add-cred smb bob 'Password123' 'backup.zip config'
./scripts/oscp.sh hash "<hash> (source/type)"
```

The workspace contains `notes.md`, `notes/`, `reports/findings.md`, `reports/scoring.md`, `commands.log`, `creds/creds.csv`, service folders, scan output, screenshots, evidence, transfer files, and loot. Keep raw command output in the generated folders and write concise findings in `reports/findings.md`.

## Buddy Helpers

These commands are intentionally decision-support helpers. They print manual checks, command blocks, and reporting reminders; they do not select exploits, brute-force services by default, run SQLmap, or chain exploitation.

```bash
./scripts/oscp.sh suggest
./scripts/oscp.sh ad
./scripts/oscp.sh loot-linux
./scripts/oscp.sh loot-windows
./scripts/oscp.sh win-privs
./scripts/oscp.sh proof proof
./scripts/oscp.sh stuck
./scripts/oscp.sh score
./scripts/oscp.sh hash-guess '<hash>'
```

## Post-Shell Tool Toolbox

The `tools` helper checks common local AD and Windows tooling, stages already-installed Windows-side files into `transfer/tools/`, and prints disk-based fetch/import snippets.

```bash
./scripts/oscp.sh tools status
./scripts/oscp.sh tools stage
./scripts/oscp.sh tools memory
./scripts/oscp.sh tools commands
./scripts/oscp.sh serve 8000
```

It looks for BloodHound, SharpHound, PowerView, Rubeus, evil-winrm, Responder, NetExec/CrackMapExec, Impacket, PrintSpoofer, Empire, Covenant, and Mimikatz in common Kali paths. Mimikatz staging is opt-in:

```bash
OSCP_STAGE_SENSITIVE=1 ./scripts/oscp.sh tools stage
```

This helper does not create memory-only download cradles, reflective loaders, or bypasses. The `memory` mode shows local PowerShell import patterns from files already on disk. Use only tools and features allowed by the live exam rules; Responder poisoning/spoofing and C2-style workflows may be restricted.

## Screenshot Evidence

The screenshot helper saves a PNG into `screenshots/`, writes a metadata file into `evidence/`, and updates `evidence/screenshots.md`.

```bash
./scripts/oscp.sh screenshot "local proof with ip visible"
OSCP_SCREENSHOT_MODE=area ./scripts/oscp.sh screenshot "web evidence"
```

Supported modes are `full`, `area`, and `window`. The helper uses whichever screenshot tool is installed, such as `gnome-screenshot`, `xfce4-screenshooter`, `flameshot`, `scrot`, `maim`, or ImageMagick `import`.

Do not treat this as a replacement for the current official report guide. Use it to keep the target IP, proof/output, timestamp, and evidence path organised while you follow the live requirements.

## Scope

Use this only for systems you are authorised to test. The scripts are designed for lab and exam-style enumeration, not uncontrolled scanning.

For an actual exam, treat this as prebuilt static local tooling only. Verify the live OffSec guide and control panel, and do not use LLM/chatbot help during the exam or report phase.
