# OSCP Training Toolkit

Small Bash toolkit for authorised OSCP/PEN-200 style lab work. It creates a per-target workspace, runs repeatable enumeration, and keeps outputs organised for notes and reporting. The guided dashboard keeps the current phase, focus, checklist, evidence counts, and next three actions visible so you do not have to remember the whole workflow under pressure.

## Install

For a brand-new Kali rebuild, run the bootstrap first:

```bash
chmod +x bootstrap_kali_oscp_plus.sh
./bootstrap_kali_oscp_plus.sh --yes
source ~/.oscp_plus_aliases
oscp-health
```

This creates `~/Documents/OffSec`, installs the OSCP-focused package set, stages helper files under `~/Documents/OffSec/Transfer/tools`, and installs this toolkit into `~/oscp-toolkit`.

The bootstrap also installs Docker using Kali's `docker.io` package, installs `docker-compose`, enables the Docker service where possible, and adds your user to the `docker` group. Log out and back in before running Docker without `sudo`.

Optional heavier Kali profiles:

```bash
./bootstrap_kali_oscp_plus.sh --large --yes
./bootstrap_kali_oscp_plus.sh --everything --yes
```

The default profile is recommended for OSCP+ prep. The heavier profiles install a lot of tools you will not need and can include restricted-use tooling; installing a tool does not make every feature exam-allowed.

For just the local workspace toolkit:

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
./scripts/guided.sh
```

Without the alias:

```bash
~/oscp-toolkit/init_oscp.sh -n secura -t 192.168.56.10
```

The original 38-option interface remains available as an advanced menu:

```bash
./scripts/helper.sh
```

## Guided Flow

Start each session with:

```bash
./scripts/oscp.sh guide
```

For an independent target:

```bash
./scripts/oscp.sh profile standalone
./scripts/oscp.sh status
./scripts/oscp.sh nmap-full
./scripts/oscp.sh nmap-deep
./scripts/oscp.sh suggest
./scripts/oscp.sh enum-all
```

For the AD set:

```bash
./scripts/oscp.sh profile ad
./scripts/oscp.sh phase enum
./scripts/oscp.sh ad 192.168.56.10 corp.local alice
./scripts/oscp.sh reference ad
```

When the password is omitted, the AD helper prompts for it without writing the plaintext password directly into shell history.

Track the current activity instead of relying on memory:

```bash
./scripts/oscp.sh phase foothold
./scripts/oscp.sh focus "manual Windows service and task checks"
./scripts/oscp.sh task list
./scripts/oscp.sh task done foothold
./scripts/oscp.sh task skip udp-scan
```

Target setup, saved scans, credential logging, and screenshots automatically complete the corresponding tracker items. Service coverage, access, privilege escalation, and proof milestones remain yours to confirm after reviewing the evidence.

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
./scripts/oscp.sh ad 192.168.56.10 corp.local alice
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
./scripts/oscp.sh capture "sudo permissions" -- sudo -l
./scripts/oscp.sh capture "web response headers" -- curl -k -i https://192.168.56.10/
./scripts/oscp.sh cred "bob:Password123 (SMB on 192.168.56.10)"
./scripts/oscp.sh add-cred smb bob 'Password123' 'backup.zip config'
./scripts/oscp.sh hash "<hash> (source/type)"
```

`capture` runs one manual command, shows its output live, saves the combined command/output under `evidence/commands/`, records the exact command and output path in `commands.log`, and appends a report-friendly entry to `notes/04-report-commands.md`. Its exit status matches the captured command. The command and output are stored verbatim, so use interactive prompts or placeholders instead of putting plaintext secrets in arguments.

The workspace contains `notes.md`, `notes/`, `reports/findings.md`, `reports/scoring.md`, `commands.log`, `creds/creds.csv`, service folders, scan output, screenshots, evidence, transfer files, and loot. Keep raw command output in the generated folders and write concise findings in `reports/findings.md`.

## Buddy Helpers

These commands are intentionally decision-support helpers. They print manual checks, command blocks, and reporting reminders; they do not select exploits, brute-force services by default, run SQLmap, or chain exploitation.

The AD helper is built for the presumed-breach start where you are given a domain username and password. In the interactive helper, choose `AD presumed-breach flow`; it prompts for DC IP, domain, username, and password, then prints the ordered validation, SMB/LDAP enumeration, BloodHound, Kerberoast/AS-REP, WinRM, and evidence commands. Leave username or password blank to print placeholders instead.

```bash
./scripts/oscp.sh suggest
./scripts/oscp.sh ad
./scripts/oscp.sh ad 192.168.56.10 corp.local alice
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
export OSCP_TOOLS_DIR="$HOME/Documents/OffSec/Scripts"
./scripts/oscp.sh tools status
./scripts/oscp.sh tools stage
./scripts/oscp.sh tools memory
./scripts/oscp.sh tools commands
./scripts/oscp.sh serve 8000
```

It looks for BloodHound, SharpHound, PowerView, Rubeus, evil-winrm, Responder, NetExec/CrackMapExec, Impacket, PrintSpoofer, Empire, Covenant, and Mimikatz in common Kali paths. Tool installation is not the same as permission to use every feature. Responder poisoning/spoofing is prohibited in the current OSCP+ exam rules. Mimikatz staging is opt-in:

The default search path also includes `~/Documents/OffSec/Scripts` and common subfolders such as `oscp-ad`, `Ghostpack-CompiledBinaries`, `Powershell`, `LinEnum`, and `PSExec`. Use `OSCP_EXTRA_TOOL_DIRS` with colon-separated paths for more locations.

```bash
OSCP_STAGE_SENSITIVE=1 ./scripts/oscp.sh tools stage
```

This helper does not create memory-only download cradles, reflective loaders, or bypasses. The `memory` mode shows local PowerShell import patterns from files already on disk. Use only features and actions allowed by the live exam rules.

## Curated Playbooks

The workspace includes short, evidence-led references distilled for the exam workflow:

```bash
./scripts/oscp.sh reference ad
./scripts/oscp.sh reference windows
./scripts/oscp.sh reference lateral
./scripts/oscp.sh reference advanced-ad
```

Persistence, blind spraying, poisoning/spoofing, in-memory bypasses, and destructive domain changes are intentionally excluded from the core path. Advanced AD material is presented as decision points that require a demonstrated prerequisite.

The repository also includes an [eight-week practice plan](TRAINING_PLAN.md) for turning the workflow into habit before an end-of-September exam.

## Offline Tests

Run these before freezing or refreshing the exam VM:

```bash
bash tests/run.sh
```

The tests validate Bash syntax, workspace creation, guided tracking, AD argument handling, configuration preservation, references, and safe workspace refresh without performing network scans.

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
