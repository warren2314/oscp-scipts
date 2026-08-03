# Windows Privilege-Escalation Playbook

The objective is an explainable path to the required administrative shell, not the largest possible tool output.

## 1. Preserve the starting context

```text
whoami
whoami /all
whoami /groups
whoami /priv
hostname
ipconfig /all
systeminfo
```

Save `whoami /priv` locally and run:

```bash
./scripts/oscp.sh win-privs privesc/windows/whoami_priv.txt
```

High-signal token privileges include `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, and `SeTakeOwnershipPrivilege`. Match the technique to the OS build and privilege; do not choose a potato exploit by name alone.

## 2. Hunt credentials before exploits

```text
cmdkey /list
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
dir /s /b C:\Users\*.config C:\Users\*.xml C:\Users\*.ini C:\Users\*.kdbx 2>nul
dir /s /b C:\inetpub\wwwroot\web.config 2>nul
dir /s /b C:\unattend.xml C:\Windows\Panther\Unattend.xml 2>nul
```

Prioritize application configuration, service credentials, deployment scripts, backup files, saved sessions, and reused domain credentials.

## 3. Services and filesystem ACLs

```text
sc query state= all
wmic service get name,startname,startmode,pathname
icacls "C:\path\to\service.exe"
icacls "C:\path\to\service-directory"
```

Check:

- Writable service binaries or containing directories
- Unquoted paths with a writable prefix directory
- Weak service configuration permissions
- Services running as SYSTEM or a privileged domain account
- Whether you can restart the service or need a reboot

Record the original configuration before changing anything and prefer reversible modifications.

## 4. Scheduled tasks, startup, and installers

```text
schtasks /query /fo LIST /v
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

For each task, identify the run-as account, trigger, command, and whether the executable, script, or working directory is writable.

## 5. Network and local-only services

```text
netstat -ano
tasklist /svc
route print
```

Map listening PIDs to processes and services. A database, admin panel, or development service bound only to localhost may be the intended path.

## 6. Automated enumeration as a cross-check

Stage and run WinPEAS or PowerUp only after the manual baseline. Save the full output, then verify every candidate manually. Tool color and confidence labels are hints, not proof.

```bash
./scripts/oscp.sh tools stage
./scripts/oscp.sh serve 8000
```

## 7. Kernel and public exploits last

Before using an exploit:

- Confirm exact OS build, architecture, patch state, and vulnerable component.
- Read the source and understand system changes and crash risk.
- Confirm the technique is permitted by the current exam rules.
- Preserve a fallback shell and report-ready commands.

## 8. Proof and cleanup

Once administrative access is obtained:

```text
whoami
hostname
ipconfig
type C:\Users\Administrator\Desktop\proof.txt
```

Submit the flag immediately, capture the required screenshot from the original file location, log the exact path, and restore any temporary service/task configuration where safe.
