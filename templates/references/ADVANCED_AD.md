# Advanced AD Decision Points

This is a trigger list, not a checklist. Do not try every technique. Follow one only when your collected data demonstrates the prerequisite.

## Writable object or ACL edge

If BloodHound shows `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, or `AllExtendedRights`:

1. Identify the exact source principal, target object, inherited path, and affected attribute.
2. Read the BloodHound edge guidance and verify with PowerView/LDAP.
3. Prefer the least disruptive reversible change.
4. Record the original value and a cleanup command before exploitation.

Possible outcomes include controlled group membership, password reset rights, SPN manipulation followed by Kerberoasting, or GPO control. The edge determines the technique; the technique does not create the edge.

## GPO control

Confirm:

- The owned principal can modify the GPO or its files.
- The GPO is linked to a useful OU/computer.
- You understand refresh timing and the change required to trigger it.
- You have captured the original state and a rollback plan.

## Delegation

For unconstrained, constrained, or resource-based constrained delegation, identify:

- The trusted account/computer
- `TrustedToAuthForDelegation` or allowed-to-delegate targets
- Required SPN and reachable service
- Whether an existing ticket/credential satisfies the prerequisite

Do not wait indefinitely for privileged authentication or coerce it unless the current exam rules and exact action permit it.

## Active Directory Certificate Services

Run evidence-led enumeration:

```bash
certipy-ad find -u 'USER@DOMAIN' -p PASS -dc-ip DC_IP -vulnerable
```

For any candidate template, verify enrollment rights, authentication EKUs, subject-name control, manager approval, authorized signatures, CA reachability, and the intended identity mapping. Save Certipy output for the report.

## MSSQL and database links

If MSSQL is exposed or BloodHound/share data identifies a SQL service account:

- Enumerate instances and the current SQL login context.
- Check linked servers and mapped login context.
- Treat `xp_cmdshell` as a consequential configuration change; record and restore the original state.
- Follow links only when the resulting server remains in scope.

## Domain and forest trusts

Start with enumeration, not ticket forging:

- Domain/forest trust direction and transitivity
- SID filtering and selective authentication
- Accessible resources and foreign group memberships
- Sessions, local-admin edges, and SQL links across the trust

Golden tickets, trust tickets, skeleton keys, custom SSPs, and long-term persistence are not default OSCP objectives. Keep them out of the core workflow unless the control panel or an evidence-backed course technique makes them necessary.

## DCSync

DCSync is justified only when the owned principal has the required replication rights. Confirm the rights first, limit the requested material where practical, and document why the action was necessary for the objective.

## Stop condition

If you cannot state the prerequisite, expected result, side effect, evidence path, and cleanup plan in one minute, return to enumeration.
