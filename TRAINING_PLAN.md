# Eight-Week OSCP Toolkit Training Plan

Target: end-of-September exam. The goal is not to add more commands every week; it is to make the same small workflow automatic under time pressure.

## Weekly rhythm

- Four focused practice sessions
- One timed box or AD objective
- One report/evidence session using only saved output
- One review/rest day

For every machine, start with `guided.sh`, maintain the dashboard, and finish with a report-ready attack path. Measure completion and evidence quality, not the number of tools launched.

## Week 1 - Stabilize the workflow

- Install or refresh the toolkit on the intended Kali exam VM.
- Run `oscp-health`; resolve missing core tools and wordlists.
- Create throwaway standalone and AD workspaces.
- Practice target setup, phase/focus updates, task tracking, notes, credentials, and screenshots.
- Complete two familiar lab machines without using external walkthroughs.

Exit test: create a workspace and reach the correct next-action dashboard without consulting the README.

## Week 2 - Standalone enumeration

- Complete three machines emphasizing full TCP, deep service validation, UDP triage, and non-web services.
- For each port, write one hypothesis and one manual validation.
- Compare automated output with manual interaction.
- Practice the 15-minute idea limit and two-hour target limit.

Exit test: produce a complete service matrix and prioritized next-action list within 45 minutes.

## Week 3 - Linux and Windows privilege escalation

- Complete at least two Linux and two Windows local escalation paths.
- Use manual checks before PEAS/PowerUp.
- Practice credential hunting, services/tasks/cron, permissions, internal ports, and token privileges.
- Capture proof screenshots exactly as required.

Exit test: explain every step and side effect without relying on tool color coding.

## Week 4 - AD presumed breach

- Complete two AD sets or equivalent lab paths from a supplied low-privilege credential.
- Drill credential validation, SMB/LDAP enumeration, BloodHound collection, shares, sessions, and roasting.
- Practice Kali/DC DNS and time troubleshooting.
- Re-enumerate after every new identity or host.

Exit test: produce a graph-backed attack hypothesis and evidence trail within 90 minutes.

## Week 5 - Lateral movement and domain escalation

- Drill WinRM, WMI, SMB execution, PowerShell remoting, password/hash authentication, and pivot awareness.
- Practice interpreting ACL, GPO, delegation, AD CS, and local-admin edges.
- Avoid persistence and destructive shortcuts unless a controlled lab specifically teaches them.
- Write each hop as a report section while the path is fresh.

Exit test: reproduce a multi-host path from notes alone after resetting the lab.

## Week 6 - Timed mixed practice

- Run two six-to-eight-hour mixed sessions with no hints or AI assistance.
- Use only the frozen toolkit, personal notes, course material, and permitted web research.
- Track time, breaks, target switches, failed hypotheses, evidence, and submissions.
- Write the report the following day from saved artifacts.

Exit test: no missing commands, source locations, screenshots, or proof submissions.

## Week 7 - Full mock and reporting

- Run the closest available full-length mock.
- Use the exact Kali VM, display setup, VPN process, browser, note editor, and report template intended for the exam.
- Test machine reverts, screenshot naming, report image legibility, PDF export, archive creation, and upload-size constraints.
- Patch only proven toolkit problems; stop adding speculative features.

Exit test: deliver a professional mock report inside the real submission window.

## Week 8 - Freeze and sharpen

- Run the automated toolkit tests and health check.
- Create hashes/backups of the toolkit, report template, VPN troubleshooting notes, and transfer tools.
- Complete one short confidence box and one AD workflow review.
- Review official exam rules and the live control panel instructions.
- Prioritize sleep and routine; do not rebuild the environment in the final days.

## Session scorecard

After each practice session, record:

- Time to complete the first reliable scan
- Time to first useful credential or attack hypothesis
- Time stuck on the longest unproductive idea
- Number of undocumented commands
- Whether every proof screenshot shows flag and IP
- Whether the attack path can be reproduced from notes alone
- One workflow change to rehearse next time

The toolkit is ready when it reduces cognitive load without making decisions for you.
