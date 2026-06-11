# Escalation triggers

> If you see any of these, stop investigating and escalate. Follow your IR runbook.

---

## Escalate immediately — no exceptions

### Ransomware
- `vssadmin delete shadows` or `wmic shadowcopy delete`
- `bcdedit /set {default} recoveryenabled No`
- Mass file renames with new extension
- Ransom note files created in multiple folders

### Credential access
- Any non-Windows process accessing `lsass.exe`
- `rundll32.exe comsvcs.dll, MiniDump [PID]`
- `NTDS.dit` accessed by a non-system process
- SAM hive read by a non-system process
- Mimikatz binary or `sekurlsa::` commands

### Active C2 session
- Confirmed beaconing with interactive response
- Cobalt Strike named pipe (`\\.\pipe\MSSE-*`, `\\.\pipe\postex_*`)
- Reverse shell — outbound connection from `cmd.exe` or `powershell.exe`

### Lateral movement confirmed
- Same malicious hash on multiple devices
- Compromised account on devices it never normally accesses
- `psexec.exe` / `psexesvc.exe` executing on remote hosts
- WMI remote execution to internal IPs

### Data exfiltration indicators
- Large outbound transfer from an unexpected process
- Staging directory — files collected and compressed before sending
- `rclone`, `MEGASync` uploading from unexpected process

### Defence evasion — attacker covering tracks
- Defender disabled via registry
- Audit logs cleared (`wevtutil cl Security`, `wevtutil cl System`)
- EDR process killed or tampered
- Firewall rules modified to allow inbound connections

---

## What to have ready when you escalate

```
Device:          hostname, OS, last logged-in user
T0 (first seen): timestamp of first malicious activity
Alert name:      Defender / Sentinel alert title
Malware family:  if identified
What ran:        key process chain
What it did:     network connections, files dropped, persistence
Spread:          yes/no — other devices, other accounts
Status:          device isolated / not isolated
Trigger:         which item above caused escalation
```

---

## Severity guide

| Scenario | Severity |
|----------|----------|
| Detected and quarantined, no execution evidence | Low — review and close |
| Executed, no persistence, no spread, no C2 | Medium — full investigation, confirm contained |
| C2 beaconing confirmed (live) | High — isolate, escalate |
| Credential dumping detected | Critical — escalate immediately |
| Lateral movement confirmed | Critical — escalate immediately |
| Ransomware indicators | Critical — escalate immediately, consider P1 |
| Multiple devices affected | Critical — escalate immediately |
