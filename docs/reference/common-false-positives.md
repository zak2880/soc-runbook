# Common false positives

> Benign activity that pattern-matches to malicious behaviour. Use this to avoid chasing noise and to speed up FP closure write-ups.  
> Confirmed FPs must not meet any criteria in [escalation-triggers.md](escalation-triggers.md) — if anything here is ambiguous, escalate rather than assume benign.

---

## Ransomware-pattern

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| `vssadmin delete shadows` or `wmic shadowcopy delete` | Backup software deletes old snapshots before creating new ones | `InitiatingProcessParentFileName` = `VeeamAgent.exe`, `VeeamBackup.exe`, `AcronisAgent.exe`, or `wbengine.exe`; binary signed by backup vendor |
| Mass file renames / extensions changed | Bulk file migration, OneDrive conflict resolution, batch rename tool | Process = `OneDrive.exe` or a known admin/migration tool; activity limited to one user's files; no ransom note files in `DeviceFileEvents` |
| `bcdedit /set {default} recoveryenabled No` | Some imaging and deployment tools set recovery options during OS provisioning | Parent = `setupprep.exe`, `DISM.exe`, or a signed deployment script; activity falls within a known build window |

> **Still escalate if:** ransom note files are present, file renames span multiple users' shares, or the backup agent binary is unsigned or running from an unexpected path.

---

## Credential access

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| Non-Windows process reads `lsass.exe` | AV/EDR vendors inspect LSASS for credential protection (CrowdStrike, SentinelOne, Carbon Black, Defender itself) | `InitiatingProcessVersionInfoCompanyName` matches a known security vendor; binary is signed; `InitiatingProcessFolderPath` is the vendor install directory |
| SAM hive or `NTDS.dit` read by non-system process | Backup software taking a system-state backup; Defender for Identity sensor | Parent = `VeeamAgent.exe`, `Acronis*.exe`, or `Microsoft.Tri.Sensor.exe`; activity during a scheduled backup window |
| Credential-access detections from a network source IP | Authorised Nessus / Qualys / Tenable scan | Source IP on client-approved scan schedule; check with client or scan ticket; scanner user-agent visible in `DeviceNetworkEvents` |

> **Still escalate if:** the process is unsigned, runs from `%TEMP%` or `%APPDATA%`, or no authorised scan is scheduled.

---

## C2 / Network

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| Regular outbound beaconing to cloud relay IP | RMM heartbeat — ScreenConnect, NinjaOne, Datto RMM, AnyDesk, TeamViewer | Process signed by RMM vendor; destination resolves to vendor relay infrastructure; interval is fixed (not jittered with interactive response) |
| Large outbound data volume to cloud storage | OneDrive, Dropbox, Google Drive, Box syncing | Process = `OneDrive.exe`, `Dropbox.exe`, `GoogleDriveFS.exe`; destination ASN = Microsoft (AS8075), Dropbox (AS19679), or Google (AS15169) in `DeviceNetworkEvents` |
| Outbound on non-standard port from management process | RMM agents use fixed non-standard ports (e.g., ScreenConnect on 8041) | Consistent single destination, signed binary, matches known RMM install; no shell spawned from the process |
| Internal port scan or SMB enumeration from a single IP | Authorised vulnerability scan — Nessus, Qualys, Nexpose | Source IP matches approved scanner; confirm scan window with client; no successful exploitation follows |

> **Still escalate if:** beacon interval varies with interactive response patterns, large data volume originates from an unexpected process, or no RMM is installed on the device.

---

## Lateral movement

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| PsExec / PsExecSvc pattern on remote hosts | RMM tools and SCCM deploy agents and run scripts via PsExec-equivalent mechanisms | Parent = RMM agent binary (`ScreenConnect.ClientService.exe`, `NinjaRMMAgent.exe`); binary is signed; activity during a patch or deployment window |
| Same binary executing across multiple devices simultaneously | SCCM or Intune pushing a software update or compliance script | Binary is signed; `InitiatingProcessFileName` = `ccmexec.exe` or `IntuneManagementExtension.exe`; matches known deployment schedule |
| WMI remote execution to internal IPs | SCCM hardware inventory, monitoring agents, IT admin scripting | Initiating account is a known service account; WMI path contains only `SELECT` queries; no file drops follow |
| Internal scanning and enumeration | Authorised pen test or vulnerability scan | Source IP on approved scan schedule; cross-reference with client scan ticket |

> **Still escalate if:** execution spreads to hosts the initiating account has no documented reason to access.

---

## Persistence

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| New scheduled task created | Software installer, SCCM/Intune deployment, updater registering a maintenance task | `InitiatingProcessFileName` = `msiexec.exe`, `ccmexec.exe`, or `IntuneManagementExtension.exe`; task `Action` path is under `C:\Program Files\` or a known application directory |
| New service registered | Software installer, RMM agent install or auto-update, AV deployment | Service binary path is in `C:\Program Files\` or vendor directory; binary is signed; parent = signed installer |
| Registry Run key added | Software installer adding autorun for a legitimate application | Key value points to a signed binary in a known application path; parent = `msiexec.exe` or signed vendor installer |
| New WMI event subscription | Some enterprise monitoring tools (SCOM, SolarWinds) use WMI event subscriptions | Consumer script references a known monitoring agent path; confirm with client whether a monitoring tool is deployed |

> **Still escalate if:** the task, service, or registry value points to a binary in `%TEMP%`, `%APPDATA%`, or any user-writable path, or the binary is unsigned.

---

## Defence evasion

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| Defender real-time protection disabled via registry or PowerShell | IT admin temporarily disabling for SCCM software deployment or AV migration | Initiating account is a known IT admin; cross-reference with change ticket; protection re-enabled within the same session |
| AV exclusion added | IT configuring exclusions for backup software, line-of-business apps, or per vendor recommendation | Exclusion path is a known software directory; initiated by an IT admin account; exclusion matches vendor documentation |
| Firewall rule added via `netsh` or `New-NetFirewallRule` | Software installer opening a port for a legitimate service | Rule references a signed binary; parent = `msiexec.exe` or known installer; inbound scope is restricted |
| Audit log clearing (`wevtutil cl Security`, `wevtutil cl System`) | Rare — some server build scripts clear logs during provisioning | Parent is a documented build script; activity falls within a known provisioning window; no other suspicious activity on the device |

> **Still escalate if:** logs are cleared after any other suspicious activity on the same device, or Defender is disabled without a corresponding change ticket.

---

## Scripting / Admin tooling

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| PowerShell with `-EncodedCommand` or `-ExecutionPolicy Bypass` | SCCM/Intune deployment scripts, IT automation, vendor install wrappers | Parent = `ccmexec.exe` or `IntuneManagementExtension.exe`; or script is signed by client's code-signing cert; decoded command shows a known deployment action |
| `Invoke-Expression` / `IEX` in PowerShell command line | Legitimate admin frameworks (PSWindowsUpdate, some RMM-pushed scripts) | Decoded payload is readable and benign; initiating account is a service account; no outbound network connection follows |
| `certutil.exe -decode` or `-urlcache` | Certificate management, some installers use certutil to fetch packages | Arguments are `-addstore`, `-store`, or `-decode` targeting a known local file — not a remote URL; parent is a signed installer or admin script |
| `wmic.exe` process or query execution | SCCM hardware inventory, IT admin scripts, monitoring tools | Query is read-only (`SELECT` statements); parent is a known management agent; no file write or remote execution follows |
| `mshta.exe` execution | Some legacy enterprise applications use HTA interfaces | HTA file is in a known application directory under `C:\Program Files\`, not `%TEMP%` or `%APPDATA%`; parent is a known enterprise application |

> **Still escalate if:** the decoded PowerShell command downloads and executes a second-stage payload, or any LOLBin execution is immediately followed by an outbound connection to an external IP.

---

## Cross-reference: escalation-triggers.md

A confirmed false positive **must not** match any item in [escalation-triggers.md](escalation-triggers.md). Before closing as FP, verify all of the following:

- [ ] No ransom note files present in `DeviceFileEvents`
- [ ] No credential-dumping tool or technique (Mimikatz, `comsvcs.dll MiniDump`, `rundll32.exe comsvcs.dll`)
- [ ] No confirmed C2 beaconing with interactive command response
- [ ] No lateral movement beyond what the legitimate tool explains
- [ ] No evidence of attacker covering tracks — log clearing after suspicious activity, EDR tampered or killed

If any item above cannot be confirmed, **escalate rather than assume FP**.

---

## Documenting a false positive

```
Alert:                [alert name / rule name / Sentinel analytic]
Why it triggered:     [specific behaviour — e.g., "vssadmin delete shadows run by VeeamAgent.exe"]
Confirmation method:  [specific field/log checked — e.g., "InitiatingProcessParentFileName = VeeamAgent.exe; binary signed by Veeam Software Group s.r.o."]
Verdict:              False positive
Suppression recommended: Yes / No / Already exists
  If yes — scope:     [narrow scope — process name, hash, path, or account; avoid broad wildcard rules]
```

> Before recommending suppression, confirm the rule has no other active detections on this device. Broad suppressions mask real activity.
