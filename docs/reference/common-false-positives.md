# Common false positives

> Benign activity that pattern-matches to malicious behaviour. Use this to avoid chasing noise and to speed up FP closure write-ups.  
> Confirmed FPs must not meet any criteria in [escalation-triggers.md](escalation-triggers.md) — if anything here is ambiguous, escalate rather than assume benign.

---

## The closing rule

Close as a false positive only with a named, verifiable benign cause, and record it. Name the product, job or change, and what proves it: a result in Defender XDR or Sentinel, or something the customer confirms in writing.

None of these is ever enough:

- A known app name
- A standard install path
- A signature alone: a remote-access tool an attacker installed is signed by its vendor too
- A fixed interval
- Low volume
- "Seen on many devices": spread means scope wider, never evidence of a false positive
- "Nothing else found"

"Don't close yourself; the IR lead decides" means escalate and leave the closure to the IR lead.

An authorised test or a sanctioned tool that was detected correctly is Informational, expected activity, not False positive.

Each section below links the playbook's closing rules. Meet those as well as the row here. For the scenarios with no section here, use the playbook: [malware alert](../scenarios/01-malware-alert/playbook.md#closing-as-a-false-positive), [initial access](../scenarios/10-initial-access/playbook.md#closing-as-a-false-positive) and [phishing email](../scenarios/12-phishing-email/playbook.md#closing-as-not-malicious).

---

## Ransomware-pattern

Playbook: [Malicious file, Closing as a false positive](../scenarios/05-malicious-file/playbook.md#closing-as-a-false-positive).

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| `vssadmin delete shadows` or `wmic shadowcopy delete` | Backup software deletes old snapshots before creating new ones | Don't close yourself; the IR lead decides. The IR lead confirms the backup job with the customer. A parent name and a signer can't close this |
| Mass file renames / extensions changed | Bulk file migration, OneDrive conflict resolution, batch rename tool | Don't close yourself; the IR lead decides. The customer names the migration job with a change record. "No ransom notes" isn't evidence, and a sync client can replay renames from another device |
| `bcdedit /set {default} recoveryenabled No` | Some imaging and deployment tools set recovery options during OS provisioning | Don't close yourself; the IR lead decides. The customer names the imaging or deployment job and its build window |

> **Always escalate** a shadow copy deletion, mass file renames, ransom-note files or a recovery change.

---

## Credential access

Playbook: [Credential compromise, Closing as a false positive](../scenarios/06-credential-compromise/playbook.md#closing-as-a-false-positive).

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| A process opened `lsass.exe` | AV/EDR vendors inspect LSASS for credential protection (CrowdStrike, SentinelOne, Carbon Black, Defender itself) | It runs from the security vendor's install folder. `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` with `IsTrusted` true. The product is deployed at this customer (asset list or ticket). No dump command, dump file or credential-sweep hit on the device |
| SAM, SYSTEM or SECURITY hive saved, or `NTDS.dit` copied | Backup software taking a system-state backup; Defender for Identity sensor | Don't close yourself; the IR lead decides. The customer names the backup job and its window |
| Credential-access detections from a network source IP | Authorised Nessus / Qualys / Tenable scan | Source IP on client-approved scan schedule; check with client or scan ticket |

> **Still escalate if:** the process is unsigned, runs from `%TEMP%` or `%APPDATA%`, or no authorised scan is scheduled.

---

## C2 / Network

Playbooks: [C2 beaconing](../scenarios/08-c2-beaconing/playbook.md#closing-as-a-false-positive), [Suspicious network activity](../scenarios/03-suspicious-network-activity/playbook.md#closing-as-a-false-positive), [LOTS & cloud C2](../scenarios/09-lots-cloud-c2/playbook.md#closing-as-a-false-positive).

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| Regular outbound beaconing to cloud relay IP | RMM heartbeat — ScreenConnect, NinjaOne, Datto RMM, AnyDesk, TeamViewer | The RMM tool is on the customer's approved list, and a change record explains the install, its time and its installer. `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` with `IsTrusted` true. The destination is infrastructure the vendor documents for that product. A fixed interval is not evidence: it is also Cobalt Strike's default |
| Large outbound data volume to cloud storage | OneDrive, Dropbox, Google Drive, Box syncing | Client runs from the vendor's install folder, and `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` with `IsTrusted` true. The product is deployed at this customer (asset list or ticket). For SharePoint or OneDrive, the host belongs to the customer's own tenant |
| Outbound on non-standard port from management process | RMM agents use fixed non-standard ports (e.g., ScreenConnect on 8041) | Same as regular outbound beaconing above. Consistent single destination; no shell started by the process |
| Internal port scan or SMB enumeration from a single IP | Authorised vulnerability scan — Nessus, Qualys, Nexpose | The scanner's process and signer match the approved scanner, the customer confirms the scan window, and the device's role explains it |

> **Still escalate if:** the RMM tool isn't on the approved list or was installed outside a change record, the RMM process started a shell, or the beacon runs inside a signed or Microsoft process.

---

## Lateral movement

Playbooks: [Suspicious process](../scenarios/02-suspicious-process/playbook.md#closing-as-a-false-positive), [Credential compromise](../scenarios/06-credential-compromise/playbook.md#closing-as-a-false-positive), [Suspicious network activity](../scenarios/03-suspicious-network-activity/playbook.md#closing-as-a-false-positive).

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| PsExec / PsExecSvc pattern on remote hosts | RMM tools and SCCM deploy agents and run scripts via PsExec-equivalent mechanisms | Don't close yourself; the IR lead decides. The customer confirms the RMM agent is theirs and names the job |
| Same binary executing across multiple devices simultaneously | SCCM or Intune pushing a software update or compliance script | The customer names the deployment job and the package, and the binary matches it |
| WMI remote execution to internal IPs | SCCM hardware inventory, monitoring agents, IT admin scripting | Don't close yourself; the IR lead decides. The customer confirms the agent or script is theirs and names the job |
| Internal scanning and enumeration | Authorised pen test or vulnerability scan | Source IP on approved scan schedule; cross-reference with client scan ticket |

> **Still escalate if:** execution spreads to hosts the initiating account has no documented reason to access.

---

## Persistence

Playbook: [Persistence detected, Closing as a false positive](../scenarios/04-persistence-detected/playbook.md#closing-as-a-false-positive).

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| New scheduled task created | Software installer, SCCM/Intune deployment, updater registering a maintenance task | The customer confirms the deployment job. The task's full command line, decoded if encoded, runs a file in the product's install folder |
| New service registered | Software installer, RMM agent install or auto-update, AV deployment | Service binary path is in `C:\Program Files\` or vendor directory; binary is signed; parent = signed installer. The asset list or a change record covers the product on this device. A remote-access tool is on the customer's approved list and was installed under a change record |
| Registry Run key added | Software installer adding autorun for a legitimate application | The value's data, decoded if encoded, runs a signed file in the product's install folder, with no script, DLL, URL or encoded argument in a user-writable folder; the customer confirms the installer or job |
| New WMI event subscription | Some enterprise monitoring tools (SCOM, SolarWinds) use WMI event subscriptions | Don't close yourself; the IR lead decides. The ticket names the monitoring product |

> **Still escalate if:** the task, service, or registry value points to a binary in `%TEMP%`, `%APPDATA%`, or any user-writable path, the binary is unsigned, or its arguments name a script, DLL, URL or encoded command in a user-writable path.

---

## Defence evasion

Playbook: [Defence evasion, Closing as a false positive](../scenarios/11-defence-evasion/playbook.md#closing-as-a-false-positive).

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| Defender real-time protection disabled via registry or PowerShell | IT admin temporarily disabling for SCCM software deployment or AV migration | A change record names this device, the exact setting, the account and the time, and the customer confirms it |
| AV exclusion added | IT configuring exclusions for backup software, line-of-business apps, or per vendor recommendation | A change record names this device, the exact path, the account and the time, and the customer confirms it. No user-writable folder, whole drive or common extension |
| Firewall rule added via `netsh` or `New-NetFirewallRule` | Software installer opening a port for a legitimate service | A change record covers the rule and the customer confirms the job |
| Audit log clearing (`wevtutil cl Security`, `wevtutil cl System`) | Rare — some server build scripts clear logs during provisioning | Don't close yourself; the IR lead decides. The ticket names the provisioning job |

> **Always escalate** a log clear, logging turned off, a tamper alert, or a Defender change with no change record.

---

## Scripting / Admin tooling

Playbooks: [Suspicious process](../scenarios/02-suspicious-process/playbook.md#closing-as-a-false-positive), [LOLBin abuse](../scenarios/07-lolbin-abuse/playbook.md#closing-as-a-false-positive), [ClickFix](../scenarios/13-clickfix/playbook.md#closing-as-a-false-positive).

| Trigger | Legitimate cause | How to confirm |
|---------|-----------------|----------------|
| PowerShell with `-EncodedCommand` or `-ExecutionPolicy Bypass` | SCCM/Intune deployment scripts, IT automation, vendor install wrappers | Decoded command is documented, and the parent is confirmed as the customer's installation of the management agent |
| `Invoke-Expression` / `IEX` in PowerShell command line | Legitimate admin frameworks (PSWindowsUpdate, some RMM-pushed scripts) | Decoded payload is readable and matches a documented script; no outbound connection follows |
| `certutil.exe -decode` or `-urlcache` | Certificate management, some installers use certutil to fetch packages | `-decode` or `-decodehex`: only if input and output are in the product's own folder and the output isn't an executable or script, and the customer confirms the parent. `-urlcache`, `-verifyctl` or `-URL` to an external URL is never a false positive |
| `wmic.exe` process or query execution, or the CIM equivalents (`Get-CimInstance`, `Invoke-CimMethod`); WMIC is removed on Windows 11 24H2 and later | SCCM hardware inventory, IT admin scripts, monitoring tools | Query is read-only (`SELECT` statements); the parent is confirmed as the customer's management agent; no file write or remote execution follows |
| `mshta.exe` execution | Some legacy enterprise applications use HTA interfaces | A named product confirmed by the asset list or a change record, with the HTA in its install folder. Any URL argument is not a false positive |
| User pastes into Run dialog or PowerShell during a support session ([ClickFix](../scenarios/13-clickfix/investigation.md) look-alike) | Helpdesk/remote-assistance session (Quick Assist, TeamViewer, RDP) has the user press Win+R and paste a one-line diagnostic or repair command | The customer's helpdesk, not the user, confirms a ticket opened before the paste that names the technician and the command; the command, decoded, matches a documented script or a vendor's published repair command word for word. A remote session alone proves nothing: attackers pose as IT support. See [Closing as a false positive](../scenarios/13-clickfix/playbook.md#closing-as-a-false-positive) |
| User pastes a documented internal script | Company-approved PowerShell one-liner from an internal wiki/runbook (e.g. mapping a drive, clearing a cache, re-registering an agent) | Command line matches a known internal script verbatim; source is an internal wiki/SharePoint URL, not an external page; the customer names the script and the ticket or wiki page |
| User pastes a vendor support/repair command | Vendor support page tells the user to paste a command to repair or reinstall an agent (VPN clients, printer drivers, conferencing software) | The vendor's published page or the customer's ticket names the exact command and host. No fake CAPTCHA/"verify you're human" prompt preceded it. "Not newly registered" isn't evidence: a compromised site is an old domain |

> **Still escalate if:** the decoded PowerShell command downloads and executes a second-stage payload, any LOLBin execution is immediately followed by an outbound connection to an external host (for a BITS job, also check `svchost.exe` with `BITS` in its command line), or the user reports being told to "verify you're human" or "fix an error" immediately before pasting — that framing is specific to [ClickFix](../scenarios/13-clickfix/investigation.md) lures and isn't something legitimate IT support or vendor instructions use.

---

## Cross-reference: escalation-triggers.md

A confirmed false positive **must not** match any item in [escalation-triggers.md](escalation-triggers.md). Before closing as FP, verify all of the following:

- [ ] No ransom note files present in `DeviceFileEvents`
- [ ] No credential-dumping tool or technique (Mimikatz, `comsvcs.dll MiniDump`, `rundll32.exe comsvcs.dll`)
- [ ] No C2 beaconing from a process that isn't a named, sanctioned product
- [ ] No lateral movement beyond what the legitimate tool explains
- [ ] No evidence of attacker covering tracks — log clearing after suspicious activity, EDR tampered or killed

If any item above cannot be confirmed, **escalate rather than assume FP**.

---

## Documenting a false positive

```
Alert:                [alert name / rule name / Sentinel analytic]
Why it triggered:     [specific behaviour — e.g., "scheduled task created by the Contoso Agent installer"]
Benign cause:         [named product, job or change — e.g., "Contoso Agent 5.2 rollout, change record CHG0012345"]
Confirmation method:  [specific field/log checked — e.g., "Customer confirmed the job in the ticket; task runs a file in the product's install folder; DeviceFileCertificateInfo shows Contoso as Signer, IsTrusted true"]
Verdict:              False positive
Suppression recommended: Yes / No / Already exists
  If yes — scope:     [narrow scope — process name, hash, path, or account; avoid broad wildcard rules]
```

> Before recommending suppression, confirm the rule has no other active detections on this device. Broad suppressions mask real activity.
