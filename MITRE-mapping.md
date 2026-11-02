# MITRE ATT&CK mapping

Full mapping of soc-runbook detection content to MITRE ATT&CK tactics and techniques.

Framework version: ATT&CK v20.0 (Enterprise). IDs, names and tactics checked against attack.mitre.org on 2026-11-02.  
Coverage: Techniques commonly seen in incidents handled at a UK MSSP targeting SME and mid-market organisations.

ATT&CK v20 replaced the Defense Evasion tactic with **Stealth** and **Defense Impairment**. IDs this repo used to cite now redirect: T1562.001 and T1562.006 to T1685 (Disable or Modify Tools), T1562.002 to T1685.001, and T1070.001 to T1685.005.

---

## Coverage by tactic

Counts are per technique ID, using the strongest status among that ID's rows in the tactic.

| Tactic | Techniques mapped | Query | Guidance | Gap |
|--------|-------------------|-------|----------|-----|
| Initial Access | T1566.001, T1566.002, T1566.003, T1078, T1133, T1189, T1195 | 2 | 3 | 2 |
| Execution | T1059.001, T1059.005, T1059.007, T1106, T1204.002, T1204.004, T1047 | 5 | 0 | 2 |
| Persistence | T1547.001, T1547.004, T1053.005, T1543.003, T1546.003, T1136.001 | 6 | 0 | 0 |
| Privilege Escalation | T1548.002, T1055, T1078 | 0 | 2 | 1 |
| Stealth | T1027, T1140, T1036.005, T1055, T1070.006, T1218.005, T1218.010, T1218.011, T1197 | 6 | 1 | 2 |
| Defense Impairment | T1112, T1685, T1685.001, T1685.005 | 2 | 1 | 1 |
| Credential Access | T1003.001, T1003.002, T1003.003, T1003.006, T1558.003, T1558.004, T1621 | 7 | 0 | 0 |
| Discovery | T1018, T1057, T1082, T1083, T1046 | 1 | 0 | 4 |
| Lateral Movement | T1021.001, T1021.002, T1021.006, T1550.002 | 1 | 0 | 3 |
| Collection | T1560, T1074 | 0 | 0 | 2 |
| Command and Control | T1071.001, T1071.004, T1095, T1105, T1102, T1102.001, T1571, T1573 | 6 | 0 | 2 |
| Exfiltration | T1041, T1567.002, T1567.001 | 1 | 0 | 2 |
| Impact | T1486, T1490, T1489 | 2 | 0 | 1 |

---

## Technique detail

Status: **Query** = a linked `.kql` file implements the detection. **Guidance** = a linked doc describes it (some docs include an inline query), with no `.kql` file. **Gap** = neither the linked file nor any other repo content implements it; the link is kept for context.

### Initial Access

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Phishing — spearphishing attachment | T1566.001 | Malicious attachment delivered via email | Query | [office-spawning-shells.kql](kql/process/office-spawning-shells.kql) |
| Phishing — spearphishing link | T1566.002 | User clicks malicious link from email | Guidance | [12-phishing-email/investigation.md](docs/scenarios/12-phishing-email/investigation.md) |
| Phishing — spearphishing via service (Teams) | T1566.003 | External Teams message with malicious content | Gap | [12-phishing-email/investigation.md](docs/scenarios/12-phishing-email/investigation.md) |
| Valid accounts | T1078 | Credential-based logon from unusual location | Query | [entra-impossible-travel.kql](kql/identity/entra-impossible-travel.kql) |
| External remote services (RDP) | T1133 | RDP brute force — many failures then success | Guidance | [10-initial-access/investigation.md](docs/scenarios/10-initial-access/investigation.md) |
| Drive-by compromise | T1189 | Browser download of executable or script | Guidance | [10-initial-access/investigation.md](docs/scenarios/10-initial-access/investigation.md) |
| Supply chain compromise | T1195 | Trojanised installer or update | Gap | [10-initial-access/investigation.md](docs/scenarios/10-initial-access/investigation.md) |

---

### Execution

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| PowerShell | T1059.001 | Encoded commands, download cradles, AMSI bypass | Query | [suspicious-powershell.kql](kql/process/suspicious-powershell.kql), [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Visual Basic | T1059.005 | wscript/cscript spawning shells | Gap | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| JavaScript | T1059.007 | mshta inline JavaScript execution | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Native API | T1106 | Process hollowing via memory write APIs | Gap | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| User execution — malicious file | T1204.002 | User opens phishing attachment | Query | [office-spawning-shells.kql](kql/process/office-spawning-shells.kql) |
| User execution — malicious copy and paste | T1204.004 | User pastes an attacker-supplied command into Run dialog or PowerShell after a fake CAPTCHA/verification prompt (ClickFix) | Query | [clickfix-lolbin-from-browser-explorer.kql](kql/process/clickfix-lolbin-from-browser-explorer.kql) |
| Windows Management Instrumentation | T1047 | wmic process call create, wmic /node: remote execution | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |

---

### Persistence

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Registry run keys | T1547.001 | Run/RunOnce key modifications | Query | [registry-run-key-modifications.kql](kql/persistence/registry-run-key-modifications.kql) |
| Winlogon helper DLL | T1547.004 | Winlogon key modifications | Query | [registry-run-key-modifications.kql](kql/persistence/registry-run-key-modifications.kql) |
| Scheduled task | T1053.005 | Task creation via schtasks.exe | Query | [scheduled-task-creation.kql](kql/persistence/scheduled-task-creation.kql) |
| Windows service | T1543.003 | New service installed | Query | [new-services-installed.kql](kql/persistence/new-services-installed.kql) |
| WMI event subscription | T1546.003 | WMI filter, consumer, binding creation | Query | [wmi-subscription-creation.kql](kql/persistence/wmi-subscription-creation.kql) |
| Local account creation | T1136.001 | New local user account created | Query | [new-local-accounts-created.kql](kql/identity/new-local-accounts-created.kql) |

---

### Privilege Escalation

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Bypass User Account Control | T1548.002 | fodhelper, eventvwr, computerdefaults spawning children | Guidance | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Process injection | T1055 | Legitimate process making unexpected network connections | Guidance | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Valid accounts | T1078 | Compromised account used for privilege escalation | Gap | [user-on-multiple-devices.kql](kql/identity/user-on-multiple-devices.kql) |

---

### Stealth

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Obfuscated files or information | T1027 | Base64 encoded PowerShell, char array obfuscation | Query | [suspicious-powershell.kql](kql/process/suspicious-powershell.kql) |
| Deobfuscate/decode files or information | T1140 | certutil -decode | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Masquerading — match legitimate resource name or location | T1036.005 | Executables in Temp/AppData with system process names | Gap | [executables-in-suspicious-paths.kql](kql/files/executables-in-suspicious-paths.kql) |
| Process injection | T1055 | Memory API calls from unexpected processes | Guidance | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Indicator removal — timestomp | T1070.006 | Files with suspiciously old timestamps in temp paths | Gap | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| System binary proxy execution — Mshta | T1218.005 | mshta with a URL or inline vbscript:/javascript: | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| System binary proxy execution — Regsvr32 | T1218.010 | regsvr32 remote scriptlet (/i: URL, scrobj.dll) | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| System binary proxy execution — Rundll32 | T1218.011 | rundll32 comsvcs MiniDump, javascript:, DLL in Temp/AppData | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| BITS jobs | T1197 | bitsadmin /transfer or SetNotifyCmdLine | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |

---

### Defense Impairment

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Modify registry | T1112 | UAC bypass registry modifications | Guidance | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Disable or modify tools — Defender | T1685 | Defender disabled via registry | Query | [defence-evasion-defender-disabled.kql](kql/ransomware/defence-evasion-defender-disabled.kql) |
| Disable or modify tools — AMSI bypass (variant) | T1685 | AmsiUtils / amsiInitFailed in PowerShell command line | Guidance | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Disable or modify tools — security process killed | T1685 | Security tools killed via taskkill | Guidance | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Disable or modify tools — ETW tampering | T1685 | ETW patching | Gap | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Disable or modify Windows event log | T1685.001 | Audit policy modification | Gap | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Clear Windows event logs | T1685.005 | wevtutil cl, Clear-EventLog | Query | [event-log-clearing.kql](kql/ransomware/event-log-clearing.kql) |

---

### Credential Access

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| OS credential dumping — LSASS memory | T1003.001 | lsass.exe accessed by non-Windows process | Query | [lsass-access-credential-dump.kql](kql/identity/lsass-access-credential-dump.kql), [credential-access-sweep.kql](kql/process/credential-access-sweep.kql), [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| OS credential dumping — SAM | T1003.002 | SAM hive read by non-system process | Query | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql) |
| OS credential dumping — NTDS | T1003.003 | NTDS.dit accessed by non-system process | Query | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql) |
| OS credential dumping — DCSync | T1003.006 | DCSync, drsuapi, DrsGetNCChanges in command lines | Query | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql) |
| Kerberoasting | T1558.003 | GetUserSPNs, Invoke-Kerberoast in command lines | Query | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql) |
| AS-REP roasting | T1558.004 | GetNPUsers, ASREPRoast in command lines | Query | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql) |
| MFA request generation (MFA fatigue) | T1621 | 5+ failed MFA prompts in 10 minutes | Query | [entra-mfa-fatigue.kql](kql/identity/entra-mfa-fatigue.kql) |

---

### Discovery

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Remote system discovery | T1018 | wmic querying network, arp -a, nslookup sweeps | Gap | [02-suspicious-process/investigation.md](docs/scenarios/02-suspicious-process/investigation.md) |
| Process discovery | T1057 | wmic process list, tasklist in command lines | Gap | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| System info discovery | T1082 | wmic computersystem, systeminfo, hostname | Gap | [02-suspicious-process/investigation.md](docs/scenarios/02-suspicious-process/investigation.md) |
| File and directory discovery | T1083 | dir /s, Get-ChildItem recursing filesystem | Gap | [05-malicious-file/investigation.md](docs/scenarios/05-malicious-file/investigation.md) |
| Network service discovery | T1046 | Device probing many internal IPs on SMB, RDP, SSH, RPC and WinRM ports | Query | [lateral-movement-scanning.kql](kql/network/lateral-movement-scanning.kql) |

---

### Lateral Movement

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| RDP | T1021.001 | Account logging into new devices via RemoteInteractive | Query | [user-on-multiple-devices.kql](kql/identity/user-on-multiple-devices.kql) |
| SMB / Windows Admin Shares | T1021.002 | Confirmed SMB logon or admin-share use (the scanning query shows port-445 attempts only) | Gap | [lateral-movement-scanning.kql](kql/network/lateral-movement-scanning.kql) |
| WinRM | T1021.006 | Confirmed WinRM session (the scanning query shows port 5985/5986 attempts only) | Gap | [lateral-movement-scanning.kql](kql/network/lateral-movement-scanning.kql) |
| Pass the Hash | T1550.002 | Network logons from unexpected source using domain account | Gap | [06-credential-compromise/investigation.md](docs/scenarios/06-credential-compromise/investigation.md) |

---

### Collection

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Archive collected data | T1560 | No query or investigation step in the repo | Gap | — |
| Data staged | T1074 | No query or investigation step in the repo | Gap | — |

---

### Command and Control

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Application layer protocol — web | T1071.001 | Regular beaconing over HTTP/S; ClickFix LOLBin callout to its staging/C2 domain | Query | [beacon-suspicion-score.kql](kql/network/beacon-suspicion-score.kql), [beacon-high-connection-count.kql](kql/network/beacon-high-connection-count.kql), [beacon-interval-regularity.kql](kql/network/beacon-interval-regularity.kql), [beacon-after-hours.kql](kql/network/beacon-after-hours.kql), [clickfix-callout-correlation.kql](kql/network/clickfix-callout-correlation.kql) |
| Application layer protocol — DNS | T1071.004 | DNS tunnelling via encoded subdomains | Query | [dns-tunnelling.kql](kql/network/dns-tunnelling.kql) |
| Non-application layer protocol | T1095 | Raw socket connections, unusual protocol usage | Gap | [unusual-outbound-ports.kql](kql/network/unusual-outbound-ports.kql) |
| Ingress tool transfer | T1105 | certutil -urlcache, bitsadmin /transfer downloads | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Web service — LOTS | T1102 | Scripting engine connecting to Discord, Telegram, Pastebin, cloud storage | Query | [lots-suspicious-process-to-cloud.kql](kql/network/lots-suspicious-process-to-cloud.kql), [lots-scripting-engine-to-cloud-storage.kql](kql/network/lots-scripting-engine-to-cloud-storage.kql) |
| Web service — smart contract C2 (EtherHiding) | T1102 | Non-browser process querying a BSC/EVM RPC endpoint to read attacker-staged commands from a smart contract; IOC is an RPC host + contract address, not a domain | Query | [clickfix-etherhiding-rpc-callout.kql](kql/network/clickfix-etherhiding-rpc-callout.kql) |
| Web service — dead drop resolver | T1102.001 | Paste service GET followed by raw IP connection | Query | [lots-dead-drop-resolver.kql](kql/network/lots-dead-drop-resolver.kql) |
| Non-standard port | T1571 | Connections on ports 4444, 50050, 1337, 8080, etc. | Query | [unusual-outbound-ports.kql](kql/network/unusual-outbound-ports.kql) |
| Encrypted channel | T1573 | Low-volume HTTPS beaconing to single CDN IP | Gap | [beacon-interval-regularity.kql](kql/network/beacon-interval-regularity.kql) |

---

### Exfiltration

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Exfil over C2 channel | T1041 | Large outbound transfers from unexpected process | Gap | [03-suspicious-network-activity/investigation.md](docs/scenarios/03-suspicious-network-activity/investigation.md) |
| Exfil to cloud storage | T1567.002 | Non-browser process connecting to OneDrive, S3, Dropbox and other cloud storage (connection count; no volume data) | Query | [lots-exfiltration-via-cloud.kql](kql/network/lots-exfiltration-via-cloud.kql) |
| Exfil to code repository | T1567.001 | Non-browser process pushing to GitHub (the linked query flags any connection; push not confirmed) | Gap | [lots-scripting-engine-to-cloud-storage.kql](kql/network/lots-scripting-engine-to-cloud-storage.kql) |

---

### Impact

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Data encrypted for impact (ransomware) | T1486 | Mass file renames, new extensions across filesystem | Query | [mass-file-renames.kql](kql/ransomware/mass-file-renames.kql) |
| Inhibit system recovery | T1490 | VSS deletion, bcdedit recovery disabled | Query | [vss-shadow-copy-deletion.kql](kql/ransomware/vss-shadow-copy-deletion.kql), [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Service stop | T1489 | Services stopped for impact (net stop / sc stop); killing security tools is under T1685 | Gap | — |
