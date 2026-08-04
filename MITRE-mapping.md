# MITRE ATT&CK mapping

Full mapping of soc-runbook detection content to MITRE ATT&CK tactics and techniques.

Framework version: ATT&CK v14 (Enterprise)  
Coverage: Techniques commonly seen in incidents handled at a UK MSSP targeting SME and mid-market organisations.

---

## Coverage by tactic

| Tactic | Techniques covered |
|--------|-------------------|
| Initial Access | T1078, T1133, T1189, T1195, T1566.001, T1566.002, T1566.003 |
| Execution | T1059.001, T1059.005, T1059.007, T1106, T1204.002, T1218 |
| Persistence | T1053.005, T1098.001, T1098.003, T1136.001, T1543.003, T1546.003, T1547.001 |
| Privilege Escalation | T1548.002, T1055, T1078 |
| Defence Evasion | T1027, T1036.005, T1055, T1070.001, T1112, T1218, T1562.001, T1562.002 |
| Credential Access | T1003.001, T1003.002, T1003.003, T1528, T1539, T1556.006, T1558.003, T1558.004, T1621 |
| Discovery | T1016, T1018, T1033, T1057, T1082, T1083, T1087.001, T1087.002, T1482 |
| Lateral Movement | T1021.001, T1021.002, T1021.006, T1550.002 |
| Collection | T1114, T1114.003, T1213, T1560, T1074 |
| Command and Control | T1071.001, T1071.004, T1095, T1102, T1102.001, T1568.002, T1571, T1573 |
| Exfiltration | T1041, T1567, T1567.002 |
| Impact | T1486, T1490, T1489 |

---

## Technique detail

### Initial Access

| Technique | ID | Detection | KQL |
|-----------|-----|-----------|-----|
| Phishing — spearphishing attachment | T1566.001 | Malicious attachment delivered via email | [office-spawning-shells.kql](kql/process/office-spawning-shells.kql) |
| Phishing — spearphishing link | T1566.002 | User clicks malicious link from email | [docs/13-email-investigation.md](docs/13-email-investigation.md) |
| Phishing — spearphishing via Teams | T1566.003 | External Teams message with malicious content | [docs/13-email-investigation.md](docs/13-email-investigation.md) |
| Valid accounts | T1078 | Credential-based logon from unusual location | [entra-impossible-travel.kql](kql/identity/entra-impossible-travel.kql) |
| External remote services (RDP) | T1133 | RDP brute force — many failures then success | [docs/11-initial-access.md](docs/11-initial-access.md) |
| Drive-by compromise | T1189 | Browser download of executable or script | [docs/11-initial-access.md](docs/11-initial-access.md) |
| Supply chain compromise | T1195 | Trojanised installer or update | [docs/11-initial-access.md](docs/11-initial-access.md) |

---

### Execution

| Technique | ID | Detection | KQL |
|-----------|-----|-----------|-----|
| PowerShell | T1059.001 | Encoded commands, download cradles, AMSI bypass | [suspicious-powershell.kql](kql/process/suspicious-powershell.kql) |
| Visual Basic (VBScript) | T1059.005 | wscript/cscript spawning shells | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| JavaScript | T1059.007 | mshta inline JavaScript execution | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Native API | T1106 | Process hollowing via memory write APIs | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| User execution — malicious file | T1204.002 | User opens phishing attachment | [office-spawning-shells.kql](kql/process/office-spawning-shells.kql) |
| Signed binary proxy execution | T1218 | certutil, mshta, regsvr32, rundll32, wmic, bitsadmin | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |

---

### Persistence

| Technique | ID | Detection | KQL |
|-----------|-----|-----------|-----|
| Registry run keys | T1547.001 | Run/RunOnce key modifications | [registry-run-key-modifications.kql](kql/persistence/registry-run-key-modifications.kql) |
| Scheduled task | T1053.005 | Task creation via schtasks.exe | [scheduled-task-creation.kql](kql/persistence/scheduled-task-creation.kql) |
| Windows service | T1543.003 | New service installed | [new-services-installed.kql](kql/persistence/new-services-installed.kql) |
| WMI event subscription | T1546.003 | WMI filter, consumer, binding creation | [wmi-subscription-creation.kql](kql/persistence/wmi-subscription-creation.kql) |
| Local account creation | T1136.001 | New local user account created | [new-local-accounts-created.kql](kql/identity/new-local-accounts-created.kql) |
| Account manipulation — additional cloud credentials | T1098.001 | New MFA methods, service principals, or app registrations added post-compromise | [entra-post-compromise-persistence.kql](kql/identity/entra-post-compromise-persistence.kql) |
| Account manipulation — additional cloud roles | T1098.003 | New Conditional Access exclusions, guest invites, or directory role assignments post-compromise | [entra-post-compromise-persistence.kql](kql/identity/entra-post-compromise-persistence.kql) |

---

### Privilege Escalation

| Technique | ID | Detection | KQL |
|-----------|-----|-----------|-----|
| UAC bypass | T1548.002 | fodhelper, eventvwr, computerdefaults spawning children | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| Process injection | T1055 | Legitimate process making unexpected network connections | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| Valid accounts | T1078 | Compromised account used for privilege escalation | [user-on-multiple-devices.kql](kql/identity/user-on-multiple-devices.kql) |

---

### Defence Evasion

| Technique | ID | Detection | KQL |
|-----------|-----|-----------|-----|
| Obfuscated files / encoding | T1027 | Base64 encoded PowerShell, char array obfuscation | [suspicious-powershell.kql](kql/process/suspicious-powershell.kql) |
| Masquerading — match legitimate name | T1036.005 | Executables in Temp/AppData with system process names | [executables-in-suspicious-paths.kql](kql/files/executables-in-suspicious-paths.kql) |
| Process injection | T1055 | Memory API calls from unexpected processes | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| Indicator removal — clear event logs | T1070.001 | wevtutil cl, Clear-EventLog | [event-log-clearing.kql](kql/ransomware/event-log-clearing.kql) |
| Modify registry | T1112 | UAC bypass registry modifications | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| Signed binary proxy execution | T1218 | LOLBin abuse | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Impair defences — disable AV | T1562.001 | Defender disabled via registry | [defence-evasion-defender-disabled.kql](kql/ransomware/defence-evasion-defender-disabled.kql) |
| Impair defences — disable logging | T1562.002 | ETW patching, audit policy modification | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| AMSI bypass | T1562.001 | AmsiUtils / amsiInitFailed in PowerShell command line | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| Timestomping | T1070.006 | Files with suspiciously old timestamps in temp paths | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |

---

### Credential Access

| Technique | ID | Detection | KQL |
|-----------|-----|-----------|-----|
| OS credential dumping — lsass | T1003.001 | lsass.exe accessed by non-Windows process | [lsass-access-credential-dump.kql](kql/identity/lsass-access-credential-dump.kql) |
| OS credential dumping — SAM | T1003.002 | SAM hive read by non-system process | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql) |
| OS credential dumping — NTDS | T1003.003 | NTDS.dit accessed by non-system process | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql) |
| Kerberoasting | T1558.003 | GetUserSPNs, Invoke-Kerberoast in command lines | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql) |
| AS-REP roasting | T1558.004 | GetNPUsers, ASREPRoast in command lines | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql) |
| MFA fatigue | T1621 | 5+ failed MFA prompts in 10 minutes | [entra-mfa-fatigue.kql](kql/identity/entra-mfa-fatigue.kql) |
| Modify authentication process — device registration | T1556.006 | Device code auth flow, flagged from new locations or outside business hours | [entra-device-code-auth-flow.kql](kql/identity/entra-device-code-auth-flow.kql) |
| Steal web session cookie | T1539 | Token replay, impossible travel post-MFA, compliance-state drop, UserAgent mismatch | [entra-aitm-session-anomalies.kql](kql/identity/entra-aitm-session-anomalies.kql) |
| Steal application access token | T1528 | Suspicious OAuth consent grant within 1h of a suspicious sign-in | [entra-post-compromise-oauth-grants.kql](kql/identity/entra-post-compromise-oauth-grants.kql) |

---

### Discovery

| Technique | ID | Detection | KQL |
|-----------|-----|-----------|-----|
| Remote system discovery | T1018 | wmic querying network, arp -a, nslookup sweeps | [docs/02-process-investigation.md](docs/02-process-investigation.md) |
| Process discovery | T1057 | wmic process list, tasklist in command lines | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| System info discovery | T1082 | wmic computersystem, systeminfo, hostname | [docs/02-process-investigation.md](docs/02-process-investigation.md) |
| File and directory discovery | T1083 | dir /s, Get-ChildItem recursing filesystem | [docs/05-file-artefacts.md](docs/05-file-artefacts.md) |
| System owner/user discovery | T1033 | whoami run as part of a post-compromise recon burst | [post-compromise-discovery-commands.kql](kql/process/post-compromise-discovery-commands.kql) |
| Account discovery — local account | T1087.001 | net user in a post-compromise recon burst | [post-compromise-discovery-commands.kql](kql/process/post-compromise-discovery-commands.kql) |
| Account discovery — domain account | T1087.002 | net localgroup administrators in a post-compromise recon burst | [post-compromise-discovery-commands.kql](kql/process/post-compromise-discovery-commands.kql) |
| Domain trust discovery | T1482 | nltest /domain_trusts in a post-compromise recon burst | [post-compromise-discovery-commands.kql](kql/process/post-compromise-discovery-commands.kql) |
| System network configuration discovery | T1016 | ipconfig /all, nslookup, arp -a in a post-compromise recon burst | [post-compromise-discovery-commands.kql](kql/process/post-compromise-discovery-commands.kql) |

---

### Lateral Movement

| Technique | ID | Detection | KQL |
|-----------|-----|-----------|-----|
| RDP | T1021.001 | Account logging into new devices via RemoteInteractive | [user-on-multiple-devices.kql](kql/identity/user-on-multiple-devices.kql) |
| SMB / Windows Admin Shares | T1021.002 | Connections to port 445 on multiple internal IPs | [lateral-movement-scanning.kql](kql/network/lateral-movement-scanning.kql) |
| WinRM | T1021.006 | Connections to port 5985/5986 on multiple internal IPs | [lateral-movement-scanning.kql](kql/network/lateral-movement-scanning.kql) |
| Pass the Hash | T1550.002 | Network logons from unexpected source using domain account | [docs/06-identity-and-credentials.md](docs/06-identity-and-credentials.md) |

---

### Collection

| Technique | ID | Detection | KQL |
|-----------|-----|-----------|-----|
| Email collection | T1114 | Unusual volume of MailItemsAccessed, mail export operations, or non-admin eDiscovery searches post-compromise | [entra-post-compromise-email-exfil.kql](kql/identity/entra-post-compromise-email-exfil.kql) |
| Email collection — forwarding rule | T1114.003 | Inbox rule forwards externally, deletes by keyword, or marks as read post-compromise | [entra-post-compromise-mailbox-rules.kql](kql/identity/entra-post-compromise-mailbox-rules.kql) |
| Data from information repositories | T1213 | Bulk SharePoint/OneDrive access above baseline, off-hours access, or external sharing post-compromise | [entra-post-compromise-sharepoint-access.kql](kql/identity/entra-post-compromise-sharepoint-access.kql) |

---

### Command and Control

| Technique | ID | Detection | KQL |
|-----------|-----|-----------|-----|
| Application layer protocol — web | T1071.001 | Regular beaconing over HTTP/S | [beacon-suspicion-score.kql](kql/network/beacon-suspicion-score.kql) |
| Application layer protocol — DNS | T1071.004 | DNS tunnelling via encoded subdomains | [dns-tunnelling.kql](kql/network/dns-tunnelling.kql) |
| Non-application layer protocol | T1095 | Raw socket connections, unusual protocol usage | [unusual-outbound-ports.kql](kql/network/unusual-outbound-ports.kql) |
| Web service — LOTS | T1102 | Scripting engine connecting to Discord, Telegram, Pastebin | [lots-suspicious-process-to-cloud.kql](kql/network/lots-suspicious-process-to-cloud.kql) |
| Web service — dead drop | T1102.001 | Paste service GET followed by raw IP connection | [lots-dead-drop-resolver.kql](kql/network/lots-dead-drop-resolver.kql) |
| Dynamic resolution — newly registered domains | T1568.002 | DNS queries to domains never queried by a device before infection | [post-compromise-c2-from-malware.kql](kql/network/post-compromise-c2-from-malware.kql) |
| Non-standard port | T1571 | Connections on ports 4444, 50050, 1337, 8080, etc. | [unusual-outbound-ports.kql](kql/network/unusual-outbound-ports.kql) |
| Encrypted channel | T1573 | Low-volume HTTPS beaconing to single CDN IP | [beacon-interval-regularity.kql](kql/network/beacon-interval-regularity.kql) |

---

### Exfiltration

| Technique | ID | Detection | KQL |
|-----------|-----|-----------|-----|
| Exfil over C2 channel | T1041 | Large outbound transfers from unexpected process | [docs/03-network-investigation.md](docs/03-network-investigation.md) |
| Exfil to cloud storage | T1567 | High-volume uploads to OneDrive, S3, Dropbox from non-browser | [lots-exfiltration-via-cloud.kql](kql/network/lots-exfiltration-via-cloud.kql) |
| Exfil to code repository | T1567.002 | Non-browser process pushing to GitHub | [lots-scripting-engine-to-cloud-storage.kql](kql/network/lots-scripting-engine-to-cloud-storage.kql) |

---

### Impact

| Technique | ID | Detection | KQL |
|-----------|-----|-----------|-----|
| Data encrypted for impact (ransomware) | T1486 | Mass file renames, new extensions across filesystem | [mass-file-renames.kql](kql/ransomware/mass-file-renames.kql) |
| Inhibit system recovery | T1490 | VSS deletion, bcdedit recovery disabled | [vss-shadow-copy-deletion.kql](kql/ransomware/vss-shadow-copy-deletion.kql) |
| Service stop | T1489 | Security tools killed via taskkill | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
