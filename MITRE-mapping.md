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
| Initial Access | T1566.001, T1566.002, T1566.003, T1078, T1078.004, T1133, T1189, T1195 | 3 | 3 | 2 |
| Execution | T1059.001, T1059.005, T1059.007, T1106, T1204.002, T1204.004, T1047 | 5 | 0 | 2 |
| Persistence | T1547.001, T1547.004, T1053.005, T1543.003, T1546.003, T1136.001, T1098.002 | 7 | 0 | 0 |
| Privilege Escalation | T1548.002, T1055, T1078 | 0 | 2 | 1 |
| Stealth | T1027, T1140, T1036.005, T1055, T1070.006, T1218.005, T1218.010, T1218.011, T1218.003, T1197, T1564.008 | 7 | 2 | 2 |
| Defense Impairment | T1112, T1685, T1685.001, T1685.005 | 2 | 1 | 1 |
| Credential Access | T1003.001, T1003.002, T1003.003, T1003.006, T1558.003, T1558.004, T1621, T1110.001, T1555.003, T1555.004, T1555.005, T1552.001, T1552.002, T1552.004, T1552.006, T1539 | 15 | 1 | 0 |
| Discovery | T1018, T1057, T1082, T1083, T1046 | 1 | 0 | 4 |
| Lateral Movement | T1021.001, T1021.002, T1021.006, T1550.002, T1550.001 | 2 | 0 | 3 |
| Collection | T1560.001, T1074.001, T1114.003 | 3 | 0 | 0 |
| Command and Control | T1071.001, T1071.004, T1095, T1105, T1102, T1102.001, T1571, T1573, T1572 | 7 | 0 | 2 |
| Exfiltration | T1041, T1567.002, T1567.001, T1567.004, T1048, T1052.001 | 5 | 0 | 1 |
| Impact | T1486, T1490, T1489 | 2 | 0 | 1 |

T1078 and T1055 each appear under two tactics, so the per-tactic rows sum to more than 85; the totals count each ID once.

---

## Technique detail

Status: **Query** = a linked `.kql` file implements the detection. **Guidance** = a linked doc describes it (some docs include an inline query), with no `.kql` file. **Gap** = neither the linked file nor any other repo content implements it; the link is kept for context.

### Initial Access

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Phishing — spearphishing attachment | T1566.001 | Office application (Word, Excel, PowerPoint, Outlook, OneNote, Access) spawning cmd, PowerShell, script hosts or LOLBins | Query | [office-spawning-shells.kql](kql/process/office-spawning-shells.kql) |
| Phishing — spearphishing link | T1566.002 | User clicks malicious link from email | Guidance | [12-phishing-email/investigation.md](docs/scenarios/12-phishing-email/investigation.md) |
| Phishing — spearphishing via service (Teams) | T1566.003 | External Teams message with malicious content | Gap | [12-phishing-email/investigation.md](docs/scenarios/12-phishing-email/investigation.md) |
| Valid accounts | T1078 | Successful sign-ins from more than one country within a 1-hour window | Query | [entra-impossible-travel.kql](kql/identity/entra-impossible-travel.kql) |
| Valid accounts — cloud accounts | T1078.004 | Entra sign-ins for an account from 24h before T0 onward, flagged where the IP was not seen in the 30 days before that window; includes non-interactive sign-ins (Sentinel) | Query | [entra-signin-after-endpoint-compromise.kql](kql/identity/entra-signin-after-endpoint-compromise.kql) |
| External remote services (RDP) | T1133 | RDP brute force — many failures then success | Guidance | [10-initial-access/investigation.md](docs/scenarios/10-initial-access/investigation.md) |
| Drive-by compromise | T1189 | Browser download of executable or script | Guidance | [10-initial-access/investigation.md](docs/scenarios/10-initial-access/investigation.md) |
| Supply chain compromise | T1195 | Trojanised installer or update | Gap | [10-initial-access/investigation.md](docs/scenarios/10-initial-access/investigation.md) |

---

### Execution

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| PowerShell | T1059.001 | Encoded commands, download cradles, hidden-window and no-profile flags in PowerShell command lines | Query | [suspicious-powershell.kql](kql/process/suspicious-powershell.kql), [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Visual Basic | T1059.005 | wscript/cscript spawning shells | Gap | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| JavaScript | T1059.007 | mshta inline JavaScript execution | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Native API | T1106 | Process hollowing via memory write APIs | Gap | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| User execution — malicious file | T1204.002 | Office application spawning a shell or LOLBin, as after a user opens a malicious document | Query | [office-spawning-shells.kql](kql/process/office-spawning-shells.kql) |
| User execution — malicious copy and paste | T1204.004 | powershell, pwsh, mshta or cmd launched by explorer.exe or a browser with an encoded, hidden-window or download-cradle command line, joined to browser activity within 5 minutes (ClickFix) | Query | [clickfix-lolbin-from-browser-explorer.kql](kql/process/clickfix-lolbin-from-browser-explorer.kql) |
| Windows Management Instrumentation | T1047 | wmic process call create, wmic /node: remote execution | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |

---

### Persistence

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Registry run keys | T1547.001 | Run/RunOnce key modifications | Query | [registry-run-key-modifications.kql](kql/persistence/registry-run-key-modifications.kql) |
| Winlogon helper DLL | T1547.004 | Winlogon key modifications | Query | [registry-run-key-modifications.kql](kql/persistence/registry-run-key-modifications.kql) |
| Scheduled task | T1053.005 | Task creation via schtasks.exe | Query | [scheduled-task-creation.kql](kql/persistence/scheduled-task-creation.kql) |
| Windows service | T1543.003 | New service installed | Query | [new-services-installed.kql](kql/persistence/new-services-installed.kql) |
| WMI event subscription | T1546.003 | DeviceEvents WmiFilterCreated, WmiConsumerCreated and WmiBindingCreated (ActionType names unverified; see the VERIFY note in the query) | Query | [wmi-subscription-creation.kql](kql/persistence/wmi-subscription-creation.kql) |
| Local account creation | T1136.001 | New local user account created | Query | [new-local-accounts-created.kql](kql/identity/new-local-accounts-created.kql) |
| Additional email delegate permissions | T1098.002 | Add-MailboxPermission and Add-RecipientPermission in Exchange audit (Sentinel OfficeActivity) | Query | [m365-mailbox-forwarding-rules.kql](kql/exfiltration/m365-mailbox-forwarding-rules.kql) |

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
| Obfuscated files or information | T1027 | Base64 encoded PowerShell (-enc, FromBase64String) | Query | [suspicious-powershell.kql](kql/process/suspicious-powershell.kql) |
| Deobfuscate/decode files or information | T1140 | certutil -decode | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Masquerading — match legitimate resource name or location | T1036.005 | Executables in Temp/AppData with system process names | Gap | [executables-in-suspicious-paths.kql](kql/files/executables-in-suspicious-paths.kql) |
| Process injection | T1055 | Memory API calls from unexpected processes | Guidance | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Indicator removal — timestomp | T1070.006 | Files with suspiciously old timestamps in temp paths | Gap | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| System binary proxy execution — Mshta | T1218.005 | mshta with a URL or inline vbscript:/javascript: | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| System binary proxy execution — Regsvr32 | T1218.010 | regsvr32 remote scriptlet (/i: URL, scrobj.dll) | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| System binary proxy execution — Rundll32 | T1218.011 | rundll32 command lines containing comsvcs, MiniDump, javascript:, AppData or Temp | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| System binary proxy execution — CMSTP | T1218.003 | Child processes launched by cmstp.exe (the cmstp.exe branch of the UAC-bypass query) | Guidance | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| BITS jobs | T1197 | bitsadmin /transfer or SetNotifyCmdLine | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Email hiding rules | T1564.008 | Inbox and transport rules that delete, move or mark mail as read (Sentinel OfficeActivity) | Query | [m365-mailbox-forwarding-rules.kql](kql/exfiltration/m365-mailbox-forwarding-rules.kql) |

---

### Defense Impairment

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Modify registry | T1112 | UAC bypass registry modifications | Guidance | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Disable or modify tools — Defender | T1685 | Defender policy values or exclusions set in the registry, Set-/Add-MpPreference disabling or excluding, and TamperingAttempt events (a hit is an attempt, not confirmed state) | Query | [defence-evasion-defender-disabled.kql](kql/ransomware/defence-evasion-defender-disabled.kql) |
| Disable or modify tools — AMSI bypass (variant) | T1685 | AmsiUtils / amsiInitFailed in PowerShell command line | Guidance | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Disable or modify tools — security process killed | T1685 | Security tools killed via taskkill | Guidance | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Disable or modify tools — ETW tampering | T1685 | ETW patching | Gap | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Disable or modify Windows event log | T1685.001 | Audit policy modification | Gap | [11-defence-evasion/investigation.md](docs/scenarios/11-defence-evasion/investigation.md) |
| Clear Windows event logs | T1685.005 | wevtutil cl, Clear-EventLog | Query | [event-log-clearing.kql](kql/ransomware/event-log-clearing.kql) |

---

### Credential Access

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| OS credential dumping — LSASS memory | T1003.001 | OpenProcessApiCall events whose AdditionalFields mention lsass (no process allow-list); sekurlsa:: and comsvcs/MiniDump in command lines; procdump, createdump and other dump tools aimed at lsass; lsass.dmp and other .dmp files in user-writable paths | Query | [lsass-access-credential-dump.kql](kql/identity/lsass-access-credential-dump.kql), [credential-access-sweep.kql](kql/process/credential-access-sweep.kql), [credential-dump-artefacts.kql](kql/identity/credential-dump-artefacts.kql), [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| OS credential dumping — SAM | T1003.002 | reg save HKLM\SAM (and SYSTEM, SECURITY) in command lines; SAM, SYSTEM or SECURITY hive copies created outside System32\config; file reads are not logged by MDE | Query | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql), [credential-dump-artefacts.kql](kql/identity/credential-dump-artefacts.kql) |
| OS credential dumping — NTDS | T1003.003 | ntdsutil or ntds.dit in command lines; ntdsutil IFM, esentutl, diskshadow and HarddiskVolumeShadowCopy copies; ntds.dit created outside the NTDS folder; file reads are not logged by MDE | Query | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql), [credential-dump-artefacts.kql](kql/identity/credential-dump-artefacts.kql) |
| OS credential dumping — DCSync | T1003.006 | DCSync, drsuapi, DrsGetNCChanges in command lines | Query | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql) |
| Kerberoasting | T1558.003 | GetUserSPNs, Invoke-Kerberoast in command lines | Query | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql) |
| AS-REP roasting | T1558.004 | GetNPUsers, ASREPRoast in command lines | Query | [credential-access-sweep.kql](kql/process/credential-access-sweep.kql) |
| MFA request generation (MFA fatigue) | T1621 | 5+ failed sign-ins requiring MFA per account in a 10-minute window | Query | [entra-mfa-fatigue.kql](kql/identity/entra-mfa-fatigue.kql) |
| Brute force — password guessing | T1110.001 | RDP logon failures (more than 10) or successes per public source IP, counting Network and RemoteInteractive logons | Guidance | [10-initial-access/investigation.md](docs/scenarios/10-initial-access/investigation.md) |
| Credentials from web browsers | T1555.003 | Non-browser process creating browser credential/cookie store files, command lines referencing them, known stealer tooling (file reads are not logged by MDE) | Query | [browser-credential-theft.kql](kql/identity/browser-credential-theft.kql) |
| Steal web session cookie | T1539 | Headless browser started with a remote debugging port; cookie store copied by a non-browser process | Query | [browser-credential-theft.kql](kql/identity/browser-credential-theft.kql) |
| Windows Credential Manager | T1555.004 | cmdkey /list, vaultcmd, keymgr.dll and credential-enumeration cmdlets in command lines | Query | [credential-store-and-secret-hunting.kql](kql/identity/credential-store-and-secret-hunting.kql) |
| Password managers | T1555.005 | KeePass vault (.kdbx) references in command lines | Query | [credential-store-and-secret-hunting.kql](kql/identity/credential-store-and-secret-hunting.kql) |
| Unsecured credentials — in files | T1552.001 | findstr / Select-String for passwords, unattend.xml, cloud and dev token files, saved remote-access client credentials, cloud CLI token requests | Query | [credential-store-and-secret-hunting.kql](kql/identity/credential-store-and-secret-hunting.kql) |
| Unsecured credentials — in registry | T1552.002 | reg query /f password in command lines | Query | [credential-store-and-secret-hunting.kql](kql/identity/credential-store-and-secret-hunting.kql) |
| Unsecured credentials — private keys | T1552.004 | id_rsa, id_ed25519 and similar key files referenced in command lines | Query | [credential-store-and-secret-hunting.kql](kql/identity/credential-store-and-secret-hunting.kql) |
| Unsecured credentials — group policy preferences | T1552.006 | Groups.xml and cpassword in command lines | Query | [credential-store-and-secret-hunting.kql](kql/identity/credential-store-and-secret-hunting.kql) |

---

### Discovery

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Remote system discovery | T1018 | wmic querying network, arp -a, nslookup sweeps | Gap | [02-suspicious-process/investigation.md](docs/scenarios/02-suspicious-process/investigation.md) |
| Process discovery | T1057 | wmic process list, tasklist in command lines | Gap | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| System info discovery | T1082 | wmic computersystem, systeminfo, hostname | Gap | [02-suspicious-process/investigation.md](docs/scenarios/02-suspicious-process/investigation.md) |
| File and directory discovery | T1083 | dir /s, Get-ChildItem recursing filesystem | Gap | [05-malicious-file/investigation.md](docs/scenarios/05-malicious-file/investigation.md) |
| Network service discovery | T1046 | Device connecting to private IPs on ports 445, 3389, 22, 135, 139, 5985 and 5986, ranked by distinct targets per port | Query | [lateral-movement-scanning.kql](kql/network/lateral-movement-scanning.kql) |

---

### Lateral Movement

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| RDP | T1021.001 | Account with Network or RemoteInteractive logons on 3+ devices (RemoteInteractive is the RDP subset) | Query | [user-on-multiple-devices.kql](kql/identity/user-on-multiple-devices.kql) |
| SMB / Windows Admin Shares | T1021.002 | Confirmed SMB logon or admin-share use (the scanning query shows port-445 attempts only) | Gap | [lateral-movement-scanning.kql](kql/network/lateral-movement-scanning.kql) |
| WinRM | T1021.006 | Confirmed WinRM session (the scanning query shows port 5985/5986 attempts only) | Gap | [lateral-movement-scanning.kql](kql/network/lateral-movement-scanning.kql) |
| Pass the Hash | T1550.002 | Network logons from unexpected source using domain account | Gap | [06-credential-compromise/investigation.md](docs/scenarios/06-credential-compromise/investigation.md) |
| Use alternate authentication material — application access token | T1550.001 | Non-interactive Entra sign-ins from a new IP and user agent after a token theft finding (Sentinel) | Query | [entra-signin-after-endpoint-compromise.kql](kql/identity/entra-signin-after-endpoint-compromise.kql) |

---

### Collection

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Archive via utility | T1560.001 | 7-Zip, WinRAR and zip tools run with a password switch or creating archives; Compress-Archive and .NET zip use | Query | [archive-staging.kql](kql/exfiltration/archive-staging.kql) |
| Local data staging | T1074.001 | Archive files created in Temp, Public, ProgramData, PerfLogs or the Recycle Bin, with file size | Query | [archive-staging.kql](kql/exfiltration/archive-staging.kql) |
| Email forwarding rule | T1114.003 | Inbox rules (including Outlook-client UpdateInboxRules), transport rules and mailbox settings that forward, redirect or copy mail (Sentinel OfficeActivity) | Query | [m365-mailbox-forwarding-rules.kql](kql/exfiltration/m365-mailbox-forwarding-rules.kql) |

---

### Command and Control

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Application layer protocol — web | T1071.001 | Repeated outbound connections to one external destination (connection count, interval regularity, after-hours, combined score; no HTTP/S protocol filter); ClickFix LOLBin callout to its staging/C2 domain | Query | [beacon-suspicion-score.kql](kql/network/beacon-suspicion-score.kql), [beacon-high-connection-count.kql](kql/network/beacon-high-connection-count.kql), [beacon-interval-regularity.kql](kql/network/beacon-interval-regularity.kql), [beacon-after-hours.kql](kql/network/beacon-after-hours.kql), [clickfix-callout-correlation.kql](kql/network/clickfix-callout-correlation.kql) |
| Application layer protocol — DNS | T1071.004 | Port 53 connections whose first RemoteUrl label is 12+ base64-like characters, more than 5 per device and name | Query | [dns-tunnelling.kql](kql/network/dns-tunnelling.kql) |
| Non-application layer protocol | T1095 | Raw socket connections, unusual protocol usage | Gap | [unusual-outbound-ports.kql](kql/network/unusual-outbound-ports.kql) |
| Ingress tool transfer | T1105 | certutil -urlcache, bitsadmin /transfer downloads | Query | [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Web service — LOTS | T1102 | Non-browser process connecting to Discord, Telegram, GitHub raw, paste and file-sharing sites; shells and script hosts connecting to OneDrive, SharePoint, Google Drive, GitHub, Dropbox or Pastebin | Query | [lots-suspicious-process-to-cloud.kql](kql/network/lots-suspicious-process-to-cloud.kql), [lots-scripting-engine-to-cloud-storage.kql](kql/network/lots-scripting-engine-to-cloud-storage.kql) |
| Web service — smart contract C2 (EtherHiding) | T1102 | Non-browser process connecting to a listed BSC/EVM RPC host (EtherHiding); the query does not see the contract call. IOC is an RPC host + contract address, not a domain | Query | [clickfix-etherhiding-rpc-callout.kql](kql/network/clickfix-etherhiding-rpc-callout.kql) |
| Web service — dead drop resolver | T1102.001 | Script host connecting to a paste or storage host, then to a public IP with no hostname from the same process within 5 minutes | Query | [lots-dead-drop-resolver.kql](kql/network/lots-dead-drop-resolver.kql) |
| Non-standard port | T1571 | Connections on ports 4444, 50050, 1337, 8080, etc. | Query | [unusual-outbound-ports.kql](kql/network/unusual-outbound-ports.kql) |
| Protocol tunnelling | T1572 | Connections to ngrok, trycloudflare, serveo and similar tunnel services | Query | [exfil-services-and-webhooks.kql](kql/exfiltration/exfil-services-and-webhooks.kql) |
| Encrypted channel | T1573 | Low-volume HTTPS beaconing to single CDN IP | Gap | [beacon-interval-regularity.kql](kql/network/beacon-interval-regularity.kql) |

---

### Exfiltration

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Exfil over C2 channel | T1041 | Megabytes sent from the device's IPs to public destinations in firewall logs, ranked (needs a firewall or proxy connector; DeviceNetworkEvents has no byte counts) | Query | [firewall-large-outbound-transfer.kql](kql/exfiltration/firewall-large-outbound-transfer.kql) |
| Exfil to cloud storage | T1567.002 | Non-browser process connecting to OneDrive, S3, Dropbox and other cloud storage (connection count; no volume data); anonymous file-drop sites such as transfer.sh, file.io, Mega | Query | [lots-exfiltration-via-cloud.kql](kql/network/lots-exfiltration-via-cloud.kql), [exfil-services-and-webhooks.kql](kql/exfiltration/exfil-services-and-webhooks.kql) |
| Exfil to code repository | T1567.001 | Non-browser process pushing to GitHub (the linked query flags any connection; push not confirmed) | Gap | [lots-scripting-engine-to-cloud-storage.kql](kql/network/lots-scripting-engine-to-cloud-storage.kql) |
| Exfil over webhook | T1567.004 | Non-browser process connecting to Discord, Telegram, Slack, webhook.site or Pipedream hosts (host only; webhook paths are not visible) | Query | [exfil-services-and-webhooks.kql](kql/exfiltration/exfil-services-and-webhooks.kql) |
| Exfil over alternative protocol | T1048 | rclone, Mega clients, WinSCP, pscp, scp, sftp, ftp, curl and PowerShell uploads, cloud CLI copies, BITS uploads | Query | [exfil-tools-and-cli.kql](kql/exfiltration/exfil-tools-and-cli.kql) |
| Exfil over physical medium — removable media | T1052.001 | USB drive mounts and file writes to the mounted drive letters | Query | [usb-removable-media.kql](kql/exfiltration/usb-removable-media.kql) |

---

### Impact

| Technique | ID | Detection | Status | Detection / reference |
|-----------|-----|-----------|--------|-----------------------|
| Data encrypted for impact (ransomware) | T1486 | More than 20 file renames per minute from one process on a device | Query | [mass-file-renames.kql](kql/ransomware/mass-file-renames.kql) |
| Inhibit system recovery | T1490 | Command lines containing vssadmin, delete shadows, resize shadowstorage, wmic shadowcopy delete or bcdedit /set (any bcdedit /set, not only recovery settings) | Query | [vss-shadow-copy-deletion.kql](kql/ransomware/vss-shadow-copy-deletion.kql), [lolbin-sweep.kql](kql/process/lolbin-sweep.kql) |
| Service stop | T1489 | Services stopped for impact (net stop / sc stop); killing security tools is under T1685 | Gap | — |
