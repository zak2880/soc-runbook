# MITRE ATT&CK mapping

Full mapping of soc-runbook detection content to MITRE ATT&CK tactics and techniques.

Framework version: ATT&CK v14 (Enterprise)  
Coverage: Techniques commonly seen in incidents handled at a UK MSSP targeting SME and mid-market organisations.

Every technique below that has a KQL detection now has **both** a Sentinel (`kql/sentinel/…`, `TimeGenerated`) and an XDR (`kql/xdr/…`, `Timestamp`) version — the Query column links to both where they exist. A handful of Sentinel-tree links point at files kept for structural parity only (the table they query isn't actually available in Sentinel yet); those are called out in the file's own header comment and in [docs/reference/sentinel-vs-advanced-hunting.md](docs/reference/sentinel-vs-advanced-hunting.md). Rows that link to a `docs/` investigation guide instead of a `.kql` file are unaffected by the platform split.

---

## Coverage by tactic

| Tactic | Techniques covered |
|--------|-------------------|
| Initial Access | T1078, T1078.004, T1133, T1189, T1195, T1566.001, T1566.002, T1566.003 |
| Execution | T1059.001, T1059.005, T1059.007, T1106, T1204.002, T1218 |
| Persistence | T1053.005, T1078.004, T1098, T1098.001, T1098.003, T1098.005, T1136.001, T1136.003, T1543.003, T1546.003, T1547.001, T1550.001 |
| Privilege Escalation | T1548.002, T1055, T1078 |
| Defence Evasion | T1027, T1036.005, T1055, T1070.001, T1112, T1218, T1562.001, T1562.002 |
| Credential Access | T1003.001, T1003.002, T1003.003, T1110.001, T1110.003, T1528, T1539, T1550.001, T1556.006, T1558.003, T1558.004, T1621 |
| Discovery | T1016, T1018, T1033, T1057, T1082, T1083, T1087.001, T1087.002, T1482 |
| Lateral Movement | T1021.001, T1021.002, T1021.006, T1550.002 |
| Collection | T1078.004, T1114, T1114.003, T1213, T1560, T1074 |
| Command and Control | T1071.001, T1071.004, T1095, T1102, T1102.001, T1568.002, T1571, T1573 |
| Exfiltration | T1041, T1567, T1567.002 |
| Impact | T1486, T1490, T1489 |

---

## Technique detail

### Initial Access

| Technique | ID | Detection | Query |
|-----------|-----|-----------|-----|
| Phishing — spearphishing attachment | T1566.001 | Malicious attachment delivered via email | [Sentinel](kql/sentinel/process/office-spawning-shells.kql) · [XDR](kql/xdr/process/office-spawning-shells.kql) |
| Phishing — spearphishing link | T1566.002 | User clicks malicious link from email | [docs/13-email-investigation.md](docs/13-email-investigation.md) |
| Phishing — spearphishing via Teams | T1566.003 | External Teams message with malicious content | [docs/13-email-investigation.md](docs/13-email-investigation.md) |
| Valid accounts | T1078 | Credential-based logon from unusual location | [Sentinel](kql/sentinel/identity/entra-impossible-travel.kql) · [XDR](kql/xdr/identity/entra-impossible-travel.kql) |
| Valid accounts — cloud accounts | T1078.004 | Guest account sign-in activity, flagged for off-hours, new country, or high volume | [Sentinel](kql/sentinel/identity-hygiene/signin-guest-account-activity.kql) · [XDR](kql/xdr/identity-hygiene/signin-guest-account-activity.kql) |
| Valid accounts | T1078 | Sign-ins flagged high/medium risk by Entra ID Protection (requires P2) | [Sentinel](kql/sentinel/identity-hygiene/signin-high-risk-users.kql) · [XDR](kql/xdr/identity-hygiene/signin-high-risk-users.kql) |
| Valid accounts | T1078 | Account signing in from a country it has never used before (90-day baseline) | [Sentinel](kql/sentinel/identity-hygiene/signin-new-country-first-seen.kql) · [XDR](kql/xdr/identity-hygiene/signin-new-country-first-seen.kql) |
| Valid accounts | T1078 | Successful overnight sign-ins for accounts with no overnight baseline | [Sentinel](kql/sentinel/identity-hygiene/signin-outside-business-hours.kql) · [XDR](kql/xdr/identity-hygiene/signin-outside-business-hours.kql) |
| External remote services (RDP) | T1133 | RDP brute force — many failures then success | [docs/11-initial-access.md](docs/11-initial-access.md) |
| Drive-by compromise | T1189 | Browser download of executable or script | [docs/11-initial-access.md](docs/11-initial-access.md) |
| Supply chain compromise | T1195 | Trojanised installer or update | [docs/11-initial-access.md](docs/11-initial-access.md) |

---

### Execution

| Technique | ID | Detection | Query |
|-----------|-----|-----------|-----|
| PowerShell | T1059.001 | Encoded commands, download cradles, AMSI bypass | [Sentinel](kql/sentinel/process/suspicious-powershell.kql) · [XDR](kql/xdr/process/suspicious-powershell.kql) |
| Visual Basic (VBScript) | T1059.005 | wscript/cscript spawning shells | [Sentinel](kql/sentinel/process/lolbin-sweep.md) · [XDR](kql/xdr/process/lolbin-sweep.md) |
| JavaScript | T1059.007 | mshta inline JavaScript execution | [Sentinel](kql/sentinel/process/lolbin-sweep.md) · [XDR](kql/xdr/process/lolbin-sweep.md) |
| Native API | T1106 | Process hollowing via memory write APIs | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| User execution — malicious file | T1204.002 | User opens phishing attachment | [Sentinel](kql/sentinel/process/office-spawning-shells.kql) · [XDR](kql/xdr/process/office-spawning-shells.kql) |
| Signed binary proxy execution | T1218 | certutil, mshta, regsvr32, rundll32, wmic, bitsadmin | [Sentinel](kql/sentinel/process/lolbin-sweep.md) · [XDR](kql/xdr/process/lolbin-sweep.md) |

---

### Persistence

| Technique | ID | Detection | Query |
|-----------|-----|-----------|-----|
| Registry run keys | T1547.001 | Run/RunOnce key modifications | [Sentinel](kql/sentinel/persistence/registry-run-key-modifications.kql) · [XDR](kql/xdr/persistence/registry-run-key-modifications.kql) |
| Scheduled task | T1053.005 | Task creation via schtasks.exe | [Sentinel](kql/sentinel/persistence/scheduled-task-creation.kql) · [XDR](kql/xdr/persistence/scheduled-task-creation.kql) |
| Windows service | T1543.003 | New service installed | [Sentinel](kql/sentinel/persistence/new-services-installed.kql) · [XDR](kql/xdr/persistence/new-services-installed.kql) |
| WMI event subscription | T1546.003 | WMI filter, consumer, binding creation | [Sentinel](kql/sentinel/persistence/wmi-subscription-creation.kql) · [XDR](kql/xdr/persistence/wmi-subscription-creation.kql) |
| Local account creation | T1136.001 | New local user account created | [Sentinel](kql/sentinel/identity/new-local-accounts-created.kql) · [XDR](kql/xdr/identity/new-local-accounts-created.kql) |
| Account manipulation — additional cloud credentials | T1098.001 | New MFA/auth methods, service principals, or app registrations added post-compromise | [Sentinel](kql/sentinel/identity/entra-post-compromise-persistence.kql) · [XDR](kql/xdr/identity/entra-post-compromise-persistence.kql) |
| Account manipulation — additional cloud roles | T1098.003 | New guest invites or directory role assignments post-compromise | [Sentinel](kql/sentinel/identity/entra-post-compromise-persistence.kql) · [XDR](kql/xdr/identity/entra-post-compromise-persistence.kql) |
| Account manipulation | T1098 | Password reset volume anomalies, admin-initiated resets, off-hours resets | [Sentinel](kql/sentinel/identity-hygiene/audit-password-resets.kql) · [XDR](kql/xdr/identity-hygiene/audit-password-resets.kql) |
| Account manipulation | T1098 | Additions to privileged security groups, bulk membership changes | [Sentinel](kql/sentinel/identity-hygiene/audit-group-membership-changes.kql) · [XDR](kql/xdr/identity-hygiene/audit-group-membership-changes.kql) |
| Account manipulation | T1098 | Mailbox FullAccess/SendAs/SendOnBehalf grants, flagged for VIP mailboxes and off-hours | [Sentinel](kql/sentinel/identity-hygiene/office-mailbox-delegation.kql) · [XDR](kql/xdr/identity-hygiene/office-mailbox-delegation.kql) |
| Account manipulation — device registration | T1098.005 | MFA method registration/removal, flagged for removals and admin-initiated changes | [Sentinel](kql/sentinel/identity-hygiene/audit-mfa-method-changes.kql) · [XDR](kql/xdr/identity-hygiene/audit-mfa-method-changes.kql) |
| Account manipulation — additional cloud roles | T1098.003 | Assignment of Global Admin and other high-value directory roles | [Sentinel](kql/sentinel/identity-hygiene/audit-role-assignments.kql) · [XDR](kql/xdr/identity-hygiene/audit-role-assignments.kql) |
| Create account — cloud account | T1136.003 | Guest invitations to non-standard domains or in bulk | [Sentinel](kql/sentinel/identity-hygiene/audit-guest-invitations.kql) · [XDR](kql/xdr/identity-hygiene/audit-guest-invitations.kql) |
| Valid accounts — cloud accounts | T1078.004 | Service principal sign-ins from a new IP or outside normal operating hours | [Sentinel](kql/sentinel/identity-hygiene/signin-service-principal-anomalies.kql) · [XDR](kql/xdr/identity-hygiene/signin-service-principal-anomalies.kql) |
| Use alternate authentication material — application access token | T1550.001 | New app/service principal registrations with a fast-follow credential or owner change | [Sentinel](kql/sentinel/identity-hygiene/audit-app-registrations.kql) · [XDR](kql/xdr/identity-hygiene/audit-app-registrations.kql) |

---

### Privilege Escalation

| Technique | ID | Detection | Query |
|-----------|-----|-----------|-----|
| UAC bypass | T1548.002 | fodhelper, eventvwr, computerdefaults spawning children | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| Process injection | T1055 | Legitimate process making unexpected network connections | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| Valid accounts | T1078 | Compromised account used for privilege escalation | [Sentinel](kql/sentinel/identity/user-on-multiple-devices.kql) · [XDR](kql/xdr/identity/user-on-multiple-devices.kql) |

---

### Defence Evasion

| Technique | ID | Detection | Query |
|-----------|-----|-----------|-----|
| Obfuscated files / encoding | T1027 | Base64 encoded PowerShell, char array obfuscation | [Sentinel](kql/sentinel/process/suspicious-powershell.kql) · [XDR](kql/xdr/process/suspicious-powershell.kql) |
| Masquerading — match legitimate name | T1036.005 | Executables in Temp/AppData with system process names | [Sentinel](kql/sentinel/files/executables-in-suspicious-paths.kql) · [XDR](kql/xdr/files/executables-in-suspicious-paths.kql) |
| Process injection | T1055 | Memory API calls from unexpected processes | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| Indicator removal — clear event logs | T1070.001 | wevtutil cl, Clear-EventLog | [Sentinel](kql/sentinel/ransomware/event-log-clearing.kql) · [XDR](kql/xdr/ransomware/event-log-clearing.kql) |
| Modify registry | T1112 | UAC bypass registry modifications | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| Signed binary proxy execution | T1218 | LOLBin abuse | [Sentinel](kql/sentinel/process/lolbin-sweep.md) · [XDR](kql/xdr/process/lolbin-sweep.md) |
| Impair defences — disable AV | T1562.001 | Defender disabled via registry | [Sentinel](kql/sentinel/ransomware/defence-evasion-defender-disabled.kql) · [XDR](kql/xdr/ransomware/defence-evasion-defender-disabled.kql) |
| Impair defences — modify security controls | T1562.001 | Conditional Access failures/notApplied sign-ins, flagged for repeated probing | [Sentinel](kql/sentinel/identity-hygiene/signin-conditional-access-failure.kql) · [XDR](kql/xdr/identity-hygiene/signin-conditional-access-failure.kql) |
| Impair defences — modify security controls | T1562.001 | Successful sign-ins with no named-location match — CA coverage gap indicator | [Sentinel](kql/sentinel/identity-hygiene/signin-named-location-violations.kql) · [XDR](kql/xdr/identity-hygiene/signin-named-location-violations.kql) |
| Impair defences — modify security controls | T1562.001 | Conditional Access policy add/update/delete, flagged for deletions | [Sentinel](kql/sentinel/identity-hygiene/audit-conditional-access-changes.kql) · [XDR](kql/xdr/identity-hygiene/audit-conditional-access-changes.kql) |
| Impair defences — modify security controls | T1562.001 | Elevated Exchange admin operations — audit config, malware filter, anti-phish rule changes | [Sentinel](kql/sentinel/identity-hygiene/office-admin-activity.kql) · [XDR](kql/xdr/identity-hygiene/office-admin-activity.kql) |
| Impair defences — disable logging | T1562.002 | ETW patching, audit policy modification | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| AMSI bypass | T1562.001 | AmsiUtils / amsiInitFailed in PowerShell command line | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
| Timestomping | T1070.006 | Files with suspiciously old timestamps in temp paths | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |

---

### Credential Access

| Technique | ID | Detection | Query |
|-----------|-----|-----------|-----|
| OS credential dumping — lsass | T1003.001 | lsass.exe accessed by non-Windows process | [Sentinel](kql/sentinel/identity/lsass-access-credential-dump.md) · [XDR](kql/xdr/identity/lsass-access-credential-dump.md) |
| OS credential dumping — SAM | T1003.002 | SAM hive read by non-system process | [Sentinel](kql/sentinel/process/credential-access-sweep.md) · [XDR](kql/xdr/process/credential-access-sweep.md) |
| OS credential dumping — NTDS | T1003.003 | NTDS.dit accessed by non-system process | [Sentinel](kql/sentinel/process/credential-access-sweep.md) · [XDR](kql/xdr/process/credential-access-sweep.md) |
| Kerberoasting | T1558.003 | GetUserSPNs, Invoke-Kerberoast in command lines | [Sentinel](kql/sentinel/process/credential-access-sweep.md) · [XDR](kql/xdr/process/credential-access-sweep.md) |
| AS-REP roasting | T1558.004 | GetNPUsers, ASREPRoast in command lines | [Sentinel](kql/sentinel/process/credential-access-sweep.md) · [XDR](kql/xdr/process/credential-access-sweep.md) |
| MFA fatigue | T1621 | 5+ failed MFA prompts in 10 minutes | [Sentinel](kql/sentinel/identity/entra-mfa-fatigue.kql) · [XDR](kql/xdr/identity/entra-mfa-fatigue.kql) |
| Modify authentication process — device registration | T1556.006 | Device code auth flow, flagged from new locations or outside business hours | [Sentinel](kql/sentinel/identity/entra-device-code-auth-flow.md) · [XDR](kql/xdr/identity/entra-device-code-auth-flow.md) |
| Steal web session cookie | T1539 | IP change post-MFA, impossible travel, compliance-state drift, UserAgent mismatch | [Sentinel](kql/sentinel/identity/entra-aitm-session-anomalies.kql) · [XDR](kql/xdr/identity/entra-aitm-session-anomalies.md) |
| Steal application access token | T1528 | Suspicious OAuth consent grant within 1h of a suspicious sign-in | [Sentinel](kql/sentinel/identity/entra-post-compromise-oauth-grants.kql) · [XDR](kql/xdr/identity/entra-post-compromise-oauth-grants.kql) |
| Steal application access token | T1528 | Admin consent grants for high-privilege Graph scopes | [Sentinel](kql/sentinel/identity-hygiene/audit-admin-consent-grants.kql) · [XDR](kql/xdr/identity-hygiene/audit-admin-consent-grants.kql) |
| Brute force — password guessing | T1110.001 | Many failed sign-ins against a single account followed by a success in the same window | [Sentinel](kql/sentinel/identity-hygiene/signin-brute-force-single-account.kql) · [XDR](kql/xdr/identity-hygiene/signin-brute-force-single-account.kql) |
| Brute force — password spraying | T1110.003 | Many failed sign-ins across many distinct accounts from one IP, or a shared UserAgent across accounts | [Sentinel](kql/sentinel/identity-hygiene/signin-password-spray.kql) · [XDR](kql/xdr/identity-hygiene/signin-password-spray.kql) |
| Use alternate authentication material — application access token | T1550.001 | Successful sign-in over a legacy auth protocol (IMAP4/POP3/SMTP/etc.) that bypasses MFA entirely | [Sentinel](kql/sentinel/identity-hygiene/signin-legacy-auth.kql) · [XDR](kql/xdr/identity-hygiene/signin-legacy-auth.kql) |

---

### Discovery

| Technique | ID | Detection | Query |
|-----------|-----|-----------|-----|
| Remote system discovery | T1018 | wmic querying network, arp -a, nslookup sweeps | [docs/02-process-investigation.md](docs/02-process-investigation.md) |
| Process discovery | T1057 | wmic process list, tasklist in command lines | [Sentinel](kql/sentinel/process/lolbin-sweep.md) · [XDR](kql/xdr/process/lolbin-sweep.md) |
| System info discovery | T1082 | wmic computersystem, systeminfo, hostname | [docs/02-process-investigation.md](docs/02-process-investigation.md) |
| File and directory discovery | T1083 | dir /s, Get-ChildItem recursing filesystem | [docs/05-file-artefacts.md](docs/05-file-artefacts.md) |
| System owner/user discovery | T1033 | whoami run as part of a post-compromise recon burst | [Sentinel](kql/sentinel/process/post-compromise-discovery-commands.kql) · [XDR](kql/xdr/process/post-compromise-discovery-commands.kql) |
| Account discovery — local account | T1087.001 | net user in a post-compromise recon burst | [Sentinel](kql/sentinel/process/post-compromise-discovery-commands.kql) · [XDR](kql/xdr/process/post-compromise-discovery-commands.kql) |
| Account discovery — domain account | T1087.002 | net localgroup administrators in a post-compromise recon burst | [Sentinel](kql/sentinel/process/post-compromise-discovery-commands.kql) · [XDR](kql/xdr/process/post-compromise-discovery-commands.kql) |
| Domain trust discovery | T1482 | nltest /domain_trusts in a post-compromise recon burst | [Sentinel](kql/sentinel/process/post-compromise-discovery-commands.kql) · [XDR](kql/xdr/process/post-compromise-discovery-commands.kql) |
| System network configuration discovery | T1016 | ipconfig /all, nslookup, arp -a in a post-compromise recon burst | [Sentinel](kql/sentinel/process/post-compromise-discovery-commands.kql) · [XDR](kql/xdr/process/post-compromise-discovery-commands.kql) |

---

### Lateral Movement

| Technique | ID | Detection | Query |
|-----------|-----|-----------|-----|
| RDP | T1021.001 | Account logging into new devices via RemoteInteractive | [Sentinel](kql/sentinel/identity/user-on-multiple-devices.kql) · [XDR](kql/xdr/identity/user-on-multiple-devices.kql) |
| SMB / Windows Admin Shares | T1021.002 | Connections to port 445 on multiple internal IPs | [Sentinel](kql/sentinel/network/lateral-movement-scanning.kql) · [XDR](kql/xdr/network/lateral-movement-scanning.kql) |
| WinRM | T1021.006 | Connections to port 5985/5986 on multiple internal IPs | [Sentinel](kql/sentinel/network/lateral-movement-scanning.kql) · [XDR](kql/xdr/network/lateral-movement-scanning.kql) |
| Pass the Hash | T1550.002 | Network logons from unexpected source using domain account | [docs/06-identity-and-credentials.md](docs/06-identity-and-credentials.md) |

---

### Collection

| Technique | ID | Detection | Query |
|-----------|-----|-----------|-----|
| Email collection | T1114 | Unusual volume of mailbox access, mail export operations, or non-admin eDiscovery searches post-compromise | [Sentinel](kql/sentinel/identity/entra-post-compromise-email-exfil.kql) · [XDR](kql/xdr/identity/entra-post-compromise-email-exfil.kql) |
| Email collection — forwarding rule | T1114.003 | Inbox rule forwards externally, deletes by keyword, or marks as read post-compromise | [Sentinel](kql/sentinel/identity/entra-post-compromise-mailbox-rules.md) · [XDR](kql/xdr/identity/entra-post-compromise-mailbox-rules.kql) |
| Data from information repositories | T1213 | Bulk SharePoint/OneDrive access above baseline, off-hours access, or external sharing post-compromise | [Sentinel](kql/sentinel/identity/entra-post-compromise-sharepoint-access.kql) · [XDR](kql/xdr/identity/entra-post-compromise-sharepoint-access.kql) |
| Data from information repositories | T1213 | SharePoint/OneDrive files shared to non-standard domains or in bulk | [Sentinel](kql/sentinel/identity-hygiene/office-external-sharing.kql) · [XDR](kql/xdr/identity-hygiene/office-external-sharing.kql) |
| Data from information repositories | T1213 | Anonymous ("anyone with the link") sharing link creation | [Sentinel](kql/sentinel/identity-hygiene/office-anonymous-link-creation.kql) · [XDR](kql/xdr/identity-hygiene/office-anonymous-link-creation.kql) |
| Email collection — forwarding rule | T1114.003 | Transport rules that redirect, blind-copy, or forward mail externally | [Sentinel](kql/sentinel/identity-hygiene/office-transport-rule-changes.kql) · [XDR](kql/xdr/identity-hygiene/office-transport-rule-changes.kql) |
| Valid accounts — cloud accounts | T1078.004 | External (#EXT#) users added to Teams channels | [Sentinel](kql/sentinel/identity-hygiene/office-teams-external-access.kql) · [XDR](kql/xdr/identity-hygiene/office-teams-external-access.kql) |

---

### Command and Control

| Technique | ID | Detection | Query |
|-----------|-----|-----------|-----|
| Application layer protocol — web | T1071.001 | Regular beaconing over HTTP/S | [Sentinel](kql/sentinel/network/beacon-suspicion-score.md) · [XDR](kql/xdr/network/beacon-suspicion-score.md) |
| Application layer protocol — DNS | T1071.004 | DNS tunnelling via encoded subdomains | [Sentinel](kql/sentinel/network/dns-tunnelling.md) · [XDR](kql/xdr/network/dns-tunnelling.md) |
| Non-application layer protocol | T1095 | Raw socket connections, unusual protocol usage | [Sentinel](kql/sentinel/network/unusual-outbound-ports.kql) · [XDR](kql/xdr/network/unusual-outbound-ports.kql) |
| Web service — LOTS | T1102 | Scripting engine connecting to Discord, Telegram, Pastebin | [Sentinel](kql/sentinel/network/lots-suspicious-process-to-cloud.kql) · [XDR](kql/xdr/network/lots-suspicious-process-to-cloud.kql) |
| Web service — dead drop | T1102.001 | Paste service GET followed by raw IP connection | [Sentinel](kql/sentinel/network/lots-dead-drop-resolver.kql) · [XDR](kql/xdr/network/lots-dead-drop-resolver.kql) |
| Dynamic resolution — newly registered domains | T1568.002 | DNS queries to domains never queried by a device before infection | [Sentinel](kql/sentinel/network/post-compromise-c2-from-malware.kql) · [XDR](kql/xdr/network/post-compromise-c2-from-malware.kql) |
| Non-standard port | T1571 | Connections on ports 4444, 50050, 1337, 8080, etc. | [Sentinel](kql/sentinel/network/unusual-outbound-ports.kql) · [XDR](kql/xdr/network/unusual-outbound-ports.kql) |
| Encrypted channel | T1573 | Low-volume HTTPS beaconing to single CDN IP | [Sentinel](kql/sentinel/network/beacon-interval-regularity.md) · [XDR](kql/xdr/network/beacon-interval-regularity.md) |

---

### Exfiltration

| Technique | ID | Detection | Query |
|-----------|-----|-----------|-----|
| Exfil over C2 channel | T1041 | Large outbound transfers from unexpected process | [docs/03-network-investigation.md](docs/03-network-investigation.md) |
| Exfil to cloud storage | T1567 | High-volume uploads to OneDrive, S3, Dropbox from non-browser | [Sentinel](kql/sentinel/network/lots-exfiltration-via-cloud.kql) · [XDR](kql/xdr/network/lots-exfiltration-via-cloud.kql) |
| Exfil to code repository | T1567.002 | Non-browser process pushing to GitHub | [Sentinel](kql/sentinel/network/lots-scripting-engine-to-cloud-storage.kql) · [XDR](kql/xdr/network/lots-scripting-engine-to-cloud-storage.kql) |

---

### Impact

| Technique | ID | Detection | Query |
|-----------|-----|-----------|-----|
| Data encrypted for impact (ransomware) | T1486 | Mass file renames, new extensions across filesystem | [Sentinel](kql/sentinel/ransomware/mass-file-renames.kql) · [XDR](kql/xdr/ransomware/mass-file-renames.kql) |
| Inhibit system recovery | T1490 | VSS deletion, bcdedit recovery disabled | [Sentinel](kql/sentinel/ransomware/vss-shadow-copy-deletion.kql) · [XDR](kql/xdr/ransomware/vss-shadow-copy-deletion.kql) |
| Service stop | T1489 | Security tools killed via taskkill | [docs/12-defence-evasion.md](docs/12-defence-evasion.md) |
