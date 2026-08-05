# KQL query library

Index of all queries in this library. Each file contains a single query with a comment block explaining what it detects, what the key thresholds are, and which doc it relates to.

All queries are syntax-checked by the harness in `tests/kql-smoke/`. See [docs/reference/kql-validation.md](../docs/reference/kql-validation.md) for details.

Replace `HOSTNAME`, `USERNAME`, `PASTE_HASH_HERE`, and datetime placeholders before running.

---

## process/

| File | What it detects | MITRE |
|------|----------------|-------|
| [suspicious-powershell.kql](process/suspicious-powershell.kql) | Encoded commands, download cradles, fileless execution, evasion flags | T1059.001 |
| [office-spawning-shells.kql](process/office-spawning-shells.kql) | Office applications spawning cmd, PowerShell, mshta, or LOLBins | T1566.001, T1204.002 |
| [lolbin-sweep.md](process/lolbin-sweep.md) | All LOLBin abuse in one query — certutil, mshta, regsvr32, rundll32, wmic, bitsadmin | T1218 |
| [processes-in-time-window.kql](process/processes-in-time-window.kql) | All process events on a device within a specific time window | T1059 |
| [credential-access-sweep.md](process/credential-access-sweep.md) | Mimikatz, DCSync, Kerberoasting, AS-REP roasting, token manipulation | T1003, T1558 |
| [post-compromise-discovery-commands.kql](process/post-compromise-discovery-commands.kql) | 4+ distinct recon commands (whoami, net user, nltest, arp, systeminfo, etc.) from one device in 10 minutes | T1033, T1087.001, T1087.002, T1482, T1018, T1016, T1082, T1057 |

---

## network/

| File | What it detects | MITRE |
|------|----------------|-------|
| [beacon-high-connection-count.kql](network/beacon-high-connection-count.kql) | Devices hitting the same external IP 30+ times per day | T1071.001 |
| [beacon-interval-regularity.md](network/beacon-interval-regularity.md) | Low standard deviation of connection intervals — catches jittered beacons | T1071.001 |
| [beacon-after-hours.kql](network/beacon-after-hours.kql) | Outbound connections continuing at 01:00–05:00 UTC | T1071.001 |
| [beacon-suspicion-score.md](network/beacon-suspicion-score.md) | Combined score across count, after-hours activity, and port consistency | T1071.001 |
| [dns-tunnelling.md](network/dns-tunnelling.md) | Base64-encoded subdomains indicating DNS-based C2 or exfiltration | T1071.004 |
| [lateral-movement-scanning.kql](network/lateral-movement-scanning.kql) | Device probing internal IPs on SMB, RDP, WinRM, and WMI ports | T1021 |
| [unusual-outbound-ports.kql](network/unusual-outbound-ports.kql) | Connections on known C2 and reverse shell ports (4444, 50050, 1337, etc.) | T1571 |
| [lots-suspicious-process-to-cloud.kql](network/lots-suspicious-process-to-cloud.kql) | Non-browser process connecting to Discord CDN, Telegram, Pastebin, paste sites | T1102 |
| [lots-scripting-engine-to-cloud-storage.kql](network/lots-scripting-engine-to-cloud-storage.kql) | Scripting engines reaching OneDrive, SharePoint, GitHub, Google Drive | T1102 |
| [lots-dead-drop-resolver.kql](network/lots-dead-drop-resolver.kql) | Scripting engine hits paste service then immediately connects to a raw IP | T1102.001 |
| [lots-exfiltration-via-cloud.kql](network/lots-exfiltration-via-cloud.kql) | High-volume uploads to cloud storage from a non-browser process | T1567 |
| [post-compromise-c2-from-malware.kql](network/post-compromise-c2-from-malware.kql) | New external IPs, orphan processes, newly-seen domains, and known C2 ports following a device infection | T1071.001, T1571, T1568.002 |
| [post-compromise-lateral-movement-timeline.kql](network/post-compromise-lateral-movement-timeline.kql) | Correlated logon/network/process timeline of lateral movement after device compromise | T1021.002, T1021.006, T1078 |

---

## persistence/

| File | What it detects | MITRE |
|------|----------------|-------|
| [registry-run-key-modifications.kql](persistence/registry-run-key-modifications.kql) | Modifications to HKCU/HKLM Run, RunOnce, and Winlogon keys | T1547.001 |
| [scheduled-task-creation.kql](persistence/scheduled-task-creation.kql) | New scheduled tasks created via schtasks.exe | T1053.005 |
| [new-services-installed.kql](persistence/new-services-installed.kql) | New Windows services installed on a device | T1543.003 |
| [wmi-subscription-creation.kql](persistence/wmi-subscription-creation.kql) | WMI event filter, consumer, and binding creation | T1546.003 |

---

## files/

| File | What it detects | MITRE |
|------|----------------|-------|
| [executables-in-suspicious-paths.kql](files/executables-in-suspicious-paths.kql) | Executables and scripts written to Temp, AppData, ProgramData, Public | T1036.005 |
| [hash-sweep-across-estate.kql](files/hash-sweep-across-estate.kql) | Known-bad SHA256 appearing on any device in the estate | T1105 |

---

## identity/

| File | What it detects | MITRE |
|------|----------------|-------|
| [lsass-access-credential-dump.md](identity/lsass-access-credential-dump.md) | Non-Windows process opening lsass.exe | T1003.001 |
| [user-on-multiple-devices.kql](identity/user-on-multiple-devices.kql) | Account appearing on 3+ devices via network or RDP logon | T1021 |
| [new-local-accounts-created.kql](identity/new-local-accounts-created.kql) | New local user accounts created on a device | T1136.001 |
| [all-alerts-for-device.kql](identity/all-alerts-for-device.kql) | All Defender alerts for a specific device in the last 7 days | — |
| [entra-impossible-travel.kql](identity/entra-impossible-travel.kql) | Account signing in from two different countries within 1 hour | T1078 |
| [entra-mfa-fatigue.kql](identity/entra-mfa-fatigue.kql) | 5+ failed MFA prompts in 10 minutes against a single account | T1621 |
| [entra-device-code-auth-flow.md](identity/entra-device-code-auth-flow.md) | Device code sign-ins, flagged for new locations or outside business hours | T1556.006 |
| [entra-aitm-session-anomalies.md](identity/entra-aitm-session-anomalies.md) | Token replay, impossible travel post-MFA, compliance-state drop, UserAgent mismatch — AiTM phishing indicators | T1539 |
| [entra-post-compromise-oauth-grants.kql](identity/entra-post-compromise-oauth-grants.kql) | Suspicious OAuth consent grants within 1h of a suspicious sign-in (mail.read, files.readwrite, offline_access, non-admin admin-consent) | T1528 |
| [entra-post-compromise-mailbox-rules.kql](identity/entra-post-compromise-mailbox-rules.kql) | Inbox rules created post-compromise that forward externally, delete by keyword, or mark as read | T1114.003 |
| [entra-post-compromise-email-exfil.kql](identity/entra-post-compromise-email-exfil.kql) | Mass mailbox access, external forwarding, eDiscovery, mail export, and attachment/URL exfil signals post-compromise | T1114, T1213 |
| [entra-post-compromise-sharepoint-access.kql](identity/entra-post-compromise-sharepoint-access.kql) | Bulk SharePoint/OneDrive access above baseline, off-hours access, or external sharing post-compromise | T1213 |
| [entra-post-compromise-persistence.kql](identity/entra-post-compromise-persistence.kql) | New MFA methods, service principals, CA exclusions, guest invites, or role assignments post-compromise | T1098.001, T1098.003 |

---

## ransomware/

| File | What it detects | MITRE |
|------|----------------|-------|
| [vss-shadow-copy-deletion.kql](ransomware/vss-shadow-copy-deletion.kql) | vssadmin, wmic shadowcopy delete, bcdedit recovery disabled | T1490 |
| [mass-file-renames.kql](ransomware/mass-file-renames.kql) | 20+ file renames per minute from a single process | T1486 |
| [defence-evasion-defender-disabled.kql](ransomware/defence-evasion-defender-disabled.kql) | Defender disabled via registry keys | T1562.001 |
| [event-log-clearing.kql](ransomware/event-log-clearing.kql) | wevtutil cl or Clear-EventLog used to destroy forensic evidence | T1070.001 |

---

## functions/

Reusable `let` function definitions — call these from other queries instead of repeating the same predicate. Each file is runnable on its own (definition + example call) and documents its parameters in the header comment.

| File | What it detects | MITRE |
|------|----------------|-------|
| [fn-beacon-score.kql](functions/fn-beacon-score.kql) | Connection count, mean interval, standard deviation, and suspicion score for one device/remote-IP pair | T1071.001 |
| [fn-is-lolbin.kql](functions/fn-is-lolbin.kql) | True if a process matches a known LOLBin abuse pattern (certutil, mshta, regsvr32, rundll32, wmic, bitsadmin, flagged PowerShell) | T1218 |
| [fn-is-known-good-beacon.kql](functions/fn-is-known-good-beacon.kql) | True if a process/destination pair matches known-good beaconing software — use to filter beacon detection false positives | — |
| [fn-suspicious-path.kql](functions/fn-suspicious-path.kql) | True if a folder path is a known suspicious write/execution location (Temp, AppData, ProgramData, Public) | T1036.005 |

---

## pivots/

Cross-investigation queries that chain two or more log sources together to follow an attack chain end-to-end, rather than looking at one investigation area in isolation. Start here for a real incident once you have an initial indicator (device, account, email, or sign-in) to pivot from.

| File | What it detects | MITRE (chained) |
|------|----------------|-------|
| [phishing-to-device-compromise.md](pivots/phishing-to-device-compromise.md) | Email received -> attachment landed on disk -> process executed, in one timeline | T1566.001, T1204.002, T1105 |
| [device-compromise-to-lateral-movement.md](pivots/device-compromise-to-lateral-movement.md) | Accounts used, internal IPs touched, remote-exec tools seen, and account reuse on a different device following compromise | T1078, T1021.002, T1021.006 |
| [aitm-phishing-to-persistence.md](pivots/aitm-phishing-to-persistence.md) | Suspicious device code/AiTM sign-in -> new MFA method, inbox rule, OAuth grant, or service principal within 24h | T1556.006, T1098.001, T1114.003, T1528 |
| [credential-dump-to-spread.kql](pivots/credential-dump-to-spread.kql) | lsass access -> corroborating credential-dump artefact -> account reuse on another device within 2h | T1003.001, T1078 |
| [email-click-to-execution.kql](pivots/email-click-to-execution.kql) | Safe Links click-through -> device that connected -> process executed within 10 minutes | T1566.002, T1204.001 |
