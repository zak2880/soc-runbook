# KQL query library

Index of all queries in this library. Each file contains a single query with a comment block explaining what it detects, what the key thresholds are, and which doc it relates to.

All queries are syntax-checked by the harness in `tests/kql-smoke/`. See [docs/kql-validation.md](../docs/kql-validation.md) for details.

Replace `HOSTNAME`, `USERNAME`, `PASTE_HASH_HERE`, and datetime placeholders before running.

---

## process/

| File | What it detects | MITRE |
|------|----------------|-------|
| [suspicious-powershell.kql](process/suspicious-powershell.kql) | Encoded commands, download cradles, fileless execution, evasion flags | T1059.001 |
| [office-spawning-shells.kql](process/office-spawning-shells.kql) | Office applications spawning cmd, PowerShell, mshta, or LOLBins | T1566.001, T1204.002 |
| [lolbin-sweep.kql](process/lolbin-sweep.kql) | All LOLBin abuse in one query — certutil, mshta, regsvr32, rundll32, wmic, bitsadmin | T1218 |
| [processes-in-time-window.kql](process/processes-in-time-window.kql) | All process events on a device within a specific time window | T1059 |
| [credential-access-sweep.kql](process/credential-access-sweep.kql) | Mimikatz, DCSync, Kerberoasting, AS-REP roasting, token manipulation | T1003, T1558 |

---

## network/

| File | What it detects | MITRE |
|------|----------------|-------|
| [beacon-high-connection-count.kql](network/beacon-high-connection-count.kql) | Devices hitting the same external IP 30+ times per day | T1071.001 |
| [beacon-interval-regularity.kql](network/beacon-interval-regularity.kql) | Low standard deviation of connection intervals — catches jittered beacons | T1071.001 |
| [beacon-after-hours.kql](network/beacon-after-hours.kql) | Outbound connections continuing at 01:00–05:00 UTC | T1071.001 |
| [beacon-suspicion-score.kql](network/beacon-suspicion-score.kql) | Combined score across count, after-hours activity, and port consistency | T1071.001 |
| [dns-tunnelling.kql](network/dns-tunnelling.kql) | Base64-encoded subdomains indicating DNS-based C2 or exfiltration | T1071.004 |
| [lateral-movement-scanning.kql](network/lateral-movement-scanning.kql) | Device probing internal IPs on SMB, RDP, WinRM, and WMI ports | T1021 |
| [unusual-outbound-ports.kql](network/unusual-outbound-ports.kql) | Connections on known C2 and reverse shell ports (4444, 50050, 1337, etc.) | T1571 |
| [lots-suspicious-process-to-cloud.kql](network/lots-suspicious-process-to-cloud.kql) | Non-browser process connecting to Discord CDN, Telegram, Pastebin, paste sites | T1102 |
| [lots-scripting-engine-to-cloud-storage.kql](network/lots-scripting-engine-to-cloud-storage.kql) | Scripting engines reaching OneDrive, SharePoint, GitHub, Google Drive | T1102 |
| [lots-dead-drop-resolver.kql](network/lots-dead-drop-resolver.kql) | Scripting engine hits paste service then immediately connects to a raw IP | T1102.001 |
| [lots-exfiltration-via-cloud.kql](network/lots-exfiltration-via-cloud.kql) | High-volume uploads to cloud storage from a non-browser process | T1567 |

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
| [lsass-access-credential-dump.kql](identity/lsass-access-credential-dump.kql) | Non-Windows process opening lsass.exe | T1003.001 |
| [user-on-multiple-devices.kql](identity/user-on-multiple-devices.kql) | Account appearing on 3+ devices via network or RDP logon | T1021 |
| [new-local-accounts-created.kql](identity/new-local-accounts-created.kql) | New local user accounts created on a device | T1136.001 |
| [all-alerts-for-device.kql](identity/all-alerts-for-device.kql) | All Defender alerts for a specific device in the last 7 days | — |
| [entra-impossible-travel.kql](identity/entra-impossible-travel.kql) | Account signing in from two different countries within 1 hour | T1078 |
| [entra-mfa-fatigue.kql](identity/entra-mfa-fatigue.kql) | 5+ failed MFA prompts in 10 minutes against a single account | T1621 |

---

## ransomware/

| File | What it detects | MITRE |
|------|----------------|-------|
| [vss-shadow-copy-deletion.kql](ransomware/vss-shadow-copy-deletion.kql) | vssadmin, wmic shadowcopy delete, bcdedit recovery disabled | T1490 |
| [mass-file-renames.kql](ransomware/mass-file-renames.kql) | 20+ file renames per minute from a single process | T1486 |
| [defence-evasion-defender-disabled.kql](ransomware/defence-evasion-defender-disabled.kql) | Defender disabled via registry keys | T1562.001 |
| [event-log-clearing.kql](ransomware/event-log-clearing.kql) | wevtutil cl or Clear-EventLog used to destroy forensic evidence | T1070.001 |
