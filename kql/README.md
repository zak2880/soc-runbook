# KQL query library

Index of all queries in this library. MITRE IDs follow [MITRE-mapping.md](../MITRE-mapping.md) (ATT&CK v20.0); `n/a (triage)` marks scoping queries that detect no technique. Each file contains a single query with a comment block explaining what it detects, what the key thresholds are, and which doc it relates to.

All queries are syntax-checked by the harness in `tests/kql-smoke/`. See [docs/reference/kql-validation.md](../docs/reference/kql-validation.md) for details.

Replace placeholders before running:

- `HOSTNAME` — the **short** device name (e.g. `PC01`). Queries match it with `DeviceName startswith "HOSTNAME"`, which is case-insensitive and also matches the FQDN that `DeviceName` stores. It also matches longer names that share the prefix (`PC01` matches `PC010`), so check `DeviceName` in the results.
- `USERNAME` — the SAM account name (e.g. `jsmith`), not the UPN.
- `PASTE_SHA1_HERE` / `PASTE_SHA256_HERE` — file hashes. SHA256 is often empty in Defender tables; paste SHA1 too.
- `IOC` — optional, used only by [triage/post-alert-quick-triage.kql](triage/post-alert-quick-triage.kql): the IP, domain, URL fragment, file name or SHA1 from the alert. Leave it as `PASTE_IOC_HERE` to skip the indicator rows.
- `T0` — the incident time in UTC, on the line under `// REPLACE: incident time`. Both the `.kql` files and the copies embedded in `docs/` use `datetime(PASTE_TIME_UTC)`, which fails to parse until replaced. For a routine hunt, set `T0` to `now()`.

Each query's second header line says where it runs (`// Runs in:`). Defender tables use `Timestamp`; Sentinel-only tables (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `OfficeActivity`, `CommonSecurityLog`) use `TimeGenerated`. Advanced Hunting holds 30 days of native data.

---

## process/

| File | What it detects | MITRE |
|------|----------------|-------|
| [suspicious-powershell.kql](process/suspicious-powershell.kql) | Encoded commands, download cradles, fileless execution, evasion flags | T1059.001, T1027 |
| [office-spawning-shells.kql](process/office-spawning-shells.kql) | Office applications spawning cmd, PowerShell, mshta, or LOLBins | T1566.001, T1204.002 |
| [lolbin-sweep.kql](process/lolbin-sweep.kql) | All LOLBin abuse in one query — certutil, mshta, regsvr32, rundll32, wmic, bitsadmin | T1218.005, T1218.010, T1218.011, T1059.001, T1059.007, T1105, T1140, T1047, T1197, T1003.001, T1490 |
| [processes-in-time-window.kql](process/processes-in-time-window.kql) | All process events on a device within a specific time window | n/a (triage) |
| [credential-access-sweep.kql](process/credential-access-sweep.kql) | Mimikatz, DCSync, Kerberoasting, AS-REP roasting, token manipulation | T1003.001, T1003.002, T1003.003, T1003.006, T1558.003, T1558.004 |
| [clickfix-lolbin-from-browser-explorer.kql](process/clickfix-lolbin-from-browser-explorer.kql) | LOLBin spawned from explorer.exe/browser with encoded/hidden command line, correlated to browser activity | T1204.004 |

---

## network/

| File | What it detects | MITRE |
|------|----------------|-------|
| [beacon-high-connection-count.kql](network/beacon-high-connection-count.kql) | Devices hitting the same external IP 30+ times per day | T1071.001 |
| [beacon-interval-regularity.kql](network/beacon-interval-regularity.kql) | Low standard deviation of connection intervals — catches jittered beacons | T1071.001 |
| [beacon-after-hours.kql](network/beacon-after-hours.kql) | Outbound connections continuing at 01:00–05:00 UTC | T1071.001 |
| [beacon-suspicion-score.kql](network/beacon-suspicion-score.kql) | Combined score across count, after-hours activity, and port consistency | T1071.001 |
| [dns-tunnelling.kql](network/dns-tunnelling.kql) | Base64-encoded subdomains indicating DNS-based C2 or exfiltration | T1071.004 |
| [lateral-movement-scanning.kql](network/lateral-movement-scanning.kql) | Device probing internal IPs on SMB, RDP, WinRM, and WMI ports | T1046 |
| [unusual-outbound-ports.kql](network/unusual-outbound-ports.kql) | Connections on known C2 and reverse shell ports (4444, 50050, 1337, etc.) | T1571 |
| [lots-suspicious-process-to-cloud.kql](network/lots-suspicious-process-to-cloud.kql) | Non-browser process connecting to Discord CDN, Telegram, Pastebin, paste sites | T1102 |
| [lots-scripting-engine-to-cloud-storage.kql](network/lots-scripting-engine-to-cloud-storage.kql) | Scripting engines reaching OneDrive, SharePoint, GitHub, Google Drive | T1102 |
| [lots-dead-drop-resolver.kql](network/lots-dead-drop-resolver.kql) | Scripting engine hits paste service then immediately connects to a raw IP | T1102.001 |
| [lots-exfiltration-via-cloud.kql](network/lots-exfiltration-via-cloud.kql) | Non-browser connections to cloud storage (connection count; no volume data) | T1567.002 |
| [clickfix-callout-correlation.kql](network/clickfix-callout-correlation.kql) | Confirms a ClickFix LOLBin reached its staging/C2 domain | T1071.001 |
| [clickfix-tenant-wide-ioc-hunt.kql](network/clickfix-tenant-wide-ioc-hunt.kql) | Union hunt for a known ClickFix domain across process, network, URL-click, and email-URL telemetry | n/a (triage) |
| [clickfix-etherhiding-rpc-callout.kql](network/clickfix-etherhiding-rpc-callout.kql) | Non-browser process connecting to a BSC/EVM RPC host — EtherHiding smart-contract C2 | T1102 |

---

## persistence/

| File | What it detects | MITRE |
|------|----------------|-------|
| [registry-run-key-modifications.kql](persistence/registry-run-key-modifications.kql) | Modifications to HKCU/HKLM Run, RunOnce, and Winlogon keys | T1547.001, T1547.004 |
| [scheduled-task-creation.kql](persistence/scheduled-task-creation.kql) | New scheduled tasks created via schtasks.exe | T1053.005 |
| [new-services-installed.kql](persistence/new-services-installed.kql) | New Windows services installed on a device | T1543.003 |
| [wmi-subscription-creation.kql](persistence/wmi-subscription-creation.kql) | WMI event filter, consumer, and binding creation | T1546.003 |

---

## files/

| File | What it detects | MITRE |
|------|----------------|-------|
| [executables-in-suspicious-paths.kql](files/executables-in-suspicious-paths.kql) | Executables and scripts written to Temp, AppData, ProgramData, Public | n/a (triage) |
| [hash-sweep-across-estate.kql](files/hash-sweep-across-estate.kql) | Known-bad SHA1/SHA256 appearing on any device in the estate | n/a (triage) |

---

## identity/

| File | What it detects | MITRE |
|------|----------------|-------|
| [lsass-access-credential-dump.kql](identity/lsass-access-credential-dump.kql) | Non-Windows process opening lsass.exe | T1003.001 |
| [user-on-multiple-devices.kql](identity/user-on-multiple-devices.kql) | Account appearing on 3+ devices via network or RDP logon | T1021.001 |
| [new-local-accounts-created.kql](identity/new-local-accounts-created.kql) | New local user accounts created on a device | T1136.001 |
| [all-alerts-for-device.kql](identity/all-alerts-for-device.kql) | All Defender alerts for a specific device in the last 7 days | n/a (triage) |
| [entra-impossible-travel.kql](identity/entra-impossible-travel.kql) | Account signing in from two different countries within 1 hour | T1078 |
| [entra-mfa-fatigue.kql](identity/entra-mfa-fatigue.kql) | 5+ failed MFA prompts in 10 minutes against a single account | T1621 |
| [browser-credential-theft.kql](identity/browser-credential-theft.kql) | Browser credential/cookie store copied by a non-browser process, stealer tooling, headless browser with remote debugging port | T1555.003, T1539 |
| [credential-store-and-secret-hunting.kql](identity/credential-store-and-secret-hunting.kql) | Credential Manager, KeePass vaults, passwords searched for in files, cloud/dev tokens and private keys, saved remote-access credentials | T1555.004, T1555.005, T1552.001, T1552.002, T1552.004, T1552.006 |
| [credential-dump-artefacts.kql](identity/credential-dump-artefacts.kql) | lsass dump tools, ntdsutil IFM, esentutl, shadow-copy copies, and the dump files and hive copies they leave | T1003.001, T1003.002, T1003.003 |
| [entra-signin-after-endpoint-compromise.kql](identity/entra-signin-after-endpoint-compromise.kql) | Sign-ins for an account from 24h before T0 onward, flagging IPs not seen in the 30 days before that, including non-interactive (Sentinel) | T1078.004, T1550.001 |

---

## exfiltration/

| File | What it detects | MITRE |
|------|----------------|-------|
| [archive-staging.kql](exfiltration/archive-staging.kql) | Password-protected or bulk archive creation and archive files in staging paths, with size | T1560.001, T1074.001 |
| [exfil-tools-and-cli.kql](exfiltration/exfil-tools-and-cli.kql) | rclone, Mega, WinSCP/scp/sftp/ftp, curl and PowerShell uploads, cloud CLI copies, BITS uploads | T1048, T1567.002 |
| [exfil-services-and-webhooks.kql](exfiltration/exfil-services-and-webhooks.kql) | Anonymous file drops, paste sites, webhook/messaging APIs and tunnel services (connection counts) | T1567.002, T1567.004, T1572 |
| [firewall-large-outbound-transfer.kql](exfiltration/firewall-large-outbound-transfer.kql) | Megabytes sent from a device's IPs to public destinations, from firewall logs (Sentinel) | T1041, T1048 |
| [usb-removable-media.kql](exfiltration/usb-removable-media.kql) | USB mounts and file writes to the mounted drive letters | T1052.001 |
| [m365-mailbox-forwarding-rules.kql](exfiltration/m365-mailbox-forwarding-rules.kql) | Inbox rules and mailbox settings that forward, redirect or hide mail; added mailbox permissions (Sentinel) | T1114.003, T1564.008, T1098.002 |

---

## triage/

| File | What it detects | MITRE |
|------|----------------|-------|
| [post-alert-quick-triage.kql](triage/post-alert-quick-triage.kql) | One timeline of suspicious process, network, file, registry, lsass and alert activity on a device around T0, plus optional IOC rows. Run straight after a TI file or network-match alert | n/a (triage) |

---

## ransomware/

| File | What it detects | MITRE |
|------|----------------|-------|
| [vss-shadow-copy-deletion.kql](ransomware/vss-shadow-copy-deletion.kql) | vssadmin, wmic shadowcopy delete, bcdedit recovery disabled | T1490 |
| [mass-file-renames.kql](ransomware/mass-file-renames.kql) | 20+ file renames per minute from a single process | T1486 |
| [defence-evasion-defender-disabled.kql](ransomware/defence-evasion-defender-disabled.kql) | Defender disabled via registry keys | T1685 |
| [event-log-clearing.kql](ransomware/event-log-clearing.kql) | wevtutil cl or Clear-EventLog used to destroy forensic evidence | T1685.005 |
