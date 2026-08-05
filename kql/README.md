# KQL query library

Index of all queries in this library. Each file contains a single query (or, where noted, a `.md` companion with narrative context) with a comment block explaining what it detects, what the key thresholds are, and which doc it relates to.

The library is split into two platform-specific trees:

```
kql/
├── sentinel/   Microsoft Sentinel (Log Analytics) — time column is TimeGenerated
└── xdr/        Microsoft Defender XDR Advanced Hunting — time column is Timestamp
```

**Every query in this repo now exists in both a `kql/sentinel/` and a `kql/xdr/` version.** They are not always a mechanical find-and-replace of each other — several detections (identity, email) query genuinely different tables with different schemas on each platform, because the underlying data lands in different places. See [docs/reference/sentinel-vs-advanced-hunting.md](../docs/reference/sentinel-vs-advanced-hunting.md) for which table exists where, and why a few files (marked below) are kept for structural parity even though the table they query isn't actually available on that platform yet.

All queries are syntax-checked by the harness in `tests/kql-smoke/`, across both `.kql` files and fenced ```` ```kql ```` blocks inside `.md` files, in both `sentinel/` and `xdr/` subfolders. See [docs/reference/kql-validation.md](../docs/reference/kql-validation.md) for details.

Replace `HOSTNAME`, `USERNAME`, `PASTE_HASH_HERE`, and datetime placeholders before running. Analyst-tunable values (lookback windows, thresholds) are set at the top of each query as `let` bindings.

---

# Sentinel queries

`kql/sentinel/` — Time column: `TimeGenerated`

## process/

| File | What it detects | MITRE |
|------|----------------|-------|
| [suspicious-powershell.kql](sentinel/process/suspicious-powershell.kql) | Encoded commands, download cradles, fileless execution, evasion flags | T1059.001 |
| [office-spawning-shells.kql](sentinel/process/office-spawning-shells.kql) | Office applications spawning cmd, PowerShell, mshta, or LOLBins | T1566.001, T1204.002 |
| [lolbin-sweep.md](sentinel/process/lolbin-sweep.md) | All LOLBin abuse in one query — certutil, mshta, regsvr32, rundll32, wmic, bitsadmin | T1218 |
| [processes-in-time-window.kql](sentinel/process/processes-in-time-window.kql) | All process events on a device within a specific time window | T1059 |
| [credential-access-sweep.md](sentinel/process/credential-access-sweep.md) | Mimikatz, DCSync, Kerberoasting, AS-REP roasting, token manipulation | T1003, T1558 |
| [post-compromise-discovery-commands.kql](sentinel/process/post-compromise-discovery-commands.kql) | 4+ distinct recon commands from one device in 10 minutes | T1033, T1087.001, T1087.002, T1482, T1018, T1016, T1082, T1057 |

## network/

| File | What it detects | MITRE |
|------|----------------|-------|
| [beacon-high-connection-count.kql](sentinel/network/beacon-high-connection-count.kql) | Devices hitting the same external IP 30+ times per day | T1071.001 |
| [beacon-interval-regularity.md](sentinel/network/beacon-interval-regularity.md) | Low standard deviation of connection intervals — catches jittered beacons | T1071.001 |
| [beacon-after-hours.kql](sentinel/network/beacon-after-hours.kql) | Outbound connections continuing at 01:00–05:00 UTC | T1071.001 |
| [beacon-suspicion-score.md](sentinel/network/beacon-suspicion-score.md) | Combined score across count, after-hours activity, and port consistency | T1071.001 |
| [dns-tunnelling.md](sentinel/network/dns-tunnelling.md) | Base64-encoded subdomains indicating DNS-based C2 or exfiltration | T1071.004 |
| [lateral-movement-scanning.kql](sentinel/network/lateral-movement-scanning.kql) | Device probing internal IPs on SMB, RDP, WinRM, and WMI ports | T1021 |
| [unusual-outbound-ports.kql](sentinel/network/unusual-outbound-ports.kql) | Connections on known C2 and reverse shell ports (4444, 50050, 1337, etc.) | T1571 |
| [lots-suspicious-process-to-cloud.kql](sentinel/network/lots-suspicious-process-to-cloud.kql) | Non-browser process connecting to Discord CDN, Telegram, Pastebin, paste sites | T1102 |
| [lots-scripting-engine-to-cloud-storage.kql](sentinel/network/lots-scripting-engine-to-cloud-storage.kql) | Scripting engines reaching OneDrive, SharePoint, GitHub, Google Drive | T1102 |
| [lots-dead-drop-resolver.kql](sentinel/network/lots-dead-drop-resolver.kql) | Scripting engine hits paste service then immediately connects to a raw IP | T1102.001 |
| [lots-exfiltration-via-cloud.kql](sentinel/network/lots-exfiltration-via-cloud.kql) | High-volume uploads to cloud storage from a non-browser process | T1567 |
| [post-compromise-c2-from-malware.kql](sentinel/network/post-compromise-c2-from-malware.kql) | New external IPs, orphan processes, newly-seen domains, and known C2 ports following a device infection | T1071.001, T1571, T1568.002 |

## persistence/

| File | What it detects | MITRE |
|------|----------------|-------|
| [registry-run-key-modifications.kql](sentinel/persistence/registry-run-key-modifications.kql) | Modifications to HKCU/HKLM Run, RunOnce, and Winlogon keys | T1547.001 |
| [scheduled-task-creation.kql](sentinel/persistence/scheduled-task-creation.kql) | New scheduled tasks created via schtasks.exe | T1053.005 |
| [new-services-installed.kql](sentinel/persistence/new-services-installed.kql) | New Windows services installed on a device | T1543.003 |
| [wmi-subscription-creation.kql](sentinel/persistence/wmi-subscription-creation.kql) | WMI event filter, consumer, and binding creation | T1546.003 |

## files/

| File | What it detects | MITRE |
|------|----------------|-------|
| [executables-in-suspicious-paths.kql](sentinel/files/executables-in-suspicious-paths.kql) | Executables and scripts written to Temp, AppData, ProgramData, Public | T1036.005 |
| [hash-sweep-across-estate.kql](sentinel/files/hash-sweep-across-estate.kql) | Known-bad SHA256 appearing on any device in the estate | T1105 |

## identity/

| File | What it detects | MITRE |
|------|----------------|-------|
| [entra-device-code-auth-flow.md](sentinel/identity/entra-device-code-auth-flow.md) | Device code sign-ins (SigninLogs), flagged for new locations or outside business hours | T1556.006 |
| [entra-aitm-session-anomalies.kql](sentinel/identity/entra-aitm-session-anomalies.kql) | IP change post-MFA, impossible travel, compliance drift, UserAgent mismatch (SigninLogs) — AiTM indicators | T1539 |
| [entra-impossible-travel.kql](sentinel/identity/entra-impossible-travel.kql) | Account signing in from two different countries within 1 hour | T1078 |
| [entra-mfa-fatigue.kql](sentinel/identity/entra-mfa-fatigue.kql) | 5+ failed MFA prompts in 10 minutes against a single account | T1621 |
| [entra-post-compromise-mailbox-rules.md](sentinel/identity/entra-post-compromise-mailbox-rules.md) | Inbox rules (OfficeActivity) created post-compromise that forward externally, delete by keyword, or mark as read | T1114.003 |
| [entra-post-compromise-oauth-grants.kql](sentinel/identity/entra-post-compromise-oauth-grants.kql) | Suspicious OAuth consent grants (AuditLogs) within 1h of a suspicious sign-in | T1528 |
| [entra-post-compromise-email-exfil.kql](sentinel/identity/entra-post-compromise-email-exfil.kql) | Mass mailbox access, external forwarding, eDiscovery, mail export (OfficeActivity) post-compromise | T1114, T1213 |
| [entra-post-compromise-sharepoint-access.kql](sentinel/identity/entra-post-compromise-sharepoint-access.kql) | Bulk SharePoint/OneDrive access above baseline, off-hours access, or external sharing (OfficeActivity) | T1213 |
| [entra-post-compromise-persistence.kql](sentinel/identity/entra-post-compromise-persistence.kql) | New auth methods, service principals, role assignments, guest invites (AuditLogs) post-compromise | T1098.001, T1098.003 |
| [lsass-access-credential-dump.md](sentinel/identity/lsass-access-credential-dump.md) | Non-Windows process opening lsass.exe | T1003.001 |
| [user-on-multiple-devices.kql](sentinel/identity/user-on-multiple-devices.kql) | Account appearing on 3+ devices via network or RDP logon | T1021 |
| [new-local-accounts-created.kql](sentinel/identity/new-local-accounts-created.kql) | New local user accounts created on a device | T1136.001 |
| [all-alerts-for-device.kql](sentinel/identity/all-alerts-for-device.kql) | All Defender alerts for a specific device — ⚠️ `DeviceAlertEvents` is not actually queryable in Sentinel, kept for structural parity, see file header | — |

## ransomware/

| File | What it detects | MITRE |
|------|----------------|-------|
| [vss-shadow-copy-deletion.kql](sentinel/ransomware/vss-shadow-copy-deletion.kql) | vssadmin, wmic shadowcopy delete, bcdedit recovery disabled | T1490 |
| [mass-file-renames.kql](sentinel/ransomware/mass-file-renames.kql) | 20+ file renames per minute from a single process | T1486 |
| [defence-evasion-defender-disabled.kql](sentinel/ransomware/defence-evasion-defender-disabled.kql) | Defender disabled via registry keys | T1562.001 |
| [event-log-clearing.kql](sentinel/ransomware/event-log-clearing.kql) | wevtutil cl or Clear-EventLog used to destroy forensic evidence | T1070.001 |

## email/

⚠️ `EmailEvents`, `EmailAttachmentInfo`, and `UrlClickEvents` are Defender XDR Advanced Hunting-only tables — none of them are exposed in Sentinel Log Analytics today, even via the Defender XDR connector (see [docs/reference/sentinel-vs-advanced-hunting.md](../docs/reference/sentinel-vs-advanced-hunting.md)). These files are kept for structural parity with `kql/xdr/email/` and documented as such in each file header; they will not run in a real Sentinel workspace.

| File | What it detects | MITRE |
|------|----------------|-------|
| [email-phishing-delivery.kql](sentinel/email/email-phishing-delivery.kql) | Mail flagged Phish/Malware that was still delivered to the mailbox | T1566.001, T1566.002 |
| [email-attachment-hunt.kql](sentinel/email/email-attachment-hunt.kql) | Emails with suspicious attachment file types or a known-bad SHA256 | T1566.001, T1105 |
| [email-url-click-through.kql](sentinel/email/email-url-click-through.kql) | Users who clicked through a Safe Links warning | T1566.002, T1204.001 |
| [email-mass-recipient-campaign.kql](sentinel/email/email-mass-recipient-campaign.kql) | Same sender delivering to many recipients in a short window | T1566.001, T1566.002 |
| [email-attachment-landed-on-device.kql](sentinel/email/email-attachment-landed-on-device.kql) | Which devices received and stored a given attachment hash | T1566.001, T1105 |

## pivots/

Cross-investigation queries that chain two or more log sources together to follow an attack chain end-to-end. Start here for a real incident once you have an initial indicator (device, account, email, or sign-in) to pivot from.

| File | What it detects | MITRE (chained) |
|------|----------------|-------|
| [phishing-to-device-compromise.md](sentinel/pivots/phishing-to-device-compromise.md) | Email received → attachment landed on disk → process executed — ⚠️ EmailEvents/EmailAttachmentInfo stages not queryable in Sentinel, kept for structural parity | T1566.001, T1204.002, T1105 |
| [device-compromise-to-lateral-movement.md](sentinel/pivots/device-compromise-to-lateral-movement.md) | Accounts used, internal IPs touched, remote-exec tools seen, and account reuse on a different device | T1078, T1021.002, T1021.006 |
| [aitm-phishing-to-persistence.md](sentinel/pivots/aitm-phishing-to-persistence.md) | Suspicious sign-in (SigninLogs) → inbox rule (OfficeActivity) → OAuth grant/service principal (AuditLogs) within 24h | T1556.006, T1098.001, T1114.003, T1528 |
| [credential-dump-to-spread.kql](sentinel/pivots/credential-dump-to-spread.kql) | lsass access → corroborating credential-dump artefact → account reuse on another device within 2h | T1003.001, T1078 |
| [email-click-to-execution.kql](sentinel/pivots/email-click-to-execution.kql) | Safe Links click-through → device that connected → process executed — ⚠️ UrlClickEvents stage not queryable in Sentinel, kept for structural parity | T1566.002, T1204.001 |
| [post-compromise-lateral-movement-timeline.kql](sentinel/pivots/post-compromise-lateral-movement-timeline.kql) | Correlated logon/network/process timeline of lateral movement after device compromise | T1021.002, T1021.006, T1078 |

## functions/

Reusable `let` function definitions — call these from other queries instead of repeating the same predicate. Each file is runnable on its own (definition + example call).

| File | What it detects | MITRE |
|------|----------------|-------|
| [fn-beacon-score.kql](sentinel/functions/fn-beacon-score.kql) | Connection count, mean interval, standard deviation, and suspicion score for one device/remote-IP pair | T1071.001 |
| [fn-is-lolbin.kql](sentinel/functions/fn-is-lolbin.kql) | True if a process matches a known LOLBin abuse pattern | T1218 |
| [fn-is-known-good-beacon.kql](sentinel/functions/fn-is-known-good-beacon.kql) | True if a process/destination pair matches known-good beaconing software | — |
| [fn-suspicious-path.kql](sentinel/functions/fn-suspicious-path.kql) | True if a folder path is a known suspicious write/execution location | T1036.005 |

---

# XDR queries

`kql/xdr/` — Time column: `Timestamp`

## process/

| File | What it detects | MITRE |
|------|----------------|-------|
| [suspicious-powershell.kql](xdr/process/suspicious-powershell.kql) | Encoded commands, download cradles, fileless execution, evasion flags | T1059.001 |
| [office-spawning-shells.kql](xdr/process/office-spawning-shells.kql) | Office applications spawning cmd, PowerShell, mshta, or LOLBins | T1566.001, T1204.002 |
| [lolbin-sweep.md](xdr/process/lolbin-sweep.md) | All LOLBin abuse in one query — certutil, mshta, regsvr32, rundll32, wmic, bitsadmin | T1218 |
| [processes-in-time-window.kql](xdr/process/processes-in-time-window.kql) | All process events on a device within a specific time window | T1059 |
| [credential-access-sweep.md](xdr/process/credential-access-sweep.md) | Mimikatz, DCSync, Kerberoasting, AS-REP roasting, token manipulation | T1003, T1558 |
| [post-compromise-discovery-commands.kql](xdr/process/post-compromise-discovery-commands.kql) | 4+ distinct recon commands from one device in 10 minutes | T1033, T1087.001, T1087.002, T1482, T1018, T1016, T1082, T1057 |

## network/

| File | What it detects | MITRE |
|------|----------------|-------|
| [beacon-high-connection-count.kql](xdr/network/beacon-high-connection-count.kql) | Devices hitting the same external IP 30+ times per day | T1071.001 |
| [beacon-interval-regularity.md](xdr/network/beacon-interval-regularity.md) | Low standard deviation of connection intervals — catches jittered beacons | T1071.001 |
| [beacon-after-hours.kql](xdr/network/beacon-after-hours.kql) | Outbound connections continuing at 01:00–05:00 UTC | T1071.001 |
| [beacon-suspicion-score.md](xdr/network/beacon-suspicion-score.md) | Combined score across count, after-hours activity, and port consistency | T1071.001 |
| [dns-tunnelling.md](xdr/network/dns-tunnelling.md) | Base64-encoded subdomains indicating DNS-based C2 or exfiltration | T1071.004 |
| [lateral-movement-scanning.kql](xdr/network/lateral-movement-scanning.kql) | Device probing internal IPs on SMB, RDP, WinRM, and WMI ports | T1021 |
| [unusual-outbound-ports.kql](xdr/network/unusual-outbound-ports.kql) | Connections on known C2 and reverse shell ports (4444, 50050, 1337, etc.) | T1571 |
| [lots-suspicious-process-to-cloud.kql](xdr/network/lots-suspicious-process-to-cloud.kql) | Non-browser process connecting to Discord CDN, Telegram, Pastebin, paste sites | T1102 |
| [lots-scripting-engine-to-cloud-storage.kql](xdr/network/lots-scripting-engine-to-cloud-storage.kql) | Scripting engines reaching OneDrive, SharePoint, GitHub, Google Drive | T1102 |
| [lots-dead-drop-resolver.kql](xdr/network/lots-dead-drop-resolver.kql) | Scripting engine hits paste service then immediately connects to a raw IP | T1102.001 |
| [lots-exfiltration-via-cloud.kql](xdr/network/lots-exfiltration-via-cloud.kql) | High-volume uploads to cloud storage from a non-browser process | T1567 |
| [post-compromise-c2-from-malware.kql](xdr/network/post-compromise-c2-from-malware.kql) | New external IPs, orphan processes, newly-seen domains, and known C2 ports following a device infection | T1071.001, T1571, T1568.002 |

## persistence/

| File | What it detects | MITRE |
|------|----------------|-------|
| [registry-run-key-modifications.kql](xdr/persistence/registry-run-key-modifications.kql) | Modifications to HKCU/HKLM Run, RunOnce, and Winlogon keys | T1547.001 |
| [scheduled-task-creation.kql](xdr/persistence/scheduled-task-creation.kql) | New scheduled tasks created via schtasks.exe | T1053.005 |
| [new-services-installed.kql](xdr/persistence/new-services-installed.kql) | New Windows services installed on a device | T1543.003 |
| [wmi-subscription-creation.kql](xdr/persistence/wmi-subscription-creation.kql) | WMI event filter, consumer, and binding creation | T1546.003 |

## files/

| File | What it detects | MITRE |
|------|----------------|-------|
| [executables-in-suspicious-paths.kql](xdr/files/executables-in-suspicious-paths.kql) | Executables and scripts written to Temp, AppData, ProgramData, Public | T1036.005 |
| [hash-sweep-across-estate.kql](xdr/files/hash-sweep-across-estate.kql) | Known-bad SHA256 appearing on any device in the estate | T1105 |

## identity/

| File | What it detects | MITRE |
|------|----------------|-------|
| [entra-device-code-auth-flow.md](xdr/identity/entra-device-code-auth-flow.md) | Device code sign-ins (EntraIdSignInEvents), flagged for new locations or outside business hours | T1556.006 |
| [entra-aitm-session-anomalies.md](xdr/identity/entra-aitm-session-anomalies.md) | Token replay, impossible travel post-MFA, compliance-state drop, UserAgent mismatch — AiTM indicators | T1539 |
| [entra-impossible-travel.kql](xdr/identity/entra-impossible-travel.kql) | Account signing in from two different countries within 1 hour | T1078 |
| [entra-mfa-fatigue.kql](xdr/identity/entra-mfa-fatigue.kql) | 5+ failed MFA prompts in 10 minutes against a single account | T1621 |
| [entra-post-compromise-mailbox-rules.kql](xdr/identity/entra-post-compromise-mailbox-rules.kql) | Inbox rules (CloudAppEvents) created post-compromise that forward externally, delete by keyword, or mark as read | T1114.003 |
| [entra-post-compromise-oauth-grants.kql](xdr/identity/entra-post-compromise-oauth-grants.kql) | Suspicious OAuth consent grants (CloudAppEvents) within 1h of a suspicious sign-in | T1528 |
| [entra-post-compromise-email-exfil.kql](xdr/identity/entra-post-compromise-email-exfil.kql) | Mass mailbox access/export (CloudAppEvents) + external forwarding of sent mail (EmailEvents) post-compromise | T1114, T1213 |
| [entra-post-compromise-sharepoint-access.kql](xdr/identity/entra-post-compromise-sharepoint-access.kql) | Bulk SharePoint/OneDrive access above baseline, off-hours access, or external sharing (CloudAppEvents) | T1213 |
| [entra-post-compromise-persistence.kql](xdr/identity/entra-post-compromise-persistence.kql) | New MFA methods, service principals, role assignments, guest invites (CloudAppEvents) post-compromise | T1098.001, T1098.003 |
| [lsass-access-credential-dump.md](xdr/identity/lsass-access-credential-dump.md) | Non-Windows process opening lsass.exe | T1003.001 |
| [user-on-multiple-devices.kql](xdr/identity/user-on-multiple-devices.kql) | Account appearing on 3+ devices via network or RDP logon | T1021 |
| [new-local-accounts-created.kql](xdr/identity/new-local-accounts-created.kql) | New local user accounts created on a device | T1136.001 |
| [all-alerts-for-device.kql](xdr/identity/all-alerts-for-device.kql) | All Defender alerts for a specific device in the last 7 days | — |

## ransomware/

| File | What it detects | MITRE |
|------|----------------|-------|
| [vss-shadow-copy-deletion.kql](xdr/ransomware/vss-shadow-copy-deletion.kql) | vssadmin, wmic shadowcopy delete, bcdedit recovery disabled | T1490 |
| [mass-file-renames.kql](xdr/ransomware/mass-file-renames.kql) | 20+ file renames per minute from a single process | T1486 |
| [defence-evasion-defender-disabled.kql](xdr/ransomware/defence-evasion-defender-disabled.kql) | Defender disabled via registry keys | T1562.001 |
| [event-log-clearing.kql](xdr/ransomware/event-log-clearing.kql) | wevtutil cl or Clear-EventLog used to destroy forensic evidence | T1070.001 |

## email/

| File | What it detects | MITRE |
|------|----------------|-------|
| [email-phishing-delivery.kql](xdr/email/email-phishing-delivery.kql) | Mail flagged Phish/Malware that was still delivered to the mailbox | T1566.001, T1566.002 |
| [email-attachment-hunt.kql](xdr/email/email-attachment-hunt.kql) | Emails with suspicious attachment file types or a known-bad SHA256 | T1566.001, T1105 |
| [email-url-click-through.kql](xdr/email/email-url-click-through.kql) | Users who clicked through a Safe Links warning | T1566.002, T1204.001 |
| [email-mass-recipient-campaign.kql](xdr/email/email-mass-recipient-campaign.kql) | Same sender delivering to many recipients in a short window | T1566.001, T1566.002 |
| [email-attachment-landed-on-device.kql](xdr/email/email-attachment-landed-on-device.kql) | Which devices received and stored a given attachment hash | T1566.001, T1105 |

## pivots/

Cross-investigation queries that chain two or more log sources together to follow an attack chain end-to-end. Start here for a real incident once you have an initial indicator (device, account, email, or sign-in) to pivot from.

| File | What it detects | MITRE (chained) |
|------|----------------|-------|
| [phishing-to-device-compromise.md](xdr/pivots/phishing-to-device-compromise.md) | Email received → attachment landed on disk → process executed, in one timeline | T1566.001, T1204.002, T1105 |
| [device-compromise-to-lateral-movement.md](xdr/pivots/device-compromise-to-lateral-movement.md) | Accounts used, internal IPs touched, remote-exec tools seen, and account reuse on a different device | T1078, T1021.002, T1021.006 |
| [aitm-phishing-to-persistence.md](xdr/pivots/aitm-phishing-to-persistence.md) | Suspicious device code/AiTM sign-in → new MFA method, inbox rule, OAuth grant, or service principal within 24h | T1556.006, T1098.001, T1114.003, T1528 |
| [credential-dump-to-spread.kql](xdr/pivots/credential-dump-to-spread.kql) | lsass access → corroborating credential-dump artefact → account reuse on another device within 2h | T1003.001, T1078 |
| [email-click-to-execution.kql](xdr/pivots/email-click-to-execution.kql) | Safe Links click-through → device that connected → process executed within 10 minutes | T1566.002, T1204.001 |
| [post-compromise-lateral-movement-timeline.kql](xdr/pivots/post-compromise-lateral-movement-timeline.kql) | Correlated logon/network/process timeline of lateral movement after device compromise | T1021.002, T1021.006, T1078 |

## functions/

Reusable `let` function definitions — call these from other queries instead of repeating the same predicate. Each file is runnable on its own (definition + example call).

| File | What it detects | MITRE |
|------|----------------|-------|
| [fn-beacon-score.kql](xdr/functions/fn-beacon-score.kql) | Connection count, mean interval, standard deviation, and suspicion score for one device/remote-IP pair | T1071.001 |
| [fn-is-lolbin.kql](xdr/functions/fn-is-lolbin.kql) | True if a process matches a known LOLBin abuse pattern | T1218 |
| [fn-is-known-good-beacon.kql](xdr/functions/fn-is-known-good-beacon.kql) | True if a process/destination pair matches known-good beaconing software | — |
| [fn-suspicious-path.kql](xdr/functions/fn-suspicious-path.kql) | True if a folder path is a known suspicious write/execution location | T1036.005 |
