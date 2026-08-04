# Changelog

## 2026-08-04 — Detection format update
- Added `kql/functions/` — reusable KQL functions
- Added `kql/pivots/` — cross-investigation pivot queries
- Refactored all existing queries to use `let` variable blocks
- Added `.md` detection files for 11 highest-value queries

## 2026-08-04 — Initial library

### process/
- `process/suspicious-powershell.kql` — Encoded commands, download cradles, fileless execution, evasion flags
- `process/office-spawning-shells.kql` — Office applications spawning cmd, PowerShell, mshta, or LOLBins
- `process/lolbin-sweep.kql` — All LOLBin abuse in one query — certutil, mshta, regsvr32, rundll32, wmic, bitsadmin
- `process/processes-in-time-window.kql` — All process events on a device within a specific time window
- `process/credential-access-sweep.kql` — Mimikatz, DCSync, Kerberoasting, AS-REP roasting, token manipulation
- `process/post-compromise-discovery-commands.kql` — 4+ distinct recon commands (whoami, net user, nltest, arp, systeminfo, etc.) from one device in 10 minutes

### network/
- `network/beacon-high-connection-count.kql` — Devices hitting the same external IP 30+ times per day
- `network/beacon-interval-regularity.kql` — Low standard deviation of connection intervals — catches jittered beacons
- `network/beacon-after-hours.kql` — Outbound connections continuing at 01:00–05:00 UTC
- `network/beacon-suspicion-score.kql` — Combined score across count, after-hours activity, and port consistency
- `network/dns-tunnelling.kql` — Base64-encoded subdomains indicating DNS-based C2 or exfiltration
- `network/lateral-movement-scanning.kql` — Device probing internal IPs on SMB, RDP, WinRM, and WMI ports
- `network/unusual-outbound-ports.kql` — Connections on known C2 and reverse shell ports (4444, 50050, 1337, etc.)
- `network/lots-suspicious-process-to-cloud.kql` — Non-browser process connecting to Discord CDN, Telegram, Pastebin, paste sites
- `network/lots-scripting-engine-to-cloud-storage.kql` — Scripting engines reaching OneDrive, SharePoint, GitHub, Google Drive
- `network/lots-dead-drop-resolver.kql` — Scripting engine hits paste service then immediately connects to a raw IP
- `network/lots-exfiltration-via-cloud.kql` — High-volume uploads to cloud storage from a non-browser process
- `network/post-compromise-c2-from-malware.kql` — New external IPs, orphan processes, newly-seen domains, and known C2 ports following a device infection
- `network/post-compromise-lateral-movement-timeline.kql` — Correlated logon/network/process timeline of lateral movement after device compromise

### persistence/
- `persistence/registry-run-key-modifications.kql` — Modifications to HKCU/HKLM Run, RunOnce, and Winlogon keys
- `persistence/scheduled-task-creation.kql` — New scheduled tasks created via schtasks.exe
- `persistence/new-services-installed.kql` — New Windows services installed on a device
- `persistence/wmi-subscription-creation.kql` — WMI event filter, consumer, and binding creation

### files/
- `files/executables-in-suspicious-paths.kql` — Executables and scripts written to Temp, AppData, ProgramData, Public
- `files/hash-sweep-across-estate.kql` — Known-bad SHA256 appearing on any device in the estate

### identity/
- `identity/lsass-access-credential-dump.kql` — Non-Windows process opening lsass.exe
- `identity/user-on-multiple-devices.kql` — Account appearing on 3+ devices via network or RDP logon
- `identity/new-local-accounts-created.kql` — New local user accounts created on a device
- `identity/all-alerts-for-device.kql` — All Defender alerts for a specific device in the last 7 days
- `identity/entra-impossible-travel.kql` — Account signing in from two different countries within 1 hour
- `identity/entra-mfa-fatigue.kql` — 5+ failed MFA prompts in 10 minutes against a single account
- `identity/entra-device-code-auth-flow.kql` — Device code sign-ins, flagged for new locations or outside business hours
- `identity/entra-aitm-session-anomalies.kql` — Token replay, impossible travel post-MFA, compliance-state drop, UserAgent mismatch — AiTM phishing indicators
- `identity/entra-post-compromise-oauth-grants.kql` — Suspicious OAuth consent grants within 1h of a suspicious sign-in
- `identity/entra-post-compromise-mailbox-rules.kql` — Inbox rules created post-compromise that forward externally, delete by keyword, or mark as read
- `identity/entra-post-compromise-email-exfil.kql` — Mass mailbox access, external forwarding, eDiscovery, mail export, and attachment/URL exfil signals post-compromise
- `identity/entra-post-compromise-sharepoint-access.kql` — Bulk SharePoint/OneDrive access above baseline, off-hours access, or external sharing post-compromise
- `identity/entra-post-compromise-persistence.kql` — New MFA methods, service principals, CA exclusions, guest invites, or role assignments post-compromise

### ransomware/
- `ransomware/vss-shadow-copy-deletion.kql` — vssadmin, wmic shadowcopy delete, bcdedit recovery disabled
- `ransomware/mass-file-renames.kql` — 20+ file renames per minute from a single process
- `ransomware/defence-evasion-defender-disabled.kql` — Defender disabled via registry keys
- `ransomware/event-log-clearing.kql` — wevtutil cl or Clear-EventLog used to destroy forensic evidence
