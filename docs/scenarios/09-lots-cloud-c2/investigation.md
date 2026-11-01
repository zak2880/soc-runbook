# LOTS & cloud C2 — investigation

## What is LOTS?

Living Off Trusted Sites — attackers use legitimate cloud infrastructure for C2 and payload delivery. Traffic to OneDrive, GitHub, Discord, or Telegram looks identical to normal business traffic. The domain is trusted, the cert is valid, the connection is over port 443. Traditional network detection largely fails here.

> You're no longer looking for bad domains. You're looking for bad behaviour on good domains.

---

## Services commonly abused

| Service | How it's used |
|---------|--------------|
| OneDrive / SharePoint | Stage payloads, exfiltrate data, C2 via shared files |
| GitHub / GitLab | Host scripts, store C2 configs in repos or Gists |
| Discord CDN | Host payloads — links don't expire, no auth needed |
| Telegram | Bot API used as C2 channel |
| Google Drive / Docs | Stage payloads, dead-drop resolvers |
| Pastebin / paste services | Dead-drop resolvers, encoded payloads |
| Dropbox API | Exfiltration and payload hosting |
| AWS / Azure / GCP object storage | Payloads on S3, Azure Blob, GCS |

---

## Dead-drop resolver technique

Malware GETs a trusted page (Google Doc, GitHub Gist, Pastebin) to retrieve the current C2 IP. The binary has no hardcoded address — makes static analysis much harder.

**Red flags:** Scripting engine makes a single short GET to a paste service, then immediately connects to a raw IP (no hostname).

---

## Detection approach

You can't block these destinations. Look for unusual processes reaching them.

**Processes that should never reach paste or file-share services:**
`powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`

**KQL — scripting engine to cloud/paste services:**
```kql
// LOTS — scripting engines reaching cloud storage and collaboration services
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Covers: OneDrive, SharePoint, Google Drive, GitHub, Discord, Telegram, Dropbox, Pastebin
// Scripting engines have no legitimate reason to contact these services directly
// Ref: docs/scenarios/09-lots-cloud-c2/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where InitiatingProcessFileName in~ (
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe")
| where RemoteUrl has_any (
    "onedrive.live.com", "sharepoint.com", "1drv.ms",
    "drive.google.com", "docs.google.com",
    "github.com", "raw.githubusercontent.com",
    "discord", "cdn.discordapp.com",
    "telegram", "api.telegram.org",
    "dropbox.com", "pastebin.com")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    RemoteUrl, RemoteIP,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

**KQL — dead-drop resolver (paste GET then raw IP connection):**
```kql
// LOTS — dead-drop resolver detection
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Scripting engine GETs a paste/storage service then connects to a raw IP within 5 minutes
// The storage page contains the actual C2 IP — no hardcoded address in the binary
// isempty(RemoteUrl) = direct IP connection with no hostname resolution
// Same process = same InitiatingProcessId AND InitiatingProcessCreationTime (PIDs are reused)
// Ref: docs/scenarios/09-lots-cloud-c2/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
let ResolverHits = DeviceNetworkEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where InitiatingProcessFileName in~ (
    "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe")
| where RemoteUrl has_any (
    "pastebin.com", "raw.githubusercontent.com", "gist.github.com",
    "docs.google.com", "drive.google.com", "api.telegram.org",
    "cdn.discordapp.com")
| project DeviceName, InitiatingProcessId, InitiatingProcessCreationTime,
    ResolverTime = Timestamp, ResolverUrl = RemoteUrl;
DeviceNetworkEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where RemoteIPType == "Public"
| where isempty(RemoteUrl)
| join kind=inner ResolverHits on DeviceName, InitiatingProcessId, InitiatingProcessCreationTime
| where Timestamp between (ResolverTime .. (ResolverTime + 5m))
| project Timestamp, ResolverTime, DeviceName, InitiatingProcessFileName,
    InitiatingProcessId, ResolverUrl, RemoteIP, RemotePort
| order by Timestamp asc
```

**KQL — non-browser processes connecting to cloud storage (potential exfiltration; upload volume is not available in MDE and needs proxy/firewall logs):**
```kql
// LOTS — non-browser processes connecting to cloud storage (possible exfiltration)
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Covers potential exfiltration via OneDrive, SharePoint, Google Drive, Dropbox, S3, Azure Blob
// Ranks process/destination pairs by connection count; no volume threshold
// TODO: byte volumes need proxy/firewall logs; DeviceNetworkEvents has no SentBytes/ReceivedBytes
// Ref: docs/scenarios/09-lots-cloud-c2/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "onedrive.exe",
    "dropbox.exe", "teams.exe", "outlook.exe", "googledrivesync.exe")
| where RemoteUrl has_any (
    "onedrive.live.com", "sharepoint.com",
    "drive.google.com", "dropboxapi.com",
    "api.dropbox.com", "s3.amazonaws.com",
    "blob.core.windows.net")
| summarize
    Connections = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Connections desc
```
