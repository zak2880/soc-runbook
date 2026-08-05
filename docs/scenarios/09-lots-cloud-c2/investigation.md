# LOTS & cloud C2 — investigation

## What is LOTS?

Living Off Trusted Sites — attackers use legitimate cloud infrastructure for C2 and payload delivery. Traffic to OneDrive, GitHub, Discord, or Telegram looks identical to normal business traffic. The domain is trusted, the cert is valid, the connection is over port 443. Traditional network detection largely fails here.

> You're no longer looking for bad domains. You're looking for bad behaviour on good domains.

---

> **Before escalating:** check [common false positives — C2 / Network](../../reference/common-false-positives.md#c2--network) — confirm this isn't one of the known benign patterns before treating it as a true positive.

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
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe")
| where RemoteUrl has_any (
    "onedrive.live.com", "sharepoint.com",
    "drive.google.com", "docs.google.com",
    "github.com", "raw.githubusercontent.com",
    "cdn.discordapp.com", "api.telegram.org",
    "dropbox.com", "pastebin.com")
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, AccountName, RemoteUrl, RemoteIP,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

**KQL — dead-drop resolver (paste GET then raw IP connection):**
```kql
let SuspiciousProcesses = DeviceNetworkEvents
| where InitiatingProcessFileName in~ (
    "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe")
| where RemoteUrl has_any (
    "pastebin.com", "raw.githubusercontent.com",
    "docs.google.com", "api.telegram.org", "cdn.discordapp.com")
| project DeviceName, InitiatingProcessFileName,
    InitiatingProcessId, TimeGenerated;
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where isempty(RemoteUrl)
| join kind=inner SuspiciousProcesses on DeviceName, InitiatingProcessId
| where TimeGenerated1 between (TimeGenerated .. (TimeGenerated + 5min))
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
    RemoteIP, RemotePort
```

**KQL — high-volume uploads to cloud (potential exfiltration):**
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "onedrive.exe",
    "dropbox.exe", "teams.exe", "outlook.exe")
| where RemoteUrl has_any (
    "onedrive.live.com", "sharepoint.com", "drive.google.com",
    "dropboxapi.com", "s3.amazonaws.com", "blob.core.windows.net")
| where SentBytes > 5000000
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, AccountName,
    RemoteUrl, SentBytes, InitiatingProcessFileName
| order by SentBytes desc
```
