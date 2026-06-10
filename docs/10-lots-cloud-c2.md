# Living Off Trusted Sites (LOTS) & Cloud C2

Attackers increasingly use legitimate cloud infrastructure for C2 and payload delivery. Traffic to OneDrive, GitHub, Discord, or Google Drive looks identical to normal business traffic — the domain is trusted, the certificate is valid, and the connection often goes over port 443. Traditional network-based detection largely fails here.

> The key shift: you're no longer looking for bad domains. You're looking for bad behaviour on good domains.

---

## What LOTS looks like

| Service abused | How it's used |
|----------------|---------------|
| **OneDrive / SharePoint** | Stage payloads, exfiltrate data, C2 channel via shared files |
| **GitHub / GitLab** | Host malicious scripts, store C2 configs in repos or Gists |
| **Discord CDN** | Host payloads at `cdn.discordapp.com` — links don't expire, no auth needed |
| **Telegram** | Bot API used as a C2 channel (`api.telegram.org`) |
| **Google Drive / Docs** | Stage payloads, dead-drop resolvers (C2 IP stored in a Google Doc) |
| **Pastebin / paste services** | Dead-drop resolvers, storing encoded payloads |
| **Dropbox API** | Exfiltration and payload hosting |
| **AWS / Azure / GCP object storage** | Payloads hosted on S3, Azure Blob, GCS — signed Microsoft/Amazon/Google certs |

---

## Detection approach

You won't block these destinations. You look for unusual processes making connections to them.

**Processes that should never reach paste/file-share services:**

```kql
DeviceNetworkEvents
| where RemoteUrl has_any (
    "cdn.discordapp.com", "discord.com/api",
    "api.telegram.org",
    "raw.githubusercontent.com", "gist.githubusercontent.com",
    "pastebin.com", "paste.ee",
    "transfer.sh", "file.io",
    "anonfiles.com", "gofile.io")
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe",
    "brave.exe", "iexplore.exe", "teams.exe",
    "outlook.exe", "onedrive.exe", "dropbox.exe")
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName,
    RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

> A hit from `powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`, or any unknown binary to these domains is suspicious. Prioritise these over browser hits.

**Scripting engines reaching cloud storage services:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe")
| where RemoteUrl has_any (
    "onedrive.live.com", "sharepoint.com", "1drv.ms",
    "drive.google.com", "docs.google.com",
    "github.com", "raw.githubusercontent.com",
    "discord", "telegram", "dropbox.com", "pastebin.com")
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## Dead-drop resolver technique

A dead-drop resolver is a publicly accessible, trusted page containing the actual C2 IP address. The malware reaches out to a Google Doc or GitHub Gist to retrieve the current C2 address, then connects directly to that IP. The binary itself contains no hardcoded C2, making static analysis much harder.

**Red flags:** Scripting engine makes a single short GET to a paste/storage service, immediately followed by a new outbound connection to a raw IP (no hostname). The storage service response is very short — just an IP or short encoded string.

**KQL — scripting engine hitting a paste service then immediately connecting to a raw IP:**

```kql
let SuspiciousProcesses = DeviceNetworkEvents
| where InitiatingProcessFileName in~ (
    "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe")
| where RemoteUrl has_any (
    "pastebin.com", "raw.githubusercontent.com", "gist.github.com",
    "docs.google.com", "drive.google.com", "api.telegram.org",
    "cdn.discordapp.com")
| project DeviceName, InitiatingProcessFileName,
    InitiatingProcessId, Timestamp;
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where isempty(RemoteUrl)
| join kind=inner SuspiciousProcesses on DeviceName, InitiatingProcessId
| where Timestamp1 between (Timestamp .. (Timestamp + 5min))
| project Timestamp, DeviceName, InitiatingProcessFileName,
    RemoteIP, RemotePort
```

---

## Exfiltration via cloud services

Exfil over legitimate cloud services is hard to detect on content alone — it's encrypted. Focus on volume and process context.

**KQL — high-volume uploads from a non-browser process:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "onedrive.exe",
    "dropbox.exe", "teams.exe", "outlook.exe", "googledrivesync.exe")
| where RemoteUrl has_any (
    "onedrive.live.com", "sharepoint.com",
    "drive.google.com", "dropboxapi.com",
    "api.dropbox.com", "s3.amazonaws.com",
    "blob.core.windows.net")
| where SentBytes > 5000000
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName,
    RemoteUrl, SentBytes, ReceivedBytes,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by SentBytes desc
```

---

## HTTPS C2 over port 443 to cloud provider IP ranges

Some C2 frameworks (Cobalt Strike, Sliver, Havoc) use malleable profiles that disguise traffic as legitimate HTTPS to cloud provider IP ranges — AWS, Azure, Cloudflare, Fastly. The destination resolves to a legitimate CDN IP and the certificate may be valid. These can't be blocked without breaking legitimate traffic. Detection is behavioural.

**KQL — periodic low-volume connections to a single public IP from an unusual process:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "svchost.exe",
    "MsMpEng.exe", "teams.exe", "outlook.exe", "onedrive.exe")
| where RemotePort == 443
| where RemoteIPType == "Public"
| where Timestamp > ago(24h)
| summarize
    ConnectionCount = count(),
    UniqueIPs = dcount(RemoteIP),
    BytesSent = sum(SentBytes),
    BytesReceived = sum(ReceivedBytes)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where ConnectionCount > 10 and UniqueIPs == 1
| where BytesSent between (1000 .. 50000)
| order by ConnectionCount desc
```

> Combine with parent-child process context. A process with no legitimate reason to make HTTPS calls that shows this pattern is worth investigating.

---

## Escalate on

- Scripting engine (`powershell` / `wscript` / `mshta`) connecting to Discord CDN, Telegram API, or Pastebin
- Unknown binary making a single GET to a paste service immediately followed by a raw IP connection
- Non-browser process making multi-MB uploads to OneDrive, SharePoint, or S3
- Repeated low-volume HTTPS connections to a single CDN IP from a non-browser process
