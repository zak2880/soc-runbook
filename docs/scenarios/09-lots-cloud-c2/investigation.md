# LOTS & cloud C2 — investigation

## What is LOTS?

Living Off Trusted Sites: attackers use legitimate cloud services for command and control (C2), payload delivery and exfiltration. Traffic to OneDrive, GitHub, Discord or Telegram looks like normal business traffic. The domain is trusted, the certificate is valid, the connection is on port 443, and devices were usually talking to these services before the compromise. Domain reputation tells you nothing here.

> You're no longer looking for bad domains. You're looking for bad behaviour on good domains.

**What the network events can and can't tell you**
- `DeviceNetworkEvents` gives the host (`RemoteUrl`), IP, port and the process that connected (`InitiatingProcess*` columns).
- For HTTPS, expect the host name only. The path is inside the encrypted session; Microsoft states Network Protection reads the host name of an HTTPS connection from the TLS handshake. Step 3 recovers the full URL.
- There are no byte counts, HTTP methods or user agents. Upload volume needs the customer's proxy or firewall logs.
- Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

T0 = first malicious event: the first connection to the service by the suspicious process, or the arrival of the file or script it ran, whichever is earlier. It is not the alert time.

---

## Services commonly abused

| Service | How it's used |
|---------|--------------|
| OneDrive / SharePoint | Stage payloads, exfiltrate data, C2 via shared files |
| Microsoft Graph API (`graph.microsoft.com`) | C2 through an attacker-controlled OneDrive account or Outlook drafts. ATT&CK T1102.002 lists ODAgent, OilBooster and OilCheck: compiled tools, not scripts |
| GitHub / GitLab | Host scripts, store C2 configs in repos or Gists |
| Discord | Payloads as CDN attachments: attachment links are signed and expire, but are easy to re-share. Webhooks on `discord.com` for exfiltration and C2 |
| Telegram | Bot API (`api.telegram.org`) as a C2 or exfiltration channel. The bot token is part of every request URL |
| Slack, webhook.site and other webhook services | Exfiltration over webhook (ATT&CK T1567.004) |
| Google Drive / Docs | Stage payloads, dead-drop resolvers |
| Pastebin / paste services | Dead-drop resolvers, encoded payloads |
| Dropbox | C2, exfiltration and payload hosting |
| AWS / Azure / GCP object storage | Payloads and exfiltration on S3, Azure Blob, GCS |
| MEGA and the storage above, through Rclone | Bulk exfiltration. ATT&CK describes Rclone as a command-line tool that syncs files with Dropbox, Google Drive, Amazon S3 and MEGA |

---

## Dead-drop resolver technique

Malware fetches a page on a trusted service (Google Doc, GitHub Gist, Pastebin) that holds the current C2 address. ATT&CK: the page carries embedded, often obfuscated or encoded, domains or IP addresses. The binary has no hardcoded address, which makes static analysis harder.

**Red flags:** the client fetches from a paste or storage service, then within minutes it, or a process it starts, connects to a host or IP that isn't part of that service. The follow-on can be a raw IP or a domain. The dead-drop query below covers only one case (Step 4).

---

## Step 1 — identify the client

The client is the process that made the connection. Classify it from its folder and signer; a file name alone isn't evidence.

| Class | What it is | How to confirm |
|-------|-----------|----------------|
| A. Browser | Edge, Chrome, Firefox and similar | `InitiatingProcessFolderPath` is the browser's normal install folder |
| B. Sync or collaboration client | OneDrive, Teams, Dropbox, Google Drive desktop | Normal install folder, and `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` with `IsTrusted` true |
| C. Scripting engine or downloader | `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `curl.exe`, `certutil.exe`, `bitsadmin.exe` | Read the command line and the script it ran (Step 3) |
| D. Anything else | Unsigned, signed by an unexpected publisher, a known name in an unusual folder, a signed program that loaded a DLL from its own or a user-writable folder, a non-Microsoft process calling Microsoft Graph | Folder, `DeviceFileCertificateInfo`, and `DeviceImageLoadEvents` for the DLLs it loaded |

- `InitiatingProcessVersionInfoCompanyName` is read from the file's own version information, which the file's author sets. Use `DeviceFileCertificateInfo` for the signer.
- `cmd.exe` usually launches the downloader rather than connecting itself. ATT&CK T1105 records DarkGate batch scripts running `curl` to fetch payloads. Look at its children.
- Graph API implants are compiled code. The connecting process can carry a legitimate name, so check its folder, signer and loaded DLLs.
- Legitimate admin scripts also reach SharePoint, GitHub and object storage. Treating one as benign needs a named script and a change record (playbook, Closing as a false positive), not a guess.
- Keep browser rows. A user's browser following a link is a common way the first-stage payload arrives. They are the starting point for Step 6 (downloads) and Step 8 (first contact).

---

## Step 2 — was it blocked?

- Network Protection logs blocks in `DeviceEvents` with `ActionType` `ExploitGuardNetworkProtectionBlocked`, and audit-only hits as `ExploitGuardNetworkProtectionAudited`. `AdditionalFields` holds `ResponseCategory`; `CustomBlockList` means a custom indicator. A block also shows in the alerts queue.
- `DeviceNetworkEvents` is reported from the TCP layer. Microsoft states a blocked site can still show `ConnectionSuccess` there. That row doesn't prove the connection worked, and it doesn't prove a block failed.
- Network Protection enforces indicators only in block mode. In audit mode the connection was allowed.
- A block doesn't clear the device. The client still ran and may have other channels.

---

## Step 3 — recover the full URL

For HTTPS the network event has the host only. The rest comes from:
- `InitiatingProcessCommandLine` of the client and of its parent
- the script on disk (playbook step 10 preserves it)
- `FileOriginUrl` and `FileOriginReferrerUrl` on files the client wrote (`DeviceFileEvents`)
- the customer's proxy logs, if they have them

**Handle what you find as evidence**
- Don't browse to, download from or call the URL from any device.
- Don't submit it to public URL scanners. A SharePoint or OneDrive share link can lead to the customer's own data. A Telegram Bot API request has the form `https://api.telegram.org/bot<token>/METHOD_NAME`, so the URL carries the attacker's bot token. Unlisted is not private: urlscan states its Pro customers can search Public and Unlisted scans.
- Record share links, bot tokens and webhook URLs as IOCs in the ticket. Using them can tell the attacker they have been found.

---

## Step 4 — check for a dead-drop resolver

- Run the dead-drop query (below). It finds a scripting engine that reached a paste or storage service and then, within 5 minutes, connected from the same process to a public IP with no host name.
- It misses compiled clients, follow-on connections to a domain, and a follow-on made by a child process. For those, use the Device timeline: from the resolver fetch, read the next few minutes for any connection by the client or its children to a host or IP that isn't part of the service. The investigation package's `DnsCache.txt` lists names the device resolved recently.
- `isempty(RemoteUrl)` is the query's test for a raw-IP connection. Microsoft doesn't document when `RemoteUrl` is empty, so an empty value may also be a host-name connection (VERIFY (tenant)).
- The follow-on host or IP is the real C2 address. Add it to the IOCs.

---

## Step 5 — trace the process chain

- The network event names the client's parent: `InitiatingProcessParentFileName`, `InitiatingProcessParentId`, `InitiatingProcessParentCreationTime`.
- Children and files: events on the device whose `InitiatingProcessId` and `InitiatingProcessCreationTime` both match the client's. PIDs are reused, so always match both. On Windows, `InitiatingProcessUniqueId` (the Process Start Key) identifies one process.
- Look for: how it started (Office app, browser, mail client, Explorer, scheduled task, service), what it started, which DLLs it loaded (`DeviceImageLoadEvents` with the client as the initiating process), and what it wrote.
- Parent-child patterns: [process guide](../02-suspicious-process/investigation.md).

---

## Step 6 — find what it downloaded or wrote

- `DeviceFileEvents` on the device from T0:
  - files whose `FileOriginUrl` or `FileOriginReferrerUrl` contains the service host
  - files written by the client (same `InitiatingProcessId` and `InitiatingProcessCreationTime`) in the minutes after the connection. Don't rely on `FileOriginUrl` alone.
- For each file record the path and SHA1. SHA256 is usually empty.
- Did it run? Use the hash sweep in the [malware investigation](../01-malware-alert/investigation.md#step-4--check-for-spread) and read `Tables`.
- PE files (`.exe`, `.dll`): Deep analysis on the file page reports behaviours, contacted IPs and files created.

---

## Step 7 — work out what was sent

- MDE doesn't record bytes sent. The exfiltration query counts connections, which shows how often, not how much. Ask the customer for proxy or firewall logs if volume matters.
- Treat it as possible exfiltration, whatever the volume, when a class C or D client connected to: a webhook service (Discord, Slack, webhook.site), the Telegram Bot API, Microsoft Graph, or a storage host outside the customer's tenant.
- SharePoint and OneDrive: compare the host name with the customer's own tenant host names. Ask the customer if unsure. A host for another tenant is external.
- Rclone: look for `rclone` in command lines, and for the storage services it supports.
- Infostealers: Microsoft documents Lumma Stealer extracting saved passwords, session cookies and autofill data from Chromium (including Edge), Mozilla and Gecko-based browsers, and using Telegram channels as fallback C2. If a stealer or unknown payload ran, or data may have left through a channel above: treat the browser-saved passwords and signed-in web sessions of every user on the device as exposed.

---

## Step 8 — first contact and spread

- **First contact:** rerun the query that hit with its first `between` line starting at `T0 - 30d` (the 30-day Advanced Hunting limit). The earliest row for the same process SHA1 or host on this device is the T0 candidate.
- **Other devices:** the three queries below have no device filter, so they already cover the estate; read `DeviceName`. Run the hash sweep for each SHA1 from Steps 1, 5 and 6.
- Spread is a reason to scope wider, never evidence that the activity is benign.
- **Delivery:** check email ([phishing email](../12-phishing-email/investigation.md)) and other vectors ([initial access](../10-initial-access/investigation.md)).

---

## Queries

**Limits. Read before trusting zero rows:**
- Process lists match file names only. A renamed or masquerading binary passes the exclusion lists, and compiled implants (class D) aren't in the include lists.
- Domain lists use `has`, which matches whole terms. `"dropbox.com"` doesn't match `dropboxapi.com`, `"s3.amazonaws.com"` doesn't match a regional bucket host, and `"gist.github.com"` doesn't match `gist.githubusercontent.com`.
- None of them lists `graph.microsoft.com`. For a class D client, use the Device timeline filtered to the process.
- None filters on `ActionType`, so failed and blocked attempts count as contacts (Step 2).
- For non-browser, non-script clients reaching Discord, Telegram, paste and file-share sites there is also [lots-suspicious-process-to-cloud.kql](../../../kql/network/lots-suspicious-process-to-cloud.kql). It looks back 24 hours from now, not from T0, so it returns nothing for an older incident.

**KQL — scripting engine to cloud/paste services:**
```kql
// LOTS — scripting engines reaching cloud storage and collaboration services
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1102
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

The header's "no legitimate reason" is too strong: admin scripts do reach these services. See Step 1.

**KQL — dead-drop resolver (paste GET then raw IP connection):**
```kql
// LOTS — dead-drop resolver detection
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1102.001
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

MDE records no HTTP method, so "GET" in the header means "connected to". Zero rows don't clear the device (Step 4).

**KQL — non-browser processes connecting to cloud storage (potential exfiltration; upload volume is not available in MDE and needs proxy/firewall logs):**
```kql
// LOTS — non-browser processes connecting to cloud storage (possible exfiltration)
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1567.002
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

The exclusions are file names only, so a binary named `onedrive.exe` in any folder is hidden. Check the folder and signer of every excluded client you rely on (Step 1).
