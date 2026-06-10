# C2 beaconing detection

## What is C2 beaconing?

Malware phones home to an attacker's server on a regular schedule — checking in for instructions or waiting for commands. A single connection looks normal. The **pattern over time** gives it away.

---

## The five signals

| Signal | Why it matters |
|--------|---------------|
| High connection count to one destination | Humans don't hit the same IP 500+ times a day — timers do |
| Low standard deviation of intervals | Mechanical timer = low variance. Human browsing = high variance |
| Uniform byte sizes | Fixed heartbeat packet. Real traffic has wildly varying sizes |
| After-hours traffic | Beacons don't sleep. Connections at 2–5am mean the user isn't driving them |
| Suspicious initiating process | svchost from AppData, random-named binary, scheduled task process |

---

## Cobalt Strike defaults — know these

| Property | Value |
|----------|-------|
| Sleep interval | **60 seconds** |
| Jitter | **0%** — perfectly regular |
| Port | 80 or 443 |
| User agent | `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1)` |

> IE7 user agent in 2025 = instant red flag. Nobody runs IE7.

---

## What it looks like in logs

### Classic Cobalt Strike — 60s, no jitter

```
02:00:00.000  185.220.101.45  443  312 bytes  svchost.exe (AppData\Temp)
02:01:00.001  185.220.101.45  443  312 bytes  svchost.exe (AppData\Temp)
02:02:00.002  185.220.101.45  443  312 bytes  svchost.exe (AppData\Temp)
... 1,440 identical rows across 24 hours ...
```

### Jittered beacon — 20% jitter, ~100s mean

```
09:14:03  91.108.56.12  gap: —
09:15:51  91.108.56.12  gap: +108s
09:17:29  91.108.56.12  gap: +97s
09:19:12  91.108.56.12  gap: +103s
09:22:41  91.108.56.12  gap: +103s
```

Looks random — but mean ~103s, tiny standard deviation. Human variance: 2s, 500s, 15s, 45s. The stdev query catches this.

### DNS beaconing

```
11:00:00  aGVsbG8.c2.attacker-domain.com
11:01:01  d29ybGQ.c2.attacker-domain.com
11:02:00  dGVzdA.c2.attacker-domain.com
```

Base64-encoded data in the subdomain. Tunnelling through DNS, which most firewalls don't inspect.

---

## False positives

| Software | Why it beacons | How to rule it out |
|----------|---------------|-------------------|
| OneDrive | Sync checkins | `onedrive.exe` → `*.sharepoint.com` |
| CrowdStrike / Defender | Heartbeat | Known sensor process → vendor IPs |
| Teams / Zoom | Presence | Known app → vendor CDN |
| Windows Time | NTP sync | `w32tm.exe` → Microsoft NTP |
| CRL / OCSP | Certificate checks | `svchost.exe` → Microsoft PKI |
| RMM agents | Device checkin | ConnectWise, Datto → known vendor endpoints |

**Three questions before escalating:**
1. Is the initiating process a known app from a standard install path?
2. Is the destination a known vendor domain registered years ago?
3. Does the same pattern appear on many other devices?

All three yes → likely false positive. Document and tune out.

---

## KQL queries

Standalone query files in [kql/network/](../kql/network/).

### High connection count
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

### Interval regularity (catches jittered beacons)
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType != "Private"
| sort by DeviceName, RemoteIP, Timestamp asc
| extend PrevTime = prev(Timestamp, 1)
| extend PrevDevice = prev(DeviceName, 1)
| extend PrevIP = prev(RemoteIP, 1)
| where DeviceName == PrevDevice and RemoteIP == PrevIP
| extend IntervalSec = datetime_diff('second', Timestamp, PrevTime)
| where IntervalSec between (5 .. 3600)
| summarize
    ConnCount = count(),
    MeanInterval = round(avg(IntervalSec), 1),
    StdDev = round(stdev(IntervalSec), 1)
    by DeviceName, RemoteIP, RemoteUrl
| where ConnCount > 20
| extend Regularity = round((1 - (StdDev / MeanInterval)) * 100, 1)
| where Regularity > 70
| order by Regularity desc
```

Regularity: 95%+ = almost certainly beaconing. 70–90% = investigate. Below 50% = likely legitimate.
