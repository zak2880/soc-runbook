# C2 beaconing — investigation

## What is C2 beaconing?

Malware phones home on a regular schedule — checking in for instructions or waiting for commands. A single connection looks normal. The **pattern over time** gives it away.

---

## The five signals

| Signal | Why it matters |
|--------|---------------|
| High connection count to one destination | Timers hit the same IP hundreds of times — humans don't |
| Low standard deviation of intervals | Mechanical timer = low variance. Human browsing = chaotic variance |
| Uniform byte sizes | Fixed heartbeat packet — real traffic has wildly varying sizes (not available in MDE; needs proxy/firewall logs) |
| After-hours traffic | Beacons don't sleep — connections at 2–5am mean the user isn't driving them |
| Suspicious initiating process | svchost from AppData, random binary, scheduled task process |

---

## Cobalt Strike defaults

| Property | Value |
|----------|-------|
| Sleep interval | 60 seconds |
| Jitter | 0% — perfectly regular |
| Port | 80 or 443 |
| User agent | `Mozilla/4.0 (IE 7.0; Win32)` — nobody runs IE7 |

---

## Log examples

**Classic 60s beacon:**
```
02:00:00  185.220.101.45  443  312 bytes  svchost.exe (AppData\Temp)
02:01:00  185.220.101.45  443  312 bytes  svchost.exe (AppData\Temp)
02:02:00  185.220.101.45  443  312 bytes  svchost.exe (AppData\Temp)
```
Byte counts in this example come from proxy/firewall logs; they are not available in MDE.

**Jittered beacon (~100s mean, 20% jitter):**
```
09:14:03  91.108.56.12  gap: —
09:15:51  91.108.56.12  gap: +108s
09:17:29  91.108.56.12  gap: +97s
09:19:12  91.108.56.12  gap: +103s
```
Looks random — but tiny standard deviation. The regularity KQL catches this.

---

## KQL queries

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

### Interval regularity
```kql
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteIPType != "Private"
| sort by DeviceName, RemoteIP, TimeGenerated asc
| extend PrevTime = prev(TimeGenerated, 1)
| extend PrevDevice = prev(DeviceName, 1)
| extend PrevIP = prev(RemoteIP, 1)
| where DeviceName == PrevDevice and RemoteIP == PrevIP
| extend IntervalSec = datetime_diff('second', TimeGenerated, PrevTime)
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

Regularity: **95%+** = almost certainly beaconing. **70–90%** = investigate. **Below 50%** = likely legitimate.

### Combined suspicion score
```kql
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteIPType != "Private"
| where RemoteIP != ""
| summarize
    TotalConns = count(),
    NightConns = countif(hourofday(TimeGenerated) between (0 .. 6)),
    DistinctPorts = dcount(RemotePort),
    Processes = make_set(InitiatingProcessFileName, 3)
    by DeviceName, RemoteIP, RemoteUrl
| extend
    CountScore = case(TotalConns > 100, 4, TotalConns > 50, 3, TotalConns > 20, 2, 1),
    NightScore = case(NightConns > 20, 3, NightConns > 5, 2, 0),
    PortScore = iff(DistinctPorts == 1, 2, 0)
| extend SuspicionScore = CountScore + NightScore + PortScore
| where SuspicionScore >= 5
| project DeviceName, RemoteIP, RemoteUrl,
    TotalConns, NightConns, SuspicionScore, Processes
| order by SuspicionScore desc
```

---

## False positives

Check these before escalating: OneDrive, CrowdStrike/Defender agents, Teams/Zoom, Windows Time (NTP), CRL/OCSP checks, RMM agents.

Three questions: Is the process a known app from a standard path? Is the destination a known vendor domain registered years ago? Does the same pattern appear on many other devices? All yes → likely FP.
