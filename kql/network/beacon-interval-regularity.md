## beacon-interval-regularity.kql

**MITRE:** T1071.001 — Application Layer Protocol: Web Protocols  
**Tables:** DeviceNetworkEvents  
**Platform:** Defender XDR / Sentinel — native Defender Advanced Hunting uses `Timestamp` as the time column; this repo's queries use `TimeGenerated` to match the Sentinel Log Analytics schema (rename if pasting directly into the Defender portal)  
**Licence:** Microsoft Defender for Endpoint Plan 2 (bundled in Microsoft 365 E5)  
**When to use:** A device is making repeated outbound connections to the same external destination and you want to know whether the timing is mechanical (beacon) or human-driven (browsing).

```kql
// C2 beaconing detection — interval regularity (catches jittered beacons)
// Calculates standard deviation of gaps between connections to the same destination
// Low StdDev relative to MeanInterval = mechanical timer = beaconing
// Regularity score: 95%+ = almost certainly beaconing, 70-90% = investigate
// Ref: docs/scenarios/08-c2-beaconing/investigation.md

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
    StdDev = round(stdev(IntervalSec), 1),
    MinGap = min(IntervalSec),
    MaxGap = max(IntervalSec)
    by DeviceName, RemoteIP, RemoteUrl
| where ConnCount > 20
| extend Regularity = round(
    (1 - (StdDev / MeanInterval)) * 100, 1)
| where Regularity > 70
| order by Regularity desc
```

### False positives
- RMM / EDR heartbeat traffic (ScreenConnect, NinjaOne, Datto, CrowdStrike) — regular by design. Check `RemoteUrl` resolves to the vendor's known infrastructure and the process is signed. Use [fn-is-known-good-beacon.kql](../functions/fn-is-known-good-beacon.kql) to filter these before triage.
- NTP / Windows Update / Teams presence pings — short, low-byte, fixed-interval traffic on well-known endpoints.
- Software update checkers polling on a fixed schedule (e.g. hourly cron-style checks) — confirm against the vendor's documented check-in interval.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

beacon-interval-regularity.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no device/destination pair showed regular-interval beaconing above the regularity threshold
        [ ] Results found — see findings below

Findings:
  Device(s):
  Remote IP/URL:
  Regularity score:
  Timeframe:
  Notes:

Conclusion:
  [ ] No suspicious activity identified — outbound connection timing for this device appears human-driven, no beaconing pattern identified
  [ ] Suspicious activity identified — escalating
  [ ] False positive — reason:

─────────────────────────────────────────────────────────────
```
