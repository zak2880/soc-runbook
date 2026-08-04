## beacon-suspicion-score.kql

**MITRE:** T1071.001 — Application Layer Protocol: Web Protocols  
**Tables:** DeviceNetworkEvents  
**Platform:** Defender XDR / Sentinel — native Defender Advanced Hunting uses `Timestamp` as the time column; this repo's queries use `TimeGenerated` to match the Sentinel Log Analytics schema (rename if pasting directly into the Defender portal)  
**Licence:** Microsoft Defender for Endpoint Plan 2 (bundled in Microsoft 365 E5)  
**When to use:** Run as a daily hunt across the estate to surface the highest-confidence beacon candidates without having to eyeball three separate queries.

```kql
// C2 beaconing detection — combined suspicion score
// Combines connection count, after-hours activity, and single-port consistency
// Score >= 5 warrants investigation; tune threshold for your environment
// Run this daily as a hunt query
// Ref: docs/scenarios/08-c2-beaconing/investigation.md

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
    CountScore = case(
        TotalConns > 100, 4,
        TotalConns > 50,  3,
        TotalConns > 20,  2,
        1),
    NightScore = case(
        NightConns > 20, 3,
        NightConns > 5,  2,
        0),
    PortScore = iff(DistinctPorts == 1, 2, 0)
| extend SuspicionScore = CountScore + NightScore + PortScore
| where SuspicionScore >= 5
| project DeviceName, RemoteIP, RemoteUrl,
    TotalConns, NightConns, SuspicionScore, Processes
| order by SuspicionScore desc
```

### False positives
- Backup/sync software running overnight maintenance windows — inflates `NightConns` legitimately. Check the process against scheduled backup jobs.
- Single-purpose appliances or IoT devices that only ever talk to one vendor endpoint on one port — naturally scores high on `PortScore` and `CountScore`. Cross-reference `DeviceName` against your asset inventory for known appliances.
- Monitoring/telemetry agents with high-frequency, single-destination check-ins (APM tools, log shippers). Use [fn-is-known-good-beacon.kql](../functions/fn-is-known-good-beacon.kql) to pre-filter known-good software.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

beacon-suspicion-score.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no device/destination pair scored 5 or above on the combined beacon suspicion score
        [ ] Results found — see findings below

Findings:
  Device(s):
  Remote IP/URL:
  Suspicion score:
  Timeframe:
  Notes:

Conclusion:
  [ ] No suspicious activity identified — no high-confidence beacon candidates in today's estate-wide sweep
  [ ] Suspicious activity identified — escalating
  [ ] False positive — reason:

─────────────────────────────────────────────────────────────
```
