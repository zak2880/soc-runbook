## beacon-suspicion-score.kql

**MITRE:** T1071.001 — Application Layer Protocol: Web Protocols  
**Tables:** DeviceNetworkEvents  
**Platform:** Microsoft Defender XDR Advanced Hunting (native). Time column is `Timestamp`. See [docs/reference/sentinel-vs-advanced-hunting.md](../../../docs/reference/sentinel-vs-advanced-hunting.md) for the Sentinel equivalent (`TimeGenerated`), at [kql/sentinel/network/beacon-suspicion-score.md](../../sentinel/network/beacon-suspicion-score.md)  
**Licence:** Microsoft Defender for Endpoint Plan 2 (bundled in Microsoft 365 E5)  
**When to use:** Run as a daily hunt across the estate to surface the highest-confidence beacon candidates without having to eyeball three separate queries.

### Why this query

A beacon that's been tuned to avoid any single tell — moderate connection count, some jitter, mixed hours — can slip past a query that only checks one signal. This query exists because the five beaconing signals in the C2 guide (connection count, interval regularity, byte size, after-hours activity, suspicious process) are meant to be considered together, and most analysts don't have time to run and cross-reference three separate queries every day. It combines connection volume, after-hours activity, and port consistency into one score so a candidate that's moderately suspicious on two axes surfaces even if it wouldn't clear either threshold alone.

The score bands (CountScore 1–4, NightScore 0–3, PortScore 0–2, summed to a `SuspicionScore >= 5` cutoff) are a deliberately rough heuristic, not a statistically derived model — they were set so that a beacon needs to combine at least a moderate connection count with either heavy after-hours activity or single-port consistency to clear the bar. Honestly: this threshold needs tuning for your environment. An estate with a lot of overnight batch jobs will push `NightScore` up across many benign devices; an estate with heavily locked-down egress (single allowed port for everything) will do the same to `PortScore`. Watch what clears 5 in your first week of runs and adjust.

**What this won't catch:** A beacon that stays entirely within business hours, keeps connection count low (under the `TotalConns > 20` floor for any `CountScore`), and rotates across several destination ports defeats all three components at once — none of the individual scores will be high enough to reach 5. This is a coarse daily triage net, not a precision instrument; anything that scores just under 5 is still worth a manual look if the destination or process looks wrong for other reasons. Pair with `beacon-interval-regularity.kql` for timing-based detection that doesn't depend on volume or hours at all.

```kql
// Platform: Microsoft Defender XDR Advanced Hunting
// C2 beaconing detection — combined suspicion score
// Combines connection count, after-hours activity, and single-port consistency
// Score >= 5 warrants investigation; tune threshold for your environment
// Run this daily as a hunt query
// Ref: docs/scenarios/08-c2-beaconing/investigation.md

DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType != "Private"
| where RemoteIP != ""
| summarize
    TotalConns = count(),
    NightConns = countif(hourofday(Timestamp) between (0 .. 6)),
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
