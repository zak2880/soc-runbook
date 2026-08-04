## dns-tunnelling.kql

**MITRE:** T1071.004 — Application Layer Protocol: DNS  
**Tables:** DeviceNetworkEvents  
**Platform:** Defender XDR / Sentinel — native Defender Advanced Hunting uses `Timestamp` as the time column; this repo's queries use `TimeGenerated` to match the Sentinel Log Analytics schema (rename if pasting directly into the Defender portal)  
**Licence:** Microsoft Defender for Endpoint Plan 2 (bundled in Microsoft 365 E5)  
**When to use:** You suspect data is being exfiltrated or C2 traffic is being tunnelled through DNS — e.g. a device shows a high volume of port-53 traffic to one domain with no corresponding web activity.

```kql
// DNS beaconing / tunnelling detection
// Hunts for DNS queries with base64-encoded subdomains — sign of DNS-based C2 or exfil
// High UniqueSubs + high QueryCount = data chunked and exfiltrated via DNS
// Ref: docs/scenarios/08-c2-beaconing/investigation.md, docs/scenarios/03-suspicious-network-activity/investigation.md

DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemotePort == 53
| extend Subdomain = tostring(split(RemoteUrl, ".")[0])
| where strlen(Subdomain) > 12
| where Subdomain matches regex @"^[A-Za-z0-9+/=_-]{12,}$"
| summarize
    QueryCount = count(),
    UniqueSubs = dcount(Subdomain),
    Samples = make_set(Subdomain, 5)
    by DeviceName, RemoteUrl, InitiatingProcessFileName
| where QueryCount > 5
| order by QueryCount desc
```

### False positives
- CDN and cloud-service subdomains that happen to be long alphanumeric strings (e.g. Azure/AWS resource GUIDs in hostnames) — check whether `RemoteUrl`'s parent domain is a known cloud provider.
- Security vendor telemetry that uses encoded subdomains for licensing/telemetry check-ins (some EDR/AV agents do this legitimately). Verify `InitiatingProcessFileName` against your security stack.
- Load-balanced or geo-routed services using randomised subdomain labels for cache-busting — usually low `QueryCount` per unique subdomain rather than one domain repeated many times.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

dns-tunnelling.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no base64-style encoded-subdomain DNS query pattern detected
        [ ] Results found — see findings below

Findings:
  Device(s):
  Domain queried:
  Query count / unique subdomains:
  Timeframe:
  Notes:

Conclusion:
  [ ] No suspicious activity identified — DNS query pattern for this device appears clean, no tunnelling indicators identified
  [ ] Suspicious activity identified — escalating
  [ ] False positive — reason:

─────────────────────────────────────────────────────────────
```
