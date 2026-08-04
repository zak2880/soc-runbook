## dns-tunnelling.kql

**MITRE:** T1071.004 — Application Layer Protocol: DNS  
**Tables:** DeviceNetworkEvents  
**Platform:** Defender XDR / Sentinel — native Defender Advanced Hunting uses `Timestamp` as the time column; this repo's queries use `TimeGenerated` to match the Sentinel Log Analytics schema (rename if pasting directly into the Defender portal)  
**Licence:** Microsoft Defender for Endpoint Plan 2 (bundled in Microsoft 365 E5)  
**When to use:** You suspect data is being exfiltrated or C2 traffic is being tunnelled through DNS — e.g. a device shows a high volume of port-53 traffic to one domain with no corresponding web activity.

### Why this query

DNS is one of the few outbound protocols almost never blocked, even in tightly locked-down environments — every device needs it to resolve hostnames, so egress filtering rarely touches port 53. That makes it an attractive channel for both C2 tasking and data exfiltration: the attacker chunks data (or commands) into the subdomain label of a DNS query, and the resolution chain carries it out through the firewall disguised as ordinary lookup traffic. A normal query changes on every request because it's for a different real hostname; a tunnelling query changes on every request because the payload changes, but the parent domain stays fixed.

The two filters — subdomain length over 12 characters, and a regex restricted to the base64 character set — are chosen to separate "unusually long but real" hostnames (CDN resource IDs, some SaaS tenant subdomains) from "structured, high-entropy" ones. Real hostnames are rarely a clean, dense base64-charset string; encoded payloads are, because that's what encoding produces. `QueryCount > 5` filters out the one-off long hostname that just happens to look encoded.

**What this won't catch:** A tool that keeps each individual subdomain label short — deliberately staying under the 12-character floor by chunking data into more, smaller queries — evades the length filter entirely, even though the aggregate exfiltrated volume could be the same or higher. Encoding schemes outside the base64 character set (hex, custom alphabets) also won't match the regex as written. And a patient exfiltration that spreads queries out to stay under `QueryCount > 5` inside the 24h window will slip through — if you suspect slow DNS exfiltration, lower the threshold and widen the lookback rather than trusting the defaults here.

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
