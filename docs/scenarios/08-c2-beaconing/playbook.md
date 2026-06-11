# C2 beaconing — playbook

## Checklist

### Immediate
- [ ] Identify source device and initiating process
- [ ] Identify destination IP/domain and port
- [ ] Is the connection still active? This may be a live C2 session
- [ ] Run suspicion score query — what's the score?

### False positive check (do this before isolating)
- [ ] Is the initiating process a known app from a standard install path?
- [ ] Is the destination a known vendor domain (Microsoft, CrowdStrike, Zoom, etc.)?
- [ ] Does the same pattern appear on many other devices?
- [ ] If all three yes → likely FP, document and tune out

### Investigation (if not FP)
- [ ] Connection count checked — 30+ to same destination?
- [ ] Interval regularity checked — regularity score above 70%?
- [ ] Byte sizes checked — uniform sizes across connections?
- [ ] After-hours connections checked — active between 1–5am?
- [ ] Destination enriched — VirusTotal, AbuseIPDB, domain age, Shodan
- [ ] IE7 user agent checked — instant Cobalt Strike indicator
- [ ] DNS tunnelling checked — base64 subdomains?
- [ ] Process chain checked — what spawned the beaconing process?

### Containment
- [ ] Device isolated if live C2 confirmed
- [ ] Destination IP/domain blocked in Tenant Allow/Block List
- [ ] Customer notified

### Remediation
- [ ] C2 implant identified and removed
- [ ] Persistence removed
- [ ] All affected devices checked for same implant

### Close out
- [ ] C2 IP/domain/port documented
- [ ] Regularity score and connection count documented
- [ ] Malware family identified if possible
- [ ] Findings written up

---

## Escalate if

```
Live interactive C2 session confirmed
Cobalt Strike named pipe detected
Beacon present on multiple devices
C2 active alongside credential dumping or lateral movement
```
