# Suspicious network activity — playbook

## Checklist

### Immediate
- [ ] Identify the source device and initiating process
- [ ] Identify the destination — IP, domain, port
- [ ] Is the connection still active? Check if this is live C2
- [ ] Is the initiating process legitimate for this device?

### Investigation
- [ ] Connection count to destination checked — is it beaconing?
- [ ] Interval regularity checked — low stdev = timer = beacon
- [ ] Byte sizes checked — uniform sizes = heartbeat packet
- [ ] After-hours connections checked
- [ ] Destination enriched — VirusTotal, AbuseIPDB, domain age
- [ ] DNS queries checked — any base64-looking subdomains?
- [ ] LOTS checked — scripting engine reaching cloud services?
- [ ] Internal scanning checked — probing internal IPs on admin ports?
- [ ] Unusual ports checked — 4444, 50050, 1337, 8080, 8443?

### Context
- [ ] Is the initiating process expected to make network calls?
- [ ] Is the destination a known vendor domain or CDN?
- [ ] Does the same pattern appear on other devices? (FP check)

### Remediation
- [ ] Device isolated if live C2 confirmed
- [ ] IOCs (IP, domain) blocked in Tenant Allow/Block List
- [ ] Malicious process terminated
- [ ] Persistence removed if established

### Close out
- [ ] Confirmed true positive or false positive
- [ ] IOCs documented and blocked
- [ ] Findings written up

---

## False positive check — ask these first

1. Is the initiating process a known installed app from a standard path?
2. Is the destination a known vendor domain registered years ago?
3. Does the same pattern appear on many other devices?

All three yes → likely false positive. Document and tune out.

---

## Escalate if

```
Confirmed live C2 session (interactive response)
Cobalt Strike named pipe detected
Internal scanning on ports 445/3389/5985 across multiple hosts
Large outbound transfer (potential exfiltration)
```
