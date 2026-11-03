# C2 beaconing — playbook

## Checklist

### Immediate
- [ ] Identify source device and initiating process
- [ ] Identify destination IP/domain and port
- [ ] Is the connection still active? This may be a live C2 session
- [ ] Run suspicion score query — what's the score?

### False positive check
- [ ] Close only if every condition in [Closing as a false positive](#closing-as-a-false-positive) holds

### Investigation (if not FP)
- [ ] Connection count checked — 30+ to same destination?
- [ ] Interval regularity checked — regularity score above 70%?
- [ ] Byte sizes checked — uniform sizes across connections? (not available in MDE; needs proxy/firewall logs)
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

## Closing as a false positive

Close only with a named, verifiable benign cause, and record it. A known app name, a standard install path, a long-established domain, a fixed interval, low volume, or "seen on many devices" is never enough: attacker-installed RMM tools, beacons injected into or side-loaded by signed programs, and C2 over cloud services or aged domains all pass those tests. Spread means scope wider. All of these must hold:

- The product is named, and the customer's asset list, approved-software list or a change record covers it on this device. For an RMM tool, its install time and installing account match that record.
- `DeviceFileCertificateInfo` for the beaconing process's SHA1 shows the vendor as `Signer` with `IsTrusted` true, and the process runs from the vendor's install folder.
- The process started no shells or recon commands. `DeviceImageLoadEvents` for it shows no DLL that isn't signed by the vendor or Microsoft. The device has no other alerts since T0.
- The destination is infrastructure the vendor documents for that product, and the Defender IP or URL/domain page shows no malicious verdict and no related alerts.

An authorised red team exercise or test with a ticket: classify as Informational, expected activity, not False positive. The IR lead confirms it.

Never close these yourself, even if a test is mentioned: shells or recon commands started by the beaconing process; a Cobalt Strike default named pipe; a reverse shell; a beacon inside a signed or Microsoft process; an RMM tool that isn't on the customer's approved list, or was installed outside a change record; credential access or lateral movement on the device. Escalate; the IR lead confirms any authorised test.

Don't add a suppression or exclusion to stop the alert. Request tuning from whoever owns the detection, with the evidence above.

If any condition can't be confirmed: don't close. Treat it as beaconing confirmed from a process that isn't a named, sanctioned product: contain and escalate.

---

## Escalate if

```
Live interactive C2 session confirmed
Cobalt Strike named pipe detected
Beacon present on multiple devices
C2 active alongside credential dumping or lateral movement
```
