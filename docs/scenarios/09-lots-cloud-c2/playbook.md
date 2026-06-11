# LOTS & cloud C2 — playbook

## Checklist

### Immediate
- [ ] Identify the initiating process — is it a browser or a scripting engine?
- [ ] Identify the cloud service being contacted
- [ ] Note the full URL — does it look like a payload, config, or data?
- [ ] Is this a browser hit (likely FP) or a scripting engine hit (suspicious)?

### Investigation
- [ ] Initiating process confirmed — not a browser or legitimate cloud sync client?
- [ ] URL retrieved and scanned on URLScan.io
- [ ] Content of the URL checked — payload, IP address, encoded data?
- [ ] Dead-drop resolver pattern checked — paste GET followed by raw IP connection?
- [ ] Byte size checked — large outbound transfer = potential exfiltration?
- [ ] Process chain traced — what spawned the process contacting the cloud service?
- [ ] Any files downloaded from the cloud service identified and hashed?

### Context
- [ ] Is this the first time this process has contacted this service?
- [ ] Does the same pattern appear on other devices?
- [ ] Does the timing correlate with a phishing email or suspicious execution?

### Containment
- [ ] Device isolated if confirmed malicious activity
- [ ] URL/domain blocked in Tenant Allow/Block List if appropriate
- [ ] Note: blocking legitimate cloud services (OneDrive, GitHub) will impact business — confirm with customer first

### Remediation
- [ ] C2 implant or downloader identified and removed
- [ ] Any downloaded payloads removed
- [ ] Persistence removed if established
- [ ] Exfiltrated data scope assessed if large upload detected

### Close out
- [ ] Cloud service, URL, and initiating process documented
- [ ] Exfil volume documented if applicable
- [ ] Findings written up

---

## Escalate if

```
Scripting engine contacting Telegram API or Discord CDN
Dead-drop resolver pattern confirmed
Non-browser process uploading >5MB to cloud storage
Payload successfully downloaded and executed
```
