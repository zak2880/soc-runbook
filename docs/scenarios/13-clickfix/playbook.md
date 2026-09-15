# ClickFix — playbook

## Checklist

### Immediate
- [ ] Identify the LOLBin that ran (`powershell.exe`, `mshta.exe`, `cmd.exe`) and its full command line
- [ ] Confirm the parent process — `explorer.exe` (Run dialog) or a browser?
- [ ] Isolate the device
- [ ] Do not wait on AV verdict before isolating — this technique is designed to look clean to AV

### Investigation
- [ ] Full process tree pulled around the timestamp — what did the LOLBin spawn afterward?
- [ ] Network callout confirmed — did the LOLBin actually reach the staging/C2 URL?
- [ ] Same domain/IOC hunted tenant-wide across process, network, URL-click, and email-URL telemetry
- [ ] Dropped files checked in Temp/AppData/ProgramData
- [ ] Persistence checked — scheduled tasks, Run keys
- [ ] Sign-in logs checked for the affected user — any sign of credential harvest on the same lure page?
- [ ] If the lure site is a compromised legitimate site rather than phishing — checked for the EtherHiding variant (RPC endpoint callout, not a domain)

### Context
- [ ] How did the user land on the page — search result, malvertising, compromised legitimate site, or a phishing link?
- [ ] Has the same domain/lure been seen on other devices?
- [ ] Is there a documented, IT-approved reason this user would be pasting a command into Run/PowerShell? (see [common false positives](../../reference/common-false-positives.md))

### Containment
- [ ] Device isolated
- [ ] Account disabled or suspended if credential harvest can't be ruled out
- [ ] Malicious domain / RPC host + contract address blocked and submitted to the TI watchlist

### Remediation
- [ ] Credentials reset for any account active on the device at the time
- [ ] Sessions / refresh tokens revoked for that account
- [ ] Device reimaged if unauthorized code execution is confirmed
- [ ] IOCs (domain, staging URL, and for EtherHiding: RPC host + contract address) submitted to the TI watchlist

### Close out
- [ ] Full delivery chain documented (e.g. search result → compromised site → fake CAPTCHA → user pasted into Run → PowerShell → payload)
- [ ] Whether credential harvest occurred documented
- [ ] Whether this was a standard domain-based lure or an EtherHiding variant documented
- [ ] Other affected users/devices documented
- [ ] Findings written up

---

## Escalate if

```
Network callout confirmed to the staging/C2 URL — payload likely delivered
Same lure/domain confirmed on more than one device
Credential harvest suspected on the same lure page
EtherHiding variant confirmed — flag for TI, standard domain blocklists won't catch it
Persistence established (scheduled task, Run key) following the paste
```
