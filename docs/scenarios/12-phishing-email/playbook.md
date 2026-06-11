# Phishing email — playbook

## Checklist

### Immediate
- [ ] Find the email in Threat Explorer
- [ ] Confirm delivery action — did it reach the inbox?
- [ ] Has ZAP fired? If yes — did it fire before or after the user opened it?
- [ ] Did the user click any links or open any attachments?

### Investigation
- [ ] All recipients found — how many people got it?
- [ ] Delivery action confirmed for each recipient
- [ ] Attachment investigated — SHA256 pulled, enriched on VirusTotal
- [ ] Attachment hash swept across estate — any devices?
- [ ] URLs in the email checked on URLScan.io
- [ ] URL click data checked — did anyone click through Safe Links?
- [ ] IsClickedThrough checked — did anyone bypass the Safe Links warning?
- [ ] Device activity checked in 30 min window after email delivery
- [ ] Any processes spawned on affected devices?

### Containment
- [ ] Sender blocked in Tenant Allow/Block List
- [ ] Malicious URL blocked in Tenant Allow/Block List
- [ ] Malicious file hash blocked in Tenant Allow/Block List
- [ ] Email soft deleted from all affected mailboxes
- [ ] Hard delete if required (Action center)

### Remediation
- [ ] Any devices that executed the payload — investigated via 01-malware-alert
- [ ] All recipients informed if payload was delivered
- [ ] Customer informed of scope

### Close out
- [ ] Sender, subject, attachment hash, and URLs documented
- [ ] Number of recipients and delivery actions documented
- [ ] Whether any user executed the payload documented
- [ ] Findings written up

---

## Phishing pattern quick reference

| Pattern | Key indicator | Action |
|---------|--------------|--------|
| Thread hijacking | Known sender, unexpected attachment mid-thread | Check sender mailbox for compromise |
| HTML smuggling | HTML attachment creating a download on open | Pull the ISO/ZIP hash, check devices |
| Quishing | QR code image, prompt to scan | Check mobile device activity if possible |
| Callback phishing | No links/attachments, phone number only | No technical IOCs — user interview needed |

---

## Escalate if

```
User executed the payload — hand off to 01-malware-alert
Large number of recipients received and opened the email
Sender is an internal compromised mailbox (BEC)
Credential harvest page was visited and form submitted
```
