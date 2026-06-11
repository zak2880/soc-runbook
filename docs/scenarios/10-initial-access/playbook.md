# Initial access — playbook

## Checklist

### Immediate
- [ ] Identify T0 — timestamp of the first malicious event on the device
- [ ] Identify the delivery method — email / browser / RDP / other
- [ ] Is the attacker still active? If yes — contain first

### Investigation
- [ ] Device timeline reviewed — scrolled back to before the alert
- [ ] Files created just before execution checked
- [ ] Browser download history checked — any suspicious downloads?
- [ ] ISO/IMG delivery checked — mounted drive spawning processes?
- [ ] Email delivery checked — was there a phishing email? (see 12-phishing-email)
- [ ] Macro execution checked — Office app spawning shells?
- [ ] RDP access checked — brute force pattern or unusual logon?
- [ ] Credential-based access checked — valid account used from new location?

### Spread check
- [ ] Same attachment hash seen on other devices?
- [ ] Other users received the same phishing email?
- [ ] Same RDP source IP attempted access to other devices?

### Context
- [ ] Did the file have Mark of the Web (Protected View triggered)?
- [ ] If macro — did the user deliberately enable it? (check registry)
- [ ] If RDP — is RDP supposed to be exposed to the internet?

### Remediation
- [ ] Initial access vector closed:
  - Email: sender blocked, email purged from all mailboxes
  - Browser download: hash blocked, file removed
  - RDP: port closed or restricted to known IPs, brute-forced account password reset
  - ISO/IMG: file removed, delivery email blocked
- [ ] All other users who received same delivery investigated

### Close out
- [ ] T0 and delivery method documented
- [ ] Full delivery chain documented (e.g. email → user opened ISO → LNK → PowerShell)
- [ ] Other affected users/devices documented
- [ ] Findings written up

---

## Escalate if

```
RDP exposed to internet with successful brute force — check for persistence immediately
Valid account used from a new country — credential compromise
Multiple users received and executed the same phishing payload
```
