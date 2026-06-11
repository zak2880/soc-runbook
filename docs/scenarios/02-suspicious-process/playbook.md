# Suspicious process — playbook

## Checklist

### Immediate
- [ ] Identify the suspicious process — name, full path, PID
- [ ] Identify the parent process — does the relationship make sense?
- [ ] Note the full command line — any encoded flags, URLs, or suspicious arguments?
- [ ] Is the process still running? If yes — consider isolating the device

### Investigation
- [ ] Full process chain traced from parent to child to grandchild
- [ ] Command line checked for: `-enc`, `IEX`, `DownloadString`, `-w hidden`
- [ ] File path checked — is the binary in a legitimate location?
- [ ] Process name checked against expected path (spoofing check)
- [ ] LOLBin abuse checked — certutil, mshta, regsvr32, rundll32, wmic, bitsadmin
- [ ] Network connections from this process checked
- [ ] Files created by this process checked
- [ ] Registry modifications by this process checked

### Context
- [ ] Is this process expected on this device / for this user's role?
- [ ] Has this process been seen on other devices?
- [ ] Does the parent-child relationship have a legitimate explanation?

### Remediation
- [ ] Process killed if still running (Live Response or Action Center)
- [ ] Associated files removed
- [ ] Persistence mechanisms removed if created
- [ ] Device isolated if broader compromise confirmed

### Close out
- [ ] Confirmed true positive or false positive
- [ ] IOCs documented
- [ ] Findings written up

---

## Key red flags — escalate if present

```
Office app spawning PowerShell, cmd, mshta, or wscript
rundll32.exe comsvcs.dll MiniDump — credential dump
PowerShell with -nop -w hidden -enc
Any process from AppData/Temp making network connections
```
