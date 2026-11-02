# LOLBin abuse — playbook

## Checklist

### Immediate
- [ ] Identify which LOLBin was abused and what it was doing
- [ ] Pull the full command line
- [ ] Identify the parent process — what spawned the LOLBin?
- [ ] Is the LOLBin still running? If yes — terminate

### Investigation
- [ ] Command line analysed — downloading, decoding, executing, or credential dumping?
- [ ] Parent-child chain traced — was it spawned by an Office app?
- [ ] Network connections from this binary checked
- [ ] Files created by this binary checked
- [ ] rundll32 + comsvcs + MiniDump checked — credential dump?
- [ ] wmic shadowcopy delete checked — ransomware pre-cursor?
- [ ] Any payload downloaded — hash enriched?

### Context
- [ ] Is this LOLBin normally used on this device/in this environment?
- [ ] Has the same command been seen on other devices?
- [ ] Does this fit a known malware family's TTP?

### Remediation
- [ ] Process terminated if still running
- [ ] Any downloaded/decoded payload removed
- [ ] Persistence removed if established
- [ ] lsass dump file removed if credential dump was attempted

### Close out
- [ ] LOLBin technique documented with full command line
- [ ] MITRE technique ID noted (mshta, regsvr32, rundll32: T1218.005 / .010 / .011 System Binary Proxy Execution; certutil: T1105 / T1140; wmic: T1047; bitsadmin: T1197; see [MITRE-mapping.md](../../../MITRE-mapping.md))
- [ ] Findings written up

---

## Escalate if

```
rundll32.exe comsvcs.dll MiniDump — credential dump
wmic shadowcopy delete — ransomware indicator
certutil or bitsadmin downloading from external IP
mshta spawned by Office app — phishing delivery confirmed
```
