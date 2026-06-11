# Defence evasion — playbook

## Checklist

### Immediate
- [ ] Identify which evasion technique was used
- [ ] Is security tooling still functioning? Check Defender status on the device
- [ ] Have event logs been cleared? If yes — escalate, attacker is covering tracks

### Investigation
- [ ] AMSI bypass checked — AmsiUtils / amsiInitFailed in PowerShell command lines
- [ ] UAC bypass checked — fodhelper, eventvwr, computerdefaults spawning children
- [ ] UAC bypass registry keys checked
- [ ] Defender disabled via registry checked
- [ ] EDR process killed via taskkill checked
- [ ] Event logs cleared checked — wevtutil cl
- [ ] Process injection checked — legitimate processes making unexpected network calls
- [ ] Timestomping checked — files with suspiciously old dates in temp paths
- [ ] ADS execution checked — colon notation in process command lines

### Context
- [ ] Which evasion technique(s) were used — multiple techniques = skilled operator
- [ ] Was evasion used before or after initial execution?
- [ ] Has the EDR lost visibility on any processes after evasion?

### Remediation
- [ ] Security tooling re-enabled if disabled
- [ ] UAC bypass registry keys removed
- [ ] Injected process killed if identified
- [ ] Any other artefacts from evasion technique removed

### Close out
- [ ] Evasion techniques documented with MITRE IDs
- [ ] Any gaps in telemetry noted (ETW patching, log clearing)
- [ ] Findings written up

---

## Escalate if

```
Event logs cleared — attacker actively covering tracks
Defender or EDR disabled or killed
AMSI bypass followed by credential dumping or C2
Process injection confirmed in a critical system process
```
