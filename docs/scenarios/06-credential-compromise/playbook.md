# Credential compromise — playbook

## Checklist

### Immediate
- [ ] Identify the affected account(s)
- [ ] Is lsass being actively accessed? If yes — escalate now
- [ ] Has the account been used on other devices since T0?
- [ ] Disable the compromised account if active lateral movement confirmed

### Investigation
- [ ] lsass access checked — any non-Windows process?
- [ ] comsvcs.dll MiniDump checked
- [ ] SAM / NTDS.dit access checked
- [ ] Mimikatz / credential dumping keywords checked in process events
- [ ] Compromised account checked across all devices post-T0
- [ ] Entra ID sign-in log checked — new locations, impossible travel
- [ ] MFA logs checked — fatigue attack attempted?
- [ ] Legacy auth sign-ins checked
- [ ] New local accounts checked — any backdoor accounts created?
- [ ] Privilege escalation checked — account added to admin groups?

### Containment
- [ ] Compromised account password reset
- [ ] Active sessions terminated
- [ ] MFA re-registered if MFA fatigue succeeded
- [ ] Legacy auth blocked for the account if not already
- [ ] Any backdoor accounts removed

### Remediation
- [ ] All devices the account accessed post-T0 investigated
- [ ] Lateral movement paths closed (patch RDP if exposed, disable WMI remotely if not needed)
- [ ] Confirmed no persistent access remains

### Close out
- [ ] Scope of compromise documented — which accounts, which devices
- [ ] Timeline of lateral movement documented
- [ ] Customer informed — password resets, MFA review
- [ ] Findings written up

---

## Escalate if

```
lsass dump confirmed — credentials are likely compromised
NTDS.dit accessed — all domain credentials potentially exposed
Lateral movement confirmed — more than one device affected
DCSync detected — attacker replicating domain credentials
```
