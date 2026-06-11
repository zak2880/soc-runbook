# Persistence detected — playbook

## Checklist

### Immediate
- [ ] Identify the persistence mechanism type (run key / task / service / startup / WMI)
- [ ] Identify what binary or script it points to
- [ ] Note when it was created — correlate with infection timeline
- [ ] Is the malware currently running via this mechanism?

### Investigation
- [ ] Registry Run keys checked around infection time
- [ ] Scheduled tasks checked — name, action, creation time, creating process
- [ ] New services checked — binary path, service name, creating process
- [ ] Startup folders checked for dropped files
- [ ] WMI subscriptions checked
- [ ] Binary/script the persistence points to — hash pulled and enriched
- [ ] Any additional persistence mechanisms (check all five types)

### Context
- [ ] Does the persistence mechanism match the malware family behaviour?
- [ ] Was the persistence created before or after the initial alert?
- [ ] Has the same persistence been created on other devices?

### Remediation
- [ ] Persistence mechanism removed:
  - Registry key deleted
  - Scheduled task deleted
  - Service stopped and deleted
  - Startup folder file removed
  - WMI subscription removed
- [ ] Binary/script the persistence pointed to removed
- [ ] Device rebooted and checked for re-emergence
- [ ] Confirmed clean after reboot

### Close out
- [ ] All persistence mechanisms documented
- [ ] Confirmed none remain after remediation
- [ ] Findings written up

---

## Escalate if

```
WMI persistence — indicates advanced attacker
Persistence created by a SYSTEM-level process
Same persistence across multiple devices
Persistence pointing to a credential dumper or C2 stager
```
