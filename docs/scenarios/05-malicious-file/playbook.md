# Malicious file — playbook

## Checklist

### Immediate
- [ ] Pull the SHA256 of the file
- [ ] Note the full file path
- [ ] Note the process that created/executed it
- [ ] Check if the file is still present on disk

### Investigation
- [ ] Hash enriched on VirusTotal — detection ratio, first seen, malware family
- [ ] Hash checked on Defender XDR file page — tenant and global prevalence
- [ ] File path checked — is it in a suspicious location?
- [ ] File name checked — double extension, random name?
- [ ] Hash swept across estate — any other devices?
- [ ] File creation time correlated with infection timeline
- [ ] Files dropped by this file checked (relations tab on VT / Defender file page)
- [ ] VSS deletion checked — any sign of ransomware pre-cursor?
- [ ] Mass file renames checked

### Context
- [ ] Does the malware family explain the behaviour seen?
- [ ] Was the file delivered via email, browser download, or lateral movement?
- [ ] Has the file self-deleted after execution?

### Remediation
- [ ] File quarantined or deleted (Action Center or Live Response)
- [ ] Confirmed quarantine/deletion on all affected devices
- [ ] Hash blocked in Tenant Allow/Block List
- [ ] Any files dropped by this file also removed

### Close out
- [ ] SHA256, file path, malware family documented
- [ ] All affected devices confirmed clean
- [ ] Findings written up

---

## Escalate if

```
VSS deletion detected — ransomware imminent or running
Mass file renames in progress
File is a known credential dumper (Mimikatz, etc.)
Hash found on multiple devices
```
