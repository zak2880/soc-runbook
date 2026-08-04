## lsass-access-credential-dump.kql

**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory  
**Tables:** DeviceEvents  
**Platform:** Defender XDR / Sentinel — native Defender Advanced Hunting uses `Timestamp` as the time column; this repo's queries use `TimeGenerated` to match the Sentinel Log Analytics schema (rename if pasting directly into the Defender portal)  
**Licence:** Microsoft Defender for Endpoint Plan 2 (bundled in Microsoft 365 E5)  
**When to use:** A Defender alert or manual hunt flags process access to `lsass.exe`, or you're validating whether credential theft occurred on a device already known to be compromised.

```kql
// Identity — lsass.exe access (credential dumping signal)
// Any non-Windows process opening lsass = likely credential theft attempt
// Covers: Mimikatz-style direct access and comsvcs.dll MiniDump technique
// Replace HOSTNAME or remove filter to monitor estate-wide
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/reference/escalation-triggers.md

let target_device = "HOSTNAME";   // replace before running, or remove the filter below to monitor estate-wide
DeviceEvents
| where DeviceName == target_device
| where ActionType == "OpenProcessApiCall"
| where AdditionalFields has "lsass"
| where TimeGenerated > ago(24h)
| project TimeGenerated, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AdditionalFields
```

### False positives
- AV/EDR vendors legitimately inspect LSASS for credential protection (CrowdStrike, SentinelOne, Carbon Black, Defender itself). Confirm `InitiatingProcessVersionInfoCompanyName` matches a known security vendor, the binary is signed, and it's running from the vendor's install directory.
- Backup software taking a system-state backup, or the Defender for Identity sensor. Confirm the parent process is `VeeamAgent.exe`, `Acronis*.exe`, or `Microsoft.Tri.Sensor.exe` and activity falls within a scheduled backup window.
- See [docs/reference/common-false-positives.md](../../docs/reference/common-false-positives.md#credential-access) for the full list and how to confirm each.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

lsass-access-credential-dump.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no lsass access by non-Windows processes detected — no credential dumping indicators
        [ ] Results found — see findings below

Findings:
  Account(s):
  IP address(es):
  Location(s):
  Timeframe:
  Notes:

Conclusion:
  [ ] No suspicious activity identified — lsass.exe access on this device appears clean, no credential dumping indicators identified
  [ ] Suspicious activity identified — escalating
  [ ] False positive — reason:

─────────────────────────────────────────────────────────────
```
