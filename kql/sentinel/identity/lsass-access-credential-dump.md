## lsass-access-credential-dump.kql

**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory  
**Tables:** DeviceEvents  
**Platform:** Microsoft Sentinel — via the Microsoft Defender XDR data connector. Time column is `TimeGenerated`. See [kql/xdr/identity/lsass-access-credential-dump.md](../../xdr/identity/lsass-access-credential-dump.md) for the XDR version  
**Licence:** Microsoft Defender for Endpoint Plan 2 (bundled in Microsoft 365 E5)  
**When to use:** A Defender alert or manual hunt flags process access to `lsass.exe`, or you're validating whether credential theft occurred on a device already known to be compromised.

### Why this query

`lsass.exe` holds credential material — cached passwords, NTLM hashes, Kerberos tickets — in memory for the lifetime of a logon session. Mimikatz and similar tools work by opening a handle to that process and reading its memory directly (the `sekurlsa::` module family), or by triggering Windows' own crash-dump machinery against it via `comsvcs.dll`'s `MiniDump` export, which writes lsass's memory out to a file an attacker can parse offline. Both techniques require the same first step this query watches for: a process calling `OpenProcess` against lsass.

There's no statistical threshold here because this isn't a volume-based detection — it's a binary one. Windows processes that legitimately need to touch lsass are a short, well-known list (other system processes, EDR/AV agents doing credential protection). Anything outside that list opening a handle to lsass has essentially no benign explanation, which is why the credential-compromise guide treats any hit here as grounds for immediate escalation rather than something to trend or threshold.

**What this won't catch:** Techniques that dump credentials without ever calling `OpenProcess` on lsass.exe directly evade this entirely — a full memory or kernel-level dump, or a driver-based technique that reads process memory through a different API path, won't generate the `OpenProcessApiCall` event this query filters on. A renamed or repackaged dumping tool with a forged `CompanyName` field in its version info could also pass a lazy manual review of the false-positive checklist, so don't stop at "the vendor name looks right" — check the actual signing certificate and file path. This query also depends on `DeviceEvents` telemetry being intact; some third-party AV/EDR agents interfere with or suppress the very API hooking this detection relies on.

```kql
// Platform: Microsoft Sentinel
// Identity — lsass.exe access (credential dumping signal)
// Any non-Windows process opening lsass = likely credential theft attempt
// Covers: Mimikatz-style direct access and comsvcs.dll MiniDump technique
// Replace HOSTNAME or remove filter to monitor estate-wide
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/reference/escalation-triggers.md

let target_device = "HOSTNAME";   // replace before running, or remove the filter below to monitor estate-wide
let lookback = 24h;
DeviceEvents
| where DeviceName == target_device
| where ActionType == "OpenProcessApiCall"
| where AdditionalFields has "lsass"
| where TimeGenerated > ago(lookback)
| project TimeGenerated, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AdditionalFields
```

### False positives
- AV/EDR vendors legitimately inspect LSASS for credential protection (CrowdStrike, SentinelOne, Carbon Black, Defender itself). Confirm `InitiatingProcessVersionInfoCompanyName` matches a known security vendor, the binary is signed, and it's running from the vendor's install directory.
- Backup software taking a system-state backup, or the Defender for Identity sensor. Confirm the parent process is `VeeamAgent.exe`, `Acronis*.exe`, or `Microsoft.Tri.Sensor.exe` and activity falls within a scheduled backup window.
- See [docs/reference/common-false-positives.md](../../../docs/reference/common-false-positives.md#credential-access) for the full list and how to confirm each.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

lsass-access-credential-dump.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no lsass access by non-Windows processes detected — no credential dumping indicators
        [ ] Results found — see findings below

Findings:
  Device(s):
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
