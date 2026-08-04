## lolbin-sweep.kql

**MITRE:** T1218 — System Binary Proxy Execution  
**Tables:** DeviceProcessEvents  
**Platform:** Defender XDR / Sentinel — native Defender Advanced Hunting uses `Timestamp` as the time column; this repo's queries use `TimeGenerated` to match the Sentinel Log Analytics schema (rename if pasting directly into the Defender portal)  
**Licence:** Microsoft Defender for Endpoint Plan 2 (bundled in Microsoft 365 E5)  
**When to use:** Run estate-wide as a daily hunt, or scoped to a specific device, to catch Living-Off-The-Land binary abuse — certutil, PowerShell, mshta, regsvr32, rundll32, wmic, or bitsadmin used for download, execution, or evasion.

```kql
// LOLBin abuse — master sweep across all known Living Off the Land binaries
// Covers: certutil, PowerShell, mshta, regsvr32, rundll32, wmic, bitsadmin
// Run estate-wide as a daily hunt or scope to a specific device
// Ref: docs/scenarios/07-lolbin-abuse/investigation.md

DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where (
    // certutil downloading or decoding
    (FileName =~ "certutil.exe"
        and ProcessCommandLine has_any("-urlcache", "-decode", "http"))
    // PowerShell suspicious flags
    or (FileName =~ "powershell.exe"
        and ProcessCommandLine has_any(
            "-enc", "-EncodedCommand", "IEX",
            "DownloadString", "-w hidden", "Reflection.Assembly"))
    // mshta — almost never legitimate in modern environments
    or (FileName =~ "mshta.exe"
        and ProcessCommandLine has_any("http", "vbscript:", "javascript:"))
    // regsvr32 remote scriptlet (Squiblydoo / AppLocker bypass)
    or (FileName =~ "regsvr32.exe"
        and ProcessCommandLine has_any("http", "scrobj.dll", "/i:"))
    // rundll32 credential dump or suspicious DLL
    or (FileName =~ "rundll32.exe"
        and ProcessCommandLine has_any("comsvcs", "MiniDump", "javascript:", "AppData", "Temp"))
    // wmic remote execution or shadow deletion
    or (FileName =~ "wmic.exe"
        and ProcessCommandLine has_any("process call create", "shadowcopy delete", "/node:"))
    // bitsadmin download or notification command
    or (FileName =~ "bitsadmin.exe"
        and ProcessCommandLine has_any("/transfer", "http", "SetNotifyCmdLine"))
)
| project TimeGenerated, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

### False positives
- SCCM/Intune deployment scripts using `certutil -decode` or PowerShell `-EncodedCommand` as part of legitimate software packaging. Confirm `InitiatingProcessFileName` is `ccmexec.exe` or `IntuneManagementExtension.exe`.
- IT admin scripts using `wmic.exe` for read-only inventory queries (`SELECT` statements only, no `process call create`). Confirm the query is read-only and no file write or remote execution follows.
- Legacy line-of-business applications that use `mshta.exe` as an HTA interface — confirm the HTA file is under `C:\Program Files\`, not `%TEMP%` or `%APPDATA%`.
- See [docs/reference/common-false-positives.md](../../docs/reference/common-false-positives.md#scripting--admin-tooling) for the full LOLBin false-positive reference.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

lolbin-sweep.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no LOLBin abuse pattern (certutil, PowerShell, mshta, regsvr32, rundll32, wmic, bitsadmin) detected
        [ ] Results found — see findings below

Findings:
  Device(s):
  Account(s):
  Binary / command line observed:
  Timeframe:
  Notes:

Conclusion:
  [ ] No suspicious activity identified — no LOLBin abuse identified in process command lines for the review window
  [ ] Suspicious activity identified — escalating
  [ ] False positive — reason:

─────────────────────────────────────────────────────────────
```
