# Persistence detected — investigation

## Why this matters

If you remediate without finding and removing persistence, the malware comes back after reboot. Always check for persistence before closing any malware incident.

---

## Registry run keys

Most common persistence method. Malware adds an entry to execute on every login.

**Key locations:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
```

**Red flags:** Path in `AppData\Temp`, `ProgramData`, `Public` — random alphanumeric binary name — entry mimicking a legitimate name but pointing to a temp path

---

## Scheduled tasks

**Red flags:** Random/meaningless task name — action points to `Temp` or `AppData` — uses PowerShell `-enc` — created around infection time — created by a non-standard process

```
schtasks.exe /create /sc minute /mo 5 /tn "WindowsUpdate" /tr "powershell.exe -enc JABj..."
```

---

## Malicious services

**Red flags:** Created recently with no matching software install — binary in `Temp` or `AppData` — service name mimics a legitimate one — created by unexpected process

---

## Startup folders

Anything here runs on every login:
```
C:\Users\[user]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
```

---

## WMI subscriptions

Advanced persistence — registers a WMI event that fires on a condition. Doesn't appear in normal startup tools.

Three parts: **EventFilter** (trigger) → **EventConsumer** (action) → **FilterToConsumerBinding** (links them)

---

## KQL queries

### Registry run key modifications
```kql
// Persistence — registry Run key modifications
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1547.001, T1547.004
// Covers HKCU and HKLM Run, RunOnce, and Winlogon keys
// Any modification around the time of a malware alert warrants investigation
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// Remove the device filter to hunt estate-wide
// Window: T0-14d to T0+2d. Advanced Hunting holds 30 days of native data; older needs Sentinel retention
// Ref: docs/scenarios/04-persistence-detected/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceRegistryEvents
| where DeviceName startswith "HOSTNAME"
| where RegistryKey has_any (
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce",
    "Winlogon")
| where Timestamp between ((T0 - 14d) .. (T0 + 2d))
| project Timestamp, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName
```

### Scheduled task creation
```kql
// Persistence — scheduled task creation via schtasks.exe
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1053.005
// Malware frequently creates scheduled tasks to re-execute the payload on reboot or login
// Look for: random task names, Temp/AppData paths, PowerShell -enc in the action
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// Window: T0-14d to T0+2d. Advanced Hunting holds 30 days of native data; older needs Sentinel retention
// Ref: docs/scenarios/04-persistence-detected/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where DeviceName startswith "HOSTNAME"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where Timestamp between ((T0 - 14d) .. (T0 + 2d))
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName
```

### New services installed
```kql
// Persistence — new Windows services installed
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1543.003
// Malware can install itself as a service for persistence and SYSTEM-level execution
// Look for: unusual binary paths, non-standard service names, creation by unexpected processes
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// Window: T0-14d to T0+2d. Advanced Hunting holds 30 days of native data; older needs Sentinel retention
// VERIFY: ServiceInstalled may depend on the "Audit Security System Extension" policy (event 4697);
// devices with zero rows here may lack it:
// DeviceEvents | where Timestamp > ago(30d) | where ActionType == "ServiceInstalled" | summarize count() by DeviceName
// Ref: docs/scenarios/04-persistence-detected/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceEvents
| where DeviceName startswith "HOSTNAME"
| where ActionType == "ServiceInstalled"
| where Timestamp between ((T0 - 14d) .. (T0 + 2d))
| project Timestamp, FileName, FolderPath, AdditionalFields
```

### WMI subscription creation
```kql
// Persistence — WMI event subscription creation
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1546.003
// Advanced persistence technique: malware registers WMI events that fire on system conditions
// Does not appear in normal startup tools — requires specific hunting
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// Window: T0-14d to T0+2d. Advanced Hunting holds 30 days of native data; older needs Sentinel retention
// VERIFY: these ActionType names are not on Microsoft Learn; community queries use
// WmiBindEventFilterToConsumer. Check what the tenant emits before relying on an empty result:
// DeviceEvents | where Timestamp > ago(30d) | where ActionType startswith "Wmi" | distinct ActionType
// Ref: docs/scenarios/04-persistence-detected/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceEvents
| where DeviceName startswith "HOSTNAME"
| where ActionType in (
    "WmiBindingCreated",
    "WmiFilterCreated",
    "WmiConsumerCreated")
| where Timestamp between ((T0 - 14d) .. (T0 + 2d))
| project Timestamp, ActionType, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AdditionalFields
```

### Files dropped in startup folder
```kql
// 04 — files written to the Startup folder
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// SHA256 is usually empty in DeviceFileEvents; enrich on SHA1

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceFileEvents
| where DeviceName startswith "HOSTNAME"
| where FolderPath has "Start Menu\\Programs\\Startup"
| where ActionType == "FileCreated"
| where Timestamp between ((T0 - 14d) .. (T0 + 2d))
| project Timestamp, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName
```
