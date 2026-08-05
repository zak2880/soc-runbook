# Persistence detected — investigation

## Why this matters

If you remediate without finding and removing persistence, the malware comes back after reboot. Always check for persistence before closing any malware incident.

---

> **Before escalating:** check [common false positives — Persistence](../../reference/common-false-positives.md#persistence) — confirm this isn't one of the known benign patterns before treating it as a true positive.

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
DeviceRegistryEvents
| where DeviceName == "HOSTNAME"
| where RegistryKey has_any (
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce",
    "Winlogon")
| where TimeGenerated > ago(7d)
| project TimeGenerated, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName
```

### Scheduled task creation
```kql
DeviceProcessEvents
| where DeviceName == "HOSTNAME"
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
| where TimeGenerated > ago(7d)
| project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName
```

### New services installed
```kql
DeviceEvents
| where DeviceName == "HOSTNAME"
| where ActionType == "ServiceInstalled"
| where TimeGenerated > ago(7d)
| project TimeGenerated, FileName, FolderPath, AdditionalFields
```

### WMI subscription creation
```kql
DeviceEvents
| where DeviceName == "HOSTNAME"
| where ActionType in (
    "WmiBindingCreated", "WmiFilterCreated", "WmiConsumerCreated")
| where TimeGenerated > ago(7d)
| project TimeGenerated, ActionType, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AdditionalFields
```

### Files dropped in startup folder
```kql
DeviceFileEvents
| where DeviceName == "HOSTNAME"
| where FolderPath has "Start Menu\\Programs\\Startup"
| where ActionType == "FileCreated"
| where TimeGenerated > ago(7d)
| project TimeGenerated, FileName, FolderPath, SHA256, InitiatingProcessFileName
```
