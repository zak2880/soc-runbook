# Persistence mechanisms

## Why this matters

If you remediate without finding and removing persistence, the malware comes back after reboot. Always check persistence before closing an incident.

---

## Registry run keys

Most common persistence method. Malware adds an entry so it executes on every user login.

**Key locations:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
```

**Red flags:**
- Path points to `AppData\Temp`, `ProgramData`, `C:\Users\Public`
- Binary has a random alphanumeric name (`a8f3bc2d.exe`)
- Name mimics a legitimate entry but points to a temp path

---

## Scheduled tasks

**Red flags:**
- Task name is random or meaningless
- Task action points to `Temp`, `AppData`, or `ProgramData`
- Task uses PowerShell with `-enc` or `cmd /c`
- Task was created around the time of infection
- Created by a non-standard process

**Malicious example:**
```
schtasks.exe /create /sc minute /mo 5 /tn "WindowsUpdate" /tr "powershell.exe -enc JABj..."
schtasks.exe /create /sc onlogon /tn "Updater" /tr "C:\Users\user\AppData\Temp\a8f3.exe"
```

---

## Malicious services

**Red flags:**
- Created recently with no matching software installation
- Binary path in `Temp`, `AppData`, `ProgramData`
- Service name mimics a legitimate one
- Created by a non-standard process

---

## Startup folders

Anything dropped here runs on every login.

```
C:\Users\[user]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
```

---

## WMI subscriptions

Advanced persistence — malware registers a WMI event subscription that fires on a condition (startup, login, elapsed time). Doesn't appear in normal startup lists.

Three parts:
1. **EventFilter** — trigger condition
2. **EventConsumer** — action to take (run a command)
3. **FilterToConsumerBinding** — links the two

---

## Persistence hunting checklist

- [ ] Registry Run keys modified around infection time
- [ ] New scheduled tasks created around infection time
- [ ] New services installed
- [ ] Files dropped in Startup folders
- [ ] WMI subscriptions created

---

## KQL queries

Standalone query files in [kql/persistence/](../kql/persistence/).

### Registry run key modifications
```kql
DeviceRegistryEvents
| where DeviceName == "HOSTNAME"
| where RegistryKey has_any (
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce",
    "Winlogon")
| where Timestamp > ago(7d)
| project Timestamp, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName
```

### Scheduled task creation
```kql
DeviceProcessEvents
| where DeviceName == "HOSTNAME"
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
| where Timestamp > ago(7d)
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName
```

### New services installed
```kql
DeviceEvents
| where DeviceName == "HOSTNAME"
| where ActionType == "ServiceInstalled"
| where Timestamp > ago(7d)
| project Timestamp, FileName, FolderPath, AdditionalFields
```

### WMI subscription creation
```kql
DeviceEvents
| where DeviceName == "HOSTNAME"
| where ActionType in ("WmiBindingCreated", "WmiFilterCreated", "WmiConsumerCreated")
| where Timestamp > ago(7d)
| project Timestamp, ActionType, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AdditionalFields
```
