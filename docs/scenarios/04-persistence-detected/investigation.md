# Persistence detected — investigation

## What you're looking for

Persistence is how attacker code runs again without the attacker: at logon, at startup, on a schedule, or when an event fires. It doesn't need a reboot. The example task below runs every 5 minutes, and a WMI subscription can fire on the clock, a user logon or the computer's uptime. A running payload, or a second mechanism you haven't found, can re-create anything you remove. So contain the device and record every item before you remove anything; the [playbook](playbook.md) sets the order.

Check for persistence before closing any incident where attacker code ran on the device.

This guide has queries for five mechanisms: Run keys (with Winlogon), scheduled tasks, services, startup folders and WMI subscriptions. They are the most frequent, not the full set. See [Other mechanisms](#other-mechanisms).

---

## Read the device first

The queries show changes recorded in the last 30 days. The device shows what is configured now, including entries older than that. Use both.

- **Investigation package** (collect it before anything is removed): the Autoruns folder holds one file per known auto-start entry point (ASEP) in the registry; Scheduled tasks and Services are CSV lists; Processes lists what was running at collection time.
- **Live Response, read-only commands** (basic role): `persistence` shows all known persistence methods on the device; `scheduledtasks`, `services` and `startupfolders` list each type; `registry <key>` shows the values in a key, and `registry <key>\\<value>` (double backslash) shows one value; `fileinfo <path>` describes a file; `processes` lists running processes. Microsoft doesn't list which methods `persistence` covers; whether it shows WMI subscriptions is VERIFY (tenant).
- Don't use Live Response `remediate` while you investigate. It changes the device (see the playbook).

### Record before you remove

Removal destroys the item. Record these for every item first; the playbook's removal step depends on them.

| Mechanism | Record |
|---|---|
| Registry (Run, Winlogon, service value) | Full key, value name, current data (`registry <key>\\<value>`), the data before the change (`PreviousRegistryValueData` in `DeviceRegistryEvents`), time, creating process and account |
| Scheduled task | Task path and name, action (command line), trigger, run-as account, the task XML file from `C:\Windows\System32\Tasks\` (Live Response `getfile`), time, creating process and account |
| Service | Service name, image path and arguments, start type, account, time, creating process and account |
| Startup folder | File path and SHA1; for a shortcut (`.lnk`), the file it starts |
| WMI subscription | Filter, consumer and binding names, the consumer's command or script, time, creating process |
| Every target file | Full path and SHA1 (`fileinfo`); preserve it with Collect file or `getfile` unless it is a Windows binary |

---

## Registry Run keys

A Run entry is one **value** under a shared key: the value name is a label and the data is the command line. Microsoft: "You can write multiple entries under a key." Legitimate programs share the same key, so the attacker's entry is one value among many. Remove only that value, never the key.

**Key locations (Microsoft):**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**Other autostart keys (MITRE ATT&CK T1547.001):** `RunOnceEx`, `RunServices`, `RunServicesOnce`, `Policies\Explorer\Run` (HKLM and HKCU), the `load` value of `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows`, and `Explorer\User Shell Folders` or `Shell Folders`, which can move the Startup folder. The Run-key query matches whole terms after `CurrentVersion\`, so it misses most of these. Check them in the package's Autoruns folder or with Live Response `registry`.

**RunOnce deletes itself.** By default Windows deletes a RunOnce value before it runs the command (unless the value name starts with `!`). A RunOnce value missing after a restart proves nothing; look for the write event instead.

**Red flags:** a command line pointing to `AppData\Local\Temp`, `AppData\Roaming`, `ProgramData` or `Users\Public`; a random value or file name; a name copying a legitimate product but pointing to a user-writable folder; a Windows binary (`powershell.exe`, `rundll32.exe`, `mshta.exe`) whose argument is a script, DLL, URL or encoded command. In that last case the payload is the argument, not the Windows binary.

---

## Winlogon

Winlogon is not a Run key. Only certain values under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` (also under `Wow6432Node`) and `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` matter (MITRE ATT&CK T1547.004):

- `Userinit` points to `userinit.exe`, the user initialization program run at logon.
- `Shell` points to `explorer.exe`, the shell run at logon.
- `Notify` points to notification package DLLs that handle Winlogon events.

The attacker usually changes one of these existing values, for example by adding a payload after the legitimate program, rather than adding a new one. These values are part of every user's logon, so never delete them or the key. The fix is to restore the original data, which `PreviousRegistryValueData` shows. That is the IR lead's decision (playbook).

The Run-key query watches the whole Winlogon key, where many legitimate values live. Read `RegistryValueName` and look only at the three above.

---

## Scheduled tasks

**How they are created:** `schtasks.exe /create`, which the task query sees. MITRE ATT&CK also lists a .NET wrapper, the netapi32 library, WMI and PowerShell `Invoke-CimMethod` with the `PS_ScheduledTask` class. None of these runs `schtasks.exe`, so the query misses them; use the package's Scheduled tasks CSV and Live Response `scheduledtasks`. `schtasks /create /s <computer>` creates the task on a remote computer: a task created from another device.

**Where a task lives:** an XML file under `C:\Windows\System32\Tasks\` named after the task, and a registry key under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`. Preserve the XML (`getfile`) before removal.

**Hidden tasks:** deleting the task's `SD` (security descriptor) value under `TaskCache\Tree\<task name>` makes the task disappear from `schtasks /query` and Task Scheduler, but it still runs. Deleting `SD` needs SYSTEM. ATT&CK also lists changing the `Index` value. Microsoft's advice is to look for task keys with no `SD` value. Whether Live Response `scheduledtasks` shows a hidden task is VERIFY (tenant). To check a task you know from telemetry or from a file in `C:\Windows\System32\Tasks\`: run `registry` on its `TaskCache\Tree` key and look for an `SD` value. No `SD` = hidden task; escalate.

**Removal doesn't stop it at once.** Microsoft observed a task whose registry keys and XML were removed keep running on its triggers until the device restarted or the `svchost.exe` process running it ended. Stop the payload process as well (playbook).

**Red flags:** random task name, or one copying a Windows or vendor task (for example `WindowsUpdate`); action in `Temp` or `AppData`; PowerShell `-enc` (decode it with the [process guide](../02-suspicious-process/investigation.md#decode-before-you-judge)); runs as SYSTEM with a target in a user-writable folder; created around T0; created by a process that isn't the customer's installer or management agent.

```
schtasks.exe /create /sc minute /mo 5 /tn "WindowsUpdate" /tr "powershell.exe -enc JABj..."
```

---

## Malicious services

**New or modified.** MITRE ATT&CK (T1543.003): adversaries "may install a new service or modify an existing service". Changing an existing service's `ImagePath` in the registry, or with `sc.exe config`, never raises `ServiceInstalled`. Windows event 4697 records the path only at creation: "If the path is changed afterwards, the change is not logged." Look for `RegistryValueSet` on `ImagePath` under the service's key in `DeviceRegistryEvents`, and for `sc.exe` with `config` in the Device timeline. A changed existing service is escalated, not removed (playbook).

**The query may be blind.** `ServiceInstalled` appears to depend on event 4697, which is in the "Audit Security System Extension" policy. Zero rows may mean the policy is off; the query header has a check. Rely on the package's Services CSV and Live Response `services` too.

**The query has no creating-process or account column.** Find the creator in the Device timeline at the event time, or in event 4697 (Subject) in the package's Security event log.

**Remote-access tools.** Installing a remote-access (RMM) tool often creates a service (MITRE ATT&CK T1219). It is signed and sits in `Program Files`, so a signature or path doesn't make it legitimate. Only the customer's approved list and a change record do.

**Red flags:** created with no matching software install or change record; image path outside `%windir%`, `Program Files` and `Program Files (x86)` (Microsoft's own monitoring advice for event 4697); service name copying a legitimate one; runs as LocalSystem with an unsigned target; created by an unexpected process; image path is a Windows binary (`cmd.exe`, `powershell.exe`, `rundll32.exe`) with a script or encoded argument.

---

## Startup folders

Anything here runs at user logon:
```
C:\Users\[user]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
```

- A shortcut (`.lnk`) is common. Its hash is not the payload's; find and preserve the file it starts.
- The query looks for `FileCreated` only. A file renamed or moved into the folder may appear differently (`DeviceFileEvents` has `PreviousFileName` and `PreviousFolderPath`). Check the Device timeline and Live Response `startupfolders`.
- `User Shell Folders` can move the Startup folder (see Run keys).

---

## WMI subscriptions

A WMI event subscription runs a command when an event fires (the clock, a user logon, the computer's uptime). It has three objects: **EventFilter** (trigger), **EventConsumer** (action) and **FilterToConsumerBinding** (links them). All three must be removed. Execution runs through `WmiPrvSE.exe` and may run as SYSTEM.

- It doesn't show in Task Manager or the Startup folders. Sysinternals Autoruns has a "WMI entries" category; whether Live Response `persistence` lists it is VERIFY (tenant).
- ASR rule "Block persistence through WMI event subscription" writes `AsrPersistenceThroughWmiAudited` or `AsrPersistenceThroughWmiBlocked` in `DeviceEvents`. `Blocked` means the attempt was stopped; `Audited` means it went through.
- The WMI query's action type names are not on Microsoft Learn; read its VERIFY note before trusting an empty result.
- The execution side is visible even when creation isn't: ATT&CK advises looking for `mofcomp.exe` and unusual child processes of `WmiPrvSE.exe`.
- Live Response `remediate` has no WMI entity type. Removal needs a script that removes all three objects, so it goes to the IR lead (playbook).
- Configuration Manager relies heavily on WMI (Microsoft). That explains WMI activity, not an unknown subscription.

---

## Other mechanisms

The five above are not the full set. MITRE ATT&CK also lists, among others: Image File Execution Options Injection, Component Object Model Hijacking, BITS Jobs, Logon Script (Windows) and Local Account creation. This guide has no queries for the first four. The package's Autoruns folder and Live Response `persistence` cover more locations than the queries; read them for every device. New local accounts: [new-local-accounts-created.kql](../../../kql/identity/new-local-accounts-created.kql) (it matches `DeviceName` exactly and looks back 7 days from now; see step 12 of the [credential compromise playbook](../06-credential-compromise/playbook.md)).

---

## Is it running?

- Package Processes folder, then Live Response `processes` for the current state and `connections` for live connections.
- `DeviceProcessEvents` or the Device timeline since T0 for the target's path or SHA1. The parent tells you which mechanism started it: a scheduled task runs under `svchost.exe`; a WMI subscription runs under `WmiPrvSE.exe`.
- A target that ran after T0 is a running payload until shown otherwise. Record its PID.

---

## Scope across the estate

- Remove the `DeviceName` line from a query and add `DeviceName` to its `project` line to search every device. Search on what is specific to this item: the value name, task name, service name, a command-line fragment, or the target's SHA1.
- Target files: the [hash sweep](../01-malware-alert/investigation.md#step-4--check-for-spread) with the target's SHA1.
- To see who created an entry, add `InitiatingProcessAccountName` and `InitiatingProcessCommandLine` to the `project` line.
- The same item on two or more devices is spread. Escalate (playbook). Zero rows don't prove no spread (next section).

---

## What the queries don't show

- Advanced Hunting holds 30 days of native data. Older creation events need Sentinel retention, or the device itself (package, Live Response).
- The window is T0 − 14 days to T0 + 2 days. Persistence planted earlier than that is missed; widen the window or rely on the device.
- Run keys: term matching misses the other autostart keys listed above.
- Scheduled tasks: `schtasks.exe` only; hidden tasks need the `SD` check.
- Services: may be empty without the audit policy; modified services never appear as `ServiceInstalled`.
- WMI: action type names unverified.
- Startup folders: `FileCreated` only.
- No query returns `DeviceName` or an account by default; add them (previous section).

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
