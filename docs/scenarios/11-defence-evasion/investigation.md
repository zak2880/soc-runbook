# Defence evasion — investigation

This page explains each technique and how to check it. What to do, in order, is in the [playbook](playbook.md). With a live incident, start there: if you arrived here from the README or the MITRE mapping, nothing on this page tells you to change anything on a device.

Two rules hold throughout. Never add a Defender exclusion, whatever the reason. Never turn protection back on yourself: record the state first and request it (step 28 of the [playbook](playbook.md)).

The six queries on this page run across the whole estate from `T0` − 24 hours to `T0` + 24 hours. Replace `PASTE_TIME_UTC`, then filter the results to your device.

---

## What is defence evasion?

Techniques attackers use to avoid detection: turning off or weakening security tools, hiding inside other processes, and covering their tracks.

These techniques appear in commodity malware as well as hands-on-keyboard intrusions. ATT&CK lists Lumma Stealer trying to bypass AMSI and PureCrypter adding Defender exclusions, for example. One of them on its own doesn't tell you a person is at the keyboard. Several techniques together, interactive timing, or tampering followed by discovery or lateral movement point to an operator. Either way, something has already run on the device.

---

## Check the real state first

A query hit shows an attempt. It doesn't show that protection changed, and an empty result doesn't show that protection is on.

- With tamper protection on, Microsoft says attempts to change Defender Antivirus settings through the registry are blocked and real-time protection stays on. Changes made through a management tool "might appear to succeed" while tamper protection blocks them.
- Microsoft says `DisableAntiSpyware` is ignored on devices onboarded to Defender for Endpoint (platform 4.18.2108.4 and later). A hit on it is an attempt, not a Defender that is off.
- A driver-based kill, or a bypass inside a script, leaves no row in these queries.

Read the state from the device. All of these are read-only.

| Where | What it shows | Limits |
|-------|---------------|--------|
| Device page: Sensor health state (or `DeviceInfo`: `OnboardingStatus`, `SensorHealthState`) | Whether the EDR sensor is healthy. Misconfigured has two forms: Impaired communications (limited communication with the service) and No sensor data (it reports only partial sensor data) | Microsoft treats a device as Inactive after more than seven days without signals. Active doesn't prove the sensor is working now |
| Device timeline: the newest events | Whether the sensor is still sending | The device page's Last seen can lag: Microsoft says it may show an older time than the timeline. A device that is switched off also goes quiet; ask the customer |
| Device page: Device health status card | `Defender Antivirus not active` as the top message, the Defender Antivirus mode, the last scans | Microsoft says the date and time for the mode isn't available |
| Device page: Configuration management, Effective settings tab | The actual value of each antivirus setting, ASR rule and exclusion, the source that set it, other attempts that didn't take effect, and the last report time | It is as old as the last report time. VERIFY (tenant) that the tab is available for this device |
| Live Response `processes` and `services` | `MsMpEng.exe` and `MsSense.exe` running; the `WinDefend`, `Sense` and `EventLog` services | Needs the Live Response role and a responding sensor |
| Live Response `registry` | The policy and exclusion keys, for example `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` and `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` | Read-only. Don't use `remediate` on these keys |
| `Get-MpComputerStatus` and `Get-MpPreference` | `AMRunningMode` (`Normal`, `Passive` or `EDR Block Mode`), `RealTimeProtectionEnabled`, `IsTamperProtected`, `BehaviorMonitorEnabled`, `IoavProtectionEnabled`; exclusions | Live Response has no PowerShell prompt. It runs a script only from the library (`run`, an advanced command), and unsigned scripts need a tenant setting. Otherwise ask the customer's IT contact. `HideExclusionsFromLocalAdmin` hides exclusions from local administrators |

How to read it:

- **Passive or EDR Block Mode** is normal only where a non-Microsoft antivirus is the customer's primary product. Check the asset list. A device that was in active mode yesterday and is passive today has changed.
- **`Defender Antivirus not active`** or an `AMRunningMode` outside the three values: Microsoft says you should see one of them if antivirus protection is enabled.
- **EDR client in Critical mode:** a timeline event. Microsoft says the EDR client stops processing new events until it recovers from low resources. It isn't tampering in itself, but events are missing for that period.

### What Defender can't do while it is off

Several response actions depend on Defender Antivirus. That is why protection goes back on before Stop and Quarantine File and the indicators.

| Action | Needs |
|--------|-------|
| Isolate device | Supported in passive mode. If the device is offline or inactive, Defender retries for up to three days |
| Stop and Quarantine File | Defender Antivirus at least in passive mode |
| File indicators | Defender Antivirus in active mode |
| IP, URL and domain indicators outside Edge | Defender Antivirus in active mode, behaviour monitoring, cloud protection, and network protection in block mode |
| Run antivirus scan | Defender Antivirus active or passive |
| ASR rules, network protection | Active mode. Microsoft's table lists neither for passive mode |

Exclusions weaken these too. Microsoft's order of evaluation puts an antivirus exclusion before a block file indicator: a file under an exclusion stays allowed. A process exclusion stops network protection inspecting that process's traffic. Exclusions apply to on-demand scans as well, so a clean scan with an attacker's exclusion in place proves nothing about that path.

---

## Was it blocked?

Use [Was it blocked?](../02-suspicious-process/investigation.md#was-it-blocked) in the suspicious process guide for detection status and ASR events. For this scenario, also check:

- `TamperingAttempt` in `DeviceEvents`. Microsoft says tampering that isn't correlated with suspicious activity might not raise an alert but stays in the Device timeline and advanced hunting. No alert doesn't mean no attempt.
- `AsrVulnerableSignedDriverAudited` and `AsrVulnerableSignedDriverBlocked`. Microsoft lists this rule as raising no EDR alert. `Audited` means the driver was saved.
- In passive mode there are no ASR events to find.

A block changes the urgency. It doesn't clear the device: something on it tried to turn protection off.

---

## AMSI bypass

AMSI lets security tools inspect script content before it runs. Microsoft lists PowerShell, Windows Script Host (`wscript.exe`, `cscript.exe`), JavaScript and VBScript, and Office VBA macros among the components that use it. Attackers tamper with it in the process, for example by patching `AmsiScanBuffer` or, as in the example below, by setting `amsiInitFailed` so the session stops sending content for scanning.

**Check alerts first.** Microsoft says script code reaches AMSI in plain form, after de-obfuscation, so Defender's own alerts see what a command-line search can't. "Possible anti-malware Scan Interface (AMSI) tampering" is on Microsoft's list of tampering alert titles, so it counts as a tamper alert. Look for script and AMSI events in the Device timeline too; their `ActionType` names aren't listed on Microsoft Learn ([Injection and AMSI event names](#injection-and-amsi-event-names)).

**What it looks like:**
```
powershell.exe -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
```

Also obfuscated variants: `'Am' + 'siUtils'`, char arrays, base64 encoding of the string itself. The query below finds none of these.

**What the query misses:** it matches literal strings in the command line of `powershell.exe` only. It misses `pwsh.exe`, renamed copies, the script hosts, every obfuscated variant, and a bypass inside a downloaded or `IEX`-evaluated script. An empty result is not a clean result. Decode anything encoded first ([Decode before you judge](../02-suspicious-process/investigation.md#decode-before-you-judge)).

**`Bypass` in the list is noisy:** it matches `-ExecutionPolicy Bypass`, which legitimate scripts also use. That switch alone is not an AMSI bypass.

**What matters is what happened next:** after a bypass, whatever that session runs isn't inspected. Look for a download, a child process or persistence from the same process.

**KQL:**
```kql
// 11 — AMSI bypass strings on the PowerShell command line
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "AmsiUtils", "amsiInitFailed", "AmsiScanBuffer",
    "amsi.dll", "HookAmsi", "Bypass", "DisableAmsi")
| project Timestamp, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
```

---

## UAC bypass

Auto-elevating binaries abused to elevate without a prompt. ATT&CK says this works when the UAC level is set to anything but the highest.

| Binary | Technique | Status |
|--------|-----------|--------|
| `fodhelper.exe` | Registry hijack via `HKCU\Software\Classes\ms-settings\shell\open\command` (`DelegateExecute` value) | UACME lists it as unfixed |
| `computerdefaults.exe` | Same pattern as fodhelper | UACME lists it as unfixed |
| `eventvwr.exe` | Registry hijack via `HKCU\Software\Classes\mscfile\shell\open\command` | UACME lists it as fixed in Windows 10 RS2 (15031). Legacy builds only |
| `sdclt.exe` | Registry hijack via `HKCU\Software\Classes\exefile\shell\runas\command` (`IsolatedCommand` value) | UACME lists this method as fixed in Windows 10 RS4 (17025), and a different sdclt method as unfixed. Don't dismiss sdclt children |
| `cmstp.exe` | Malicious INF file. ATT&CK: "can also be abused to Bypass User Account Control" | Check the INF file named in the command line |

UACME is a research project, not a Microsoft source. Treat the fixed builds as a guide.

**Reading a hit:**
- `eventvwr.exe` starting `mmc.exe` is normal: Event Viewer does this on every launch. The query doesn't exclude it. Ignore it unless the registry check below finds a hijack.
- Look at the child's `ProcessTokenElevation`: `TokenElevationTypeFull` means elevated. The query doesn't return this column; read it in the Device timeline or add it in the portal.
- `InitiatingProcessParentFileName` shows what started the auto-elevating binary. That is the attacker's process, if there is one. Add that column too.

**Registry check:** in `DeviceRegistryEvents` for this device from T0, look for `RegistryKey` containing `ms-settings\shell\open\command`, `mscfile\shell\open\command` or `exefile\shell\runas\command`. The fodhelper key doesn't exist by default. Any write to one of them with a command in `RegistryValueData` is a hijack. It sits under the user's hive, so record which user. The query below doesn't cover this.

**KQL:**
```kql
// 11 — processes launched by common UAC-bypass binaries
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where InitiatingProcessFileName in~ (
    "fodhelper.exe", "eventvwr.exe",
    "computerdefaults.exe", "sdclt.exe", "cmstp.exe")
| where FileName !in~ ("conhost.exe", "WerFault.exe")
| project Timestamp, DeviceName, AccountName,
    InitiatingProcessFileName, FileName, ProcessCommandLine
```

---

## Disabling security tools

Check the alerts first. Microsoft's list of tampering alert titles includes, for example, "Microsoft Defender Antivirus protection turned off", "Tamper protection bypass", "Suspicious Microsoft Defender Antivirus exclusion", "Modification attempt in Microsoft Defender Antivirus exclusion list", "Driver-based tampering attempt blocked" and "Tampering with the Microsoft Defender for Endpoint sensor". `AlertInfo` holds the titles.

### Defender settings and exclusions

**What to look for:**
- `Set-MpPreference` with a disabling setting (for example `-DisableRealtimeMonitoring`, `-DisableBehaviorMonitoring`, `-DisableIOAVProtection`, `-DisableScriptScanning`).
- `Add-MpPreference` with `-ExclusionPath`, `-ExclusionExtension`, `-ExclusionProcess` or `-ExclusionIpAddress`.
- `TamperingAttempt` events, and event 5013 in the Windows Defender Operational log. Microsoft says 5013 states which setting change was blocked.
- Events 5001 (real-time protection disabled), 5007 (configuration changed, with the old and new value), 5010 and 5012 (scanning disabled) in the same log. Microsoft says of 5007: if it is unexpected, review the settings, as it might be the result of malware.

**Exclusions.** Windows exclusions apply to antivirus scanning, not to EDR: excluded files can still raise EDR alerts. Tamper protection protects exclusion lists only under conditions: the device is managed only by Intune or only by Configuration Manager, exclusions are managed there, and `DisableLocalAdminMerge` is on. `TPExclusions` set to `1` in `HKLM\SOFTWARE\Microsoft\Windows Defender\Features` confirms it. Don't assume a local exclusion was blocked; read it in Effective settings or with `Get-MpPreference`.

An exclusion that covers a whole drive, a user-writable folder (`Temp`, `AppData`, `Public`, `Downloads`), a common extension such as `.exe`, or a file in the process chain needs an explanation you can verify. Microsoft says an exclusion creates a protection gap.

**Who changed it.** Effective settings names the source. If a Group Policy, Intune or Configuration Manager policy set it, the change came through the customer's management system, not a command on this device.

**Troubleshooting mode.** Local administrators can change protected settings while it is on. It lasts up to four hours, then settings revert. An administrator with Security Administrator rights starts it from the device page. It shows in the Device timeline and as `AntivirusTroubleshootModeEvent` in `DeviceEvents`. Someone with that role, or stolen credentials for it, can start it; confirm who did.

**What the query misses:** the command-line branch uses `has_any ("Exclusion", "Disable")`, and `has` matches whole terms only. It can miss `-ExclusionPath` and `-DisableRealtimeMonitoring`. Don't rely on it: also search the Device timeline for `MpPreference`. VERIFY (tenant) with a test command which of these the query returns. Attempts blocked by tamper protection may show only as `TamperingAttempt`.

**KQL (`defence-evasion-defender-disabled`):**
```kql
// Ransomware / defence evasion — Defender disabled or weakened
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1685
// Attackers disable security controls before deploying payload
// Any of these = active attacker, not just malware — escalate immediately
// Three sources: Defender policy values set in the registry (value names are in RegistryValueName,
// not RegistryKey) or exclusions added; Set-/Add-MpPreference disabling or excluding on the command
// line; and Defender tamper-protection TamperingAttempt events
// A hit is an attempt; confirm the actual Defender state on the device
// VERIFY: ActionType "RegistryValueSet" is not listed on Microsoft Learn:
// DeviceRegistryEvents | where Timestamp > ago(1d) | summarize count() by ActionType
// Ref: docs/reference/escalation-triggers.md, docs/scenarios/11-defence-evasion/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
union
    (DeviceRegistryEvents
    | where Timestamp between ((T0 - 1d) .. (T0 + 1d))
    | where ActionType == "RegistryValueSet"
    | where RegistryKey has @"Windows Defender"
    | where RegistryValueName in~ ("DisableAntiSpyware", "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring", "DisableIOAVProtection")
        or RegistryKey has @"Windows Defender\Exclusions"
    | project Timestamp, DeviceName, Source = "registry",
        Detail = strcat(RegistryKey, " ", RegistryValueName, "=", RegistryValueData),
        InitiatingProcessFileName, InitiatingProcessAccountName),
    (DeviceProcessEvents
    | where Timestamp between ((T0 - 1d) .. (T0 + 1d))
    | where ProcessCommandLine has_any ("Set-MpPreference", "Add-MpPreference")
    | where ProcessCommandLine has_any ("Exclusion", "Disable")
    | project Timestamp, DeviceName, Source = "cmdline", Detail = ProcessCommandLine,
        InitiatingProcessFileName, InitiatingProcessAccountName = AccountName),
    (DeviceEvents
    | where Timestamp between ((T0 - 1d) .. (T0 + 1d))
    | where ActionType == "TamperingAttempt"
    | project Timestamp, DeviceName, Source = "tamper", Detail = tostring(AdditionalFields),
        InitiatingProcessFileName, InitiatingProcessAccountName)
| order by Timestamp asc
```

### Security tools stopped or killed

A hit here is an attempt. Microsoft lists terminating processes and stopping services among the techniques tamper protection defends against, so `taskkill` against Defender may fail. Check the actual state ([Check the real state first](#check-the-real-state-first)).

**What the query misses:** it matches `taskkill.exe` with a product name in the command line. `taskkill /pid` never matches. Neither do `sc stop`, `sc config`, `sc delete`, `net stop`, `Stop-Process` or `Set-Service`. Search the Device timeline for those, with the service names `WinDefend` and `Sense`, and for the customer's other security products. Booting into Safe Mode (`bcdedit`, `bootcfg`) is a related trick: Microsoft says many security products are disabled or limited there, and the `AsrSafeModeRebootBlocked` ASR event records a block.

**KQL:**
```kql
// 11 — taskkill against security product processes
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where FileName =~ "taskkill.exe"
| where ProcessCommandLine has_any (
    "MsMpEng", "csagent", "falconhost", "xagt", "cyserver", "bdagent")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### Vulnerable drivers

Current EDR killers load a legitimate but vulnerable signed driver to reach the kernel. Microsoft says this lets attackers disable or get round security solutions. No process query above shows it.

- Defender alerts: "Driver-based tampering attempt blocked", "Potential attempt to tamper with MDE via drivers".
- ASR events: `AsrVulnerableSignedDriverAudited` and `AsrVulnerableSignedDriverBlocked` ([Was it blocked?](#was-it-blocked)). Microsoft says the rule stops apps saving a vulnerable driver but doesn't stop a driver already on the device from loading.
- `DeviceFileEvents` for this device from T0: `FileName` ending `.sys`, outside `C:\Windows\`. Check the SHA1 with the [threat intel enrichment guide](../../reference/threat-intel-enrichment.md); look it up, don't upload it.
- Live Response `drivers` shows all drivers installed on the device. Compare with the package and with what the customer expects.
- Driver-load events in the Device timeline. Their `ActionType` name isn't listed on Microsoft Learn ([Injection and AMSI event names](#injection-and-amsi-event-names)).

Microsoft says the vulnerable driver blocklist is on by default only since the Windows 11 2022 update. Older builds and servers may not have it.

### Firewall changes

Attackers turn the host firewall off or add a rule to allow inbound connections: `netsh advfirewall`, `Set-NetFirewallProfile`, `New-NetFirewallRule`, or registry changes (ATT&CK T1686.003). No query on this page covers it. Search the Device timeline for those names from T0. Firewall events in the timeline, such as 5025 (firewall service stopped), appear only if the customer's audit policy enables them.

---

## Log and artefact clearing

Events the sensor already sent are held in the Defender service with its own retention, so expect them to survive a log clear on the device. Microsoft doesn't state this directly. The sensor sees only what it sees: anything that wrote only to the cleared log is gone unless the customer forwards logs elsewhere.

### Event log clearing

- Security event 1102 is written every time the Security log is cleared, and it records the account that did it. Microsoft says you should typically not see this event. Read it in the package's Security event log. Other logs can show event 104 in the System log; that comes from Microsoft Q&A answers, not a formal reference.
- ATT&CK also lists clearing through the Event Viewer GUI, `Remove-EventLog -LogName Security`, and deleting `.evtx` files from `C:\Windows\System32\winevt\logs\`.

**What the query misses:** it covers `wevtutil cl` and `Clear-EventLog` only, and only when the text is in that process's own command line. It misses `Remove-EventLog`, the Event Viewer GUI, deleted `.evtx` files and a clear inside a script. For deleted log files, check `DeviceFileEvents` for this device for deletions under `\winevt\Logs\`.

**KQL (`event-log-clearing`):**
```kql
// Defence evasion — Windows event log clearing
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1685.005
// Attackers clear logs to destroy forensic evidence before or after ransomware deployment
// If logs are being cleared, assume active attacker covering tracks — escalate immediately
// Covers wevtutil cl / clear-log and PowerShell Clear-EventLog; file names matched case-insensitively
// Ref: docs/reference/escalation-triggers.md, docs/scenarios/11-defence-evasion/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where (FileName =~ "wevtutil.exe"
    and ProcessCommandLine has_any (" cl ", "clear-log"))
    or (FileName in~ ("powershell.exe", "pwsh.exe")
    and ProcessCommandLine has "Clear-EventLog")
| project Timestamp, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
```

### Audit policy and the EventLog service

Turning logging off leaves nothing to clear. No query on this page covers it. Search the Device timeline from T0 for:

- `auditpol /clear`, `auditpol /remove /allusers`, `auditpol /set` with `/success:disable` or `/failure:disable`. Microsoft says `auditpol /clear` resets (disables) the system audit policy for all subcategories.
- `wevtutil sl` with `/e:false` (disables a log).
- `sc config eventlog start=disabled`, `Set-Service -Name EventLog -Status Stopped`.

Some Defender data depends on the audit policy too, for example firewall events in the timeline. Audit changes can make later queries come back empty.

### Timestomping

Can't be checked in Advanced Hunting. `DeviceFileEvents` has the time of the event but no column for a file's own created or modified time, so no query can find "suspiciously old dates". If it matters, ask the IR lead about disk forensics (ATT&CK refers to comparing the file's `$SI` and `$FN` timestamps).

### Alternate data streams

No query on this page covers this, and a plain search for a colon matches every `C:\` path. In `DeviceProcessEvents` for this device, look for `ProcessCommandLine` matching `\w\.\w{1,5}:[^\\\s]` (a colon straight after a file name), and leave out `Zone.Identifier`, which marks downloaded files. Addresses with a port (`.com:8080`) also match; discard them. ATT&CK T1564.004 refers to the `file.ext:ads` colon syntax and to tools with stream parameters.

---

## Process injection

Malware injects into a legitimate process to hide under it. ATT&CK's example has a C2 module injected into a running Chrome, Firefox or Edge process, so the host can be something that connects to the internet all day.

**Confirm it from alerts.** Use Defender alerts that name injection, and the Device timeline for the process. ATT&CK's detection guidance correlates memory API calls (for example `VirtualAllocEx`, `WriteProcessMemory`), remote thread creation and unusual DLL loads.

**Signs:** a process that has no reason to use the network making public connections. The query below is a symptom hunt. A hit doesn't confirm injection, and no hit doesn't rule it out: it lists four GUI applications only. It leaves out `explorer.exe` because that connects constantly, so the query can't speak for it.

**What Defender can't give you:** the investigation package has no process memory, and neither do the Advanced Hunting tables. Memory capture is the IR lead's call and needs other tooling. Don't stop an injected process: Stop and Quarantine File can't act on Microsoft-signed files, and Live Response `remediate` on a process stops it and deletes its image file, which here is a legitimate binary. A restart loses what is in memory.

**Process hollowing and other native API use:** there is no query in this repo. Rely on Defender alerts and the event names below.

### Injection and AMSI event names

Microsoft's `DeviceEvents` page doesn't list `ActionType` values; it points to the schema reference in the portal. Names such as `CreateRemoteThreadApiCall`, `AmsiScriptDetection` and `DriverLoad` are not confirmed from Microsoft Learn. VERIFY (tenant) in the portal schema reference, or run `DeviceEvents | where Timestamp > ago(1d) | summarize count() by ActionType`, before relying on them.

**KQL:**

```kql
// 11 — unusual processes making public connections (injection symptom)
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where InitiatingProcessFileName in~ (
    "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName,
    RemoteIP, RemoteUrl, RemotePort
```

---

## Telemetry gaps and ETW tampering

ETW patching has no single event, and there is no query for it here. ATT&CK names the signal: "abnormal absence of expected telemetry". Look for:

- A drop in the device's events in the timeline while the device stays online and in use.
- A process you know ran (from an alert or the package) with no matching events.
- The start and end of any gap, and what happened either side of it.

Rule out the benign causes first: the device was off or offline, or the EDR client was in Critical mode ([Check the real state first](#check-the-real-state-first)). Record every gap. For that period, the device's own telemetry can't show what didn't happen.

---

## Scope across the estate

The queries above already run estate-wide, so read past your device in the results. Then check:

- The same exclusion path, setting change or `.sys` hash on other devices (hash sweep: [Hash across estate](../05-malicious-file/investigation.md#hash-across-estate)).
- Alerts such as "Attempt to tamper with Microsoft Defender on multiple devices", "Possible remote tampering" and "Tampering activity typical to ransomware attacks".
- Effective settings on devices in the same group, if a policy set the value.

Zero rows doesn't prove no spread: the limits listed under each query apply here too.
