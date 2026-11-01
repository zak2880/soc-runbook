# Defence evasion — investigation

## What is defence evasion?

Techniques attackers use to avoid detection — disabling security tools, hiding from EDR, covering tracks. Seeing these techniques means you're not dealing with commodity malware. This is a hands-on-keyboard operator who knows your tools are watching.

---

## AMSI bypass

AMSI allows security tools to inspect scripts before execution. Attackers patch it in memory so it returns "clean" for everything.

**What it looks like:**
```
powershell.exe -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
```

Also obfuscated variants: `'Am' + 'siUtils'`, char arrays, base64 encoding of the string itself.

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

Auto-elevating binaries abused to silently elevate to high integrity.

| Binary | Technique |
|--------|-----------|
| `fodhelper.exe` | Registry hijack via `HKCU\Software\Classes\ms-settings\shell\open\command` |
| `eventvwr.exe` | Registry hijack via `HKCU\Software\Classes\mscfile\shell\open\command` |
| `computerdefaults.exe` | Same pattern as fodhelper |
| `sdclt.exe` | Registry hijack via `HKCU\Software\Classes\exefile` |

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

**Defender via registry:**
```kql
// Ransomware / defence evasion — Defender disabled or weakened
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
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

**EDR process killed:**
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

---

## Log and artefact clearing

**Event log clearing:**
```kql
// Defence evasion — Windows event log clearing
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
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

---

## Process injection

Malware injects into a legitimate process to hide under it.

**Signs:** Legitimate process (`notepad.exe`, `calc.exe`, `explorer.exe`) making unexpected external network connections.

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
