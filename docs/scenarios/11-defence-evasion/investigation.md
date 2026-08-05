# Defence evasion — investigation

## What is defence evasion?

Techniques attackers use to avoid detection — disabling security tools, hiding from EDR, covering tracks. Seeing these techniques means you're not dealing with commodity malware. This is a hands-on-keyboard operator who knows your tools are watching.

---

> **Before escalating:** check [common false positives — Defence evasion](../../reference/common-false-positives.md#defence-evasion) — confirm this isn't one of the known benign patterns before treating it as a true positive.

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
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "AmsiUtils", "amsiInitFailed", "AmsiScanBuffer",
    "amsi.dll", "HookAmsi", "Bypass", "DisableAmsi")
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, AccountName,
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
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "fodhelper.exe", "eventvwr.exe",
    "computerdefaults.exe", "sdclt.exe", "cmstp.exe")
| where FileName !in~ ("conhost.exe", "WerFault.exe")
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, FileName, ProcessCommandLine
```

---

## Disabling security tools

**Defender via registry:**
```kql
DeviceRegistryEvents
| where RegistryKey has_any (
    "DisableAntiSpyware", "DisableRealtimeMonitoring",
    "DisableBehaviorMonitoring", "DisableIOAVProtection")
| where RegistryValueData == "1"
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, RegistryKey, InitiatingProcessFileName
```

**EDR process killed:**
```kql
DeviceProcessEvents
| where FileName =~ "taskkill.exe"
| where ProcessCommandLine has_any (
    "MsMpEng", "csagent", "falconhost", "xagt", "cyserver", "bdagent")
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

---

## Log and artefact clearing

**Event log clearing:**
```kql
DeviceProcessEvents
| where (FileName == "wevtutil.exe"
    and ProcessCommandLine has_any (" cl ", "clear-log"))
    or (FileName == "powershell.exe"
    and ProcessCommandLine has "Clear-EventLog")
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
```

---

## Process injection

Malware injects into a legitimate process to hide under it.

**Signs:** Legitimate process (`notepad.exe`, `calc.exe`, `explorer.exe`) making unexpected external network connections.

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (
    "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe")
| where RemoteIPType == "Public"
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
    RemoteIP, RemoteUrl, RemotePort
```
