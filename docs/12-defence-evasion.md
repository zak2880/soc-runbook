# Defence evasion

## What is defence evasion?

Defence evasion covers the techniques attackers use to avoid detection — hiding from EDR, disabling security tools, blending into normal traffic, and covering their tracks. It's one of the most important tactic areas to understand for a Detection Engineer role because building detections that *can't* be evaded requires knowing exactly how evasion works.

> If you're seeing defence evasion techniques, you're not dealing with commodity malware. This is a hands-on-keyboard operator who knows your tools are watching.

---

## AMSI bypass

The Antimalware Scan Interface (AMSI) allows security products to inspect scripts before they execute — PowerShell, VBScript, JScript all pass through it. Attackers patch AMSI in memory to make it return a "clean" result for everything, allowing malicious scripts to run undetected.

**What it looks like in logs:**

```
powershell.exe -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
```

Also look for obfuscated variants — the string `AmsiUtils` or `amsiInitFailed` split across concatenation, character arrays, or base64 to avoid string-based detection:

```
'Am' + 'siUtils'
[char]65 + [char]109 + [char]115 + [char]105   # 'Amsi' in char codes
```

**KQL:**

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "AmsiUtils", "amsiInitFailed", "AmsiScanBuffer",
    "AmsiScanString", "amsi.dll", "HookAmsi",
    "Bypass", "DisableAmsi")
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
```

---

## ETW patching

Event Tracing for Windows (ETW) is what feeds telemetry to Defender and many EDR products. Attackers patch `EtwEventWrite` in memory to silently drop all telemetry from a process — it keeps running but becomes invisible to monitoring tools.

You won't see ETW patching directly in process logs (that's the point), but you can hunt for the setup conditions:

- PowerShell or a script calling `VirtualProtect` or `WriteProcessMemory` on its own process
- A process loading `ntdll.dll` and immediately making suspicious network connections with no corresponding telemetry

**KQL — process hollowing / memory manipulation setup:**

```kql
DeviceEvents
| where DeviceName == "HOSTNAME"
| where ActionType in (
    "NtAllocateVirtualMemoryApiCall",
    "NtWriteVirtualMemoryApiCall",
    "NtProtectVirtualMemoryApiCall")
| where InitiatingProcessFileName !in~ (
    "MsMpEng.exe", "svchost.exe", "csrss.exe",
    "lsass.exe", "services.exe", "smss.exe")
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, ActionType, AdditionalFields
```

---

## Process hollowing and injection

Malware launches a legitimate process (e.g. `svchost.exe`, `explorer.exe`) in a suspended state, replaces its memory with malicious code, then resumes it. The process looks legitimate in Task Manager but is running the attacker's code.

**Signs in logs:**
- Legitimate process making network connections it has no business making
- Legitimate process spawned by an unexpected parent
- Process created with `CREATE_SUSPENDED` flag followed by memory write calls

**KQL — legitimate processes making unexpected network connections:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (
    "notepad.exe", "calc.exe", "mspaint.exe",
    "wordpad.exe", "explorer.exe")
| where RemoteIPType == "Public"
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, InitiatingProcessFileName,
    RemoteIP, RemoteUrl, RemotePort,
    InitiatingProcessCommandLine
```

---

## Timestomping

Attackers modify file creation/modification timestamps to make malicious files blend in with legitimate system files — e.g. backdating a dropped executable to match the OS installation date.

**Red flags:**
- File creation date is years before the device was deployed
- File in `System32` with a timestamp predating the OS version it supposedly belongs to
- Newly dropped file with a timestamp of 1970, 1601, or a suspiciously round date

**KQL — files with suspiciously old timestamps in suspicious locations:**

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has_any ("Temp", "AppData", "ProgramData")
| where FileName endswith_any (".exe", ".dll", ".ps1")
| where Timestamp > ago(24h)
| extend FileCreationYear = datepart("year", Timestamp)
| where FileCreationYear < 2010
| project Timestamp, FileName, FolderPath, SHA256,
    InitiatingProcessFileName
```

---

## Alternate Data Streams (ADS)

NTFS Alternate Data Streams allow data to be hidden inside a file's metadata stream — invisible in Explorer and most file listings. Malware can store a payload or script in an ADS and execute it directly.

**What execution looks like:**

```
wscript.exe C:\legitimate-file.txt:payload.vbs
powershell.exe -c "Get-Content C:\file.txt:hidden.ps1 | IEX"
```

**KQL:**

```kql
DeviceProcessEvents
| where ProcessCommandLine matches regex @":\w+\.\w+"
| where ProcessCommandLine !has "http"  // exclude URLs
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, FileName,
    ProcessCommandLine, InitiatingProcessFileName
```

---

## Indicator removal — log and artefact clearing

When an attacker clears logs or deletes artefacts, they're telling you they've been on the system long enough to care about what you'll find. This is one of the strongest signals of a hands-on-keyboard operator.

**Event log clearing:**

```kql
DeviceProcessEvents
| where (FileName == "wevtutil.exe"
    and ProcessCommandLine has_any (" cl ", "clear-log"))
    or (FileName == "powershell.exe"
    and ProcessCommandLine has "Clear-EventLog")
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
```

**Prefetch and artefact deletion:**

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "del /f", "rm -Force", "Remove-Item",
    "cipher /w", "sdelete",
    "fsutil usn deletejournal")
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
```

---

## Disabling or tampering with security tools

**Defender disabled via registry:**

```kql
DeviceRegistryEvents
| where RegistryKey has_any (
    "DisableAntiSpyware", "DisableRealtimeMonitoring",
    "DisableBehaviorMonitoring", "DisableIOAVProtection",
    "DisableScriptScanning")
| where RegistryValueData == "1"
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, RegistryKey,
    InitiatingProcessFileName
```

**Security tools killed via taskkill:**

```kql
DeviceProcessEvents
| where FileName =~ "taskkill.exe"
| where ProcessCommandLine has_any (
    "MsMpEng", "msmpeng", "MBAMService",
    "cb.exe", "csagent", "falconhost",
    "xagt", "cyserver", "bdagent")
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
```

---

## UAC bypass

User Account Control bypass techniques allow a process running as a standard user to silently elevate to high integrity (administrator) without triggering a UAC prompt. Common techniques abuse auto-elevating Windows binaries.

**Common UAC bypass binaries — check for unexpected children:**

| Binary | Technique |
|--------|-----------|
| `fodhelper.exe` | Registry hijack via `HKCU\Software\Classes\ms-settings\shell\open\command` |
| `eventvwr.exe` | Registry hijack via `HKCU\Software\Classes\mscfile\shell\open\command` |
| `computerdefaults.exe` | Same registry hijack pattern as fodhelper |
| `sdclt.exe` | Registry hijack via `HKCU\Software\Classes\exefile` |

**KQL — auto-elevating binaries spawning unexpected children:**

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "fodhelper.exe", "eventvwr.exe",
    "computerdefaults.exe", "sdclt.exe",
    "cmstp.exe", "mmc.exe")
| where FileName !in~ (
    "conhost.exe", "WerFault.exe")
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName,
    InitiatingProcessFileName, FileName, ProcessCommandLine
```

**KQL — registry modifications used in UAC bypass:**

```kql
DeviceRegistryEvents
| where RegistryKey has_any (
    "ms-settings\\shell\\open\\command",
    "mscfile\\shell\\open\\command",
    "exefile\\shell\\open\\command")
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, RegistryKey,
    RegistryValueName, RegistryValueData,
    InitiatingProcessFileName
```

---

## Signed binary proxy execution

Attackers use legitimate, signed binaries to proxy the execution of malicious code — the binary is trusted by the OS and security tools so the malicious code runs under its context. See [07-lolbins.md](07-lolbins.md) for full per-binary detail.

The key evasion benefit: the process in the logs is signed by Microsoft, so hash-based and signature-based detections miss it entirely. Behavioural detection (what the binary is *doing*) is the only reliable approach.

---

## Defence evasion investigation checklist

- [ ] Check for AMSI bypass strings in PowerShell command lines
- [ ] Check for memory manipulation API calls from unexpected processes
- [ ] Check for legitimate processes making unexpected network connections (injection)
- [ ] Check for log clearing — wevtutil, Clear-EventLog
- [ ] Check for security tool tampering — registry keys, taskkill against EDR processes
- [ ] Check for UAC bypass — auto-elevating binaries spawning children
- [ ] Check for ADS execution — colon notation in process command lines
- [ ] Check for timestomped files if malware is trying to blend into System32
