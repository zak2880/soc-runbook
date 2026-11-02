# Suspicious process — investigation

## What you're looking for

Malware almost always needs to run a process. The question is: what spawned it, and does that make sense? Look at the full chain — parent, child, grandchild — and ask whether each relationship is legitimate.

---

## Suspicious parent-child chains

| Parent | Spawning | Verdict |
|--------|----------|---------|
| `winword.exe` / `excel.exe` | `cmd.exe`, `powershell.exe`, `mshta.exe`, `wscript.exe` | 🔴 Almost always malicious |
| `explorer.exe` | Random `.exe` from `Temp` or `AppData` | 🔴 Investigate |
| `powershell.exe` | Another `powershell.exe` with `-enc` | 🔴 Suspicious |
| `svchost.exe` (from Temp) | Anything | 🔴 Fake svchost — malicious |
| `winword.exe` | `winword.exe` or `splwow64.exe` | 🟢 Normal |
| `services.exe` | `svchost.exe` (from System32) | 🟢 Normal |

---

## Encoded / obfuscated PowerShell

Flags to look for in `ProcessCommandLine`:

```
-e / -ec / -enc / -EncodedCommand  base64 payload (PowerShell accepts abbreviations)
-nop / -NoProfile              skips profile scripts
-noni / -NonInteractive        no interactive prompt
-w h / -w hidden / -WindowStyle Hidden  hiding from the user
IEX / Invoke-Expression        executes a string as code
DownloadString / WebClient     downloads from the internet
Reflection.Assembly::Load      loads .NET in memory (fileless)
FromBase64String               decoding a payload
```

> `-nop -w hidden -enc` together = almost always malicious

---

## LOLBins quick reference

Full detail → [../07-lolbin-abuse/investigation.md](../07-lolbin-abuse/investigation.md)

| Binary | Abused for | Key red flag |
|--------|-----------|--------------|
| `certutil.exe` | Downloading files, decoding base64 | `-urlcache -f http://...` |
| `mshta.exe` | Running remote VBScript/JScript | Any URL argument |
| `regsvr32.exe` | AppLocker bypass via remote scriptlet | `/i:http://...` + `scrobj.dll` |
| `rundll32.exe` | Credential dumping, proxy execution | `comsvcs.dll, MiniDump` |
| `wmic.exe` | Remote execution, shadow deletion | `process call create`, `shadowcopy delete` |
| `bitsadmin.exe` | Background file download | `/transfer http://...` |

---

## Process name spoofing

Always check the **full file path**, not just the process name.

| Legitimate | Suspicious — same name, wrong path |
|-----------|-----------------------------------|
| `C:\Windows\System32\svchost.exe` | `C:\Users\user\AppData\Temp\svchost.exe` |
| `C:\Windows\System32\lsass.exe` | `C:\Windows\lssas.exe` (typo) |
| `C:\Windows\explorer.exe` | `C:\Windows\Temp\explorer.exe` |

---

## KQL queries

### Processes in a time window
```kql
// All process events on a device within a specific time window
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: n/a (triage)
// Use to reconstruct execution chain around a detection timestamp
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// Ref: docs/scenarios/01-malware-alert/investigation.md, docs/scenarios/02-suspicious-process/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where DeviceName startswith "HOSTNAME"
| where Timestamp between ((T0 - 30m) .. (T0 + 2h))
| project Timestamp, InitiatingProcessFileName, FileName,
    ProcessCommandLine, FolderPath, AccountName
| order by Timestamp asc
```

### Suspicious PowerShell
```kql
// Suspicious PowerShell command-line flags
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1059.001, T1027
// Covers: encoded commands, download cradles, fileless execution, evasion switches
// PowerShell accepts abbreviated switches: -e / -ec = -EncodedCommand, -w h = -WindowStyle Hidden
// -nop = -NoProfile, -noni = -NonInteractive (two different switches)
// Runs estate-wide; add | where DeviceName startswith "HOSTNAME" (short name) to scope to one device
// Ref: docs/scenarios/02-suspicious-process/investigation.md, docs/scenarios/07-lolbin-abuse/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "-e", "-ec", "-enc", "-EncodedCommand",
    "IEX", "Invoke-Expression",
    "DownloadString", "WebClient",
    "-nop", "-NoProfile",
    "-noni", "-NonInteractive",
    "Reflection.Assembly", "FromBase64String",
    "-w h", "-w hidden", "-WindowStyle Hidden")
| project Timestamp, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
```

### Office spawning shells
```kql
// Office application spawning shell processes (phishing chain detector)
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1566.001, T1204.002
// Covers: Word, Excel, PowerPoint, Outlook, OneNote spawning cmd/PowerShell/mshta/LOLBins
// High-fidelity signal — legitimate Office apps should not spawn shells
// Ref: docs/scenarios/02-suspicious-process/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where Timestamp between ((T0 - 7d) .. (T0 + 1d))
| where InitiatingProcessFileName in~ (
    "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe", "onenote.exe", "msaccess.exe")
| where FileName in~ (
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "certutil.exe", "bitsadmin.exe", "wmic.exe")
| project Timestamp, DeviceName, AccountName,
    InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc
```

### All LOLBin abuse
```kql
// LOLBin abuse — master sweep across all known Living Off the Land binaries
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1218.005, T1218.010, T1218.011, T1059.001, T1059.007, T1105, T1140, T1047, T1197, T1003.001, T1490
// Covers: certutil, PowerShell, mshta, regsvr32, rundll32, wmic, bitsadmin
// Run estate-wide as a daily hunt (set T0 to now()) or scope to a specific device
// "has" matches whole terms, so "http" does not match https:// URLs; both are listed
// Ref: docs/scenarios/07-lolbin-abuse/investigation.md, docs/scenarios/02-suspicious-process/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where (
    // certutil downloading or decoding
    (FileName =~ "certutil.exe"
        and ProcessCommandLine has_any("-urlcache", "-decode", "http", "https"))
    // PowerShell suspicious flags (-e / -ec abbreviate -EncodedCommand, -w h = -WindowStyle Hidden)
    or (FileName in~ ("powershell.exe", "pwsh.exe")
        and ProcessCommandLine has_any(
            "-e", "-ec", "-enc", "-EncodedCommand", "IEX",
            "DownloadString", "-w h", "-w hidden", "Reflection.Assembly"))
    // mshta — almost never legitimate in modern environments
    or (FileName =~ "mshta.exe"
        and ProcessCommandLine has_any("http", "https", "vbscript:", "javascript:"))
    // regsvr32 remote scriptlet (Squiblydoo / AppLocker bypass)
    or (FileName =~ "regsvr32.exe"
        and ProcessCommandLine has_any("http", "https", "scrobj.dll", "/i:"))
    // rundll32 credential dump or suspicious DLL
    or (FileName =~ "rundll32.exe"
        and ProcessCommandLine has_any("comsvcs", "MiniDump", "javascript:", "AppData", "Temp"))
    // wmic remote execution or shadow deletion
    or (FileName =~ "wmic.exe"
        and ProcessCommandLine has_any("process call create", "shadowcopy delete", "/node:"))
    // bitsadmin download or notification command
    or (FileName =~ "bitsadmin.exe"
        and ProcessCommandLine has_any("/transfer", "http", "https", "SetNotifyCmdLine"))
)
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
