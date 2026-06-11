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
-enc / -EncodedCommand         base64 payload
-nop / -NonInteractive         evasion — no profile loaded
-w hidden / -WindowStyle Hidden  hiding from the user
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
DeviceProcessEvents
| where DeviceName == "HOSTNAME"
| where Timestamp between (datetime(YYYY-MM-DDThh:mm) .. datetime(YYYY-MM-DDThh:mm))
| project Timestamp, InitiatingProcessFileName, FileName,
    ProcessCommandLine, FolderPath, AccountName
| order by Timestamp asc
```

### Suspicious PowerShell
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "-enc", "-EncodedCommand", "IEX", "Invoke-Expression",
    "DownloadString", "WebClient", "-nop",
    "Reflection.Assembly", "FromBase64String", "-w hidden")
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
```

### Office spawning shells
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
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
DeviceProcessEvents
| where Timestamp > ago(24h)
| where (
    (FileName =~ "certutil.exe" and ProcessCommandLine has_any("-urlcache","-decode","http"))
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any("-enc","IEX","DownloadString","-w hidden","Reflection.Assembly"))
    or (FileName =~ "mshta.exe" and ProcessCommandLine has_any("http","vbscript:","javascript:"))
    or (FileName =~ "regsvr32.exe" and ProcessCommandLine has_any("http","scrobj.dll","/i:"))
    or (FileName =~ "rundll32.exe" and ProcessCommandLine has_any("comsvcs","MiniDump","AppData","Temp"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has_any("process call create","shadowcopy delete","/node:"))
    or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any("/transfer","http","SetNotifyCmdLine"))
)
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
