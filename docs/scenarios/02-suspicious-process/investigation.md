# Suspicious process — investigation

## What you're looking for

A suspicious process alert asks two questions: what started this process, and what did it do? Look at the whole chain (parent, child, grandchild) and decide whether each link has a named, legitimate reason.

Judge a process by more than its name and path:
- A legitimate, signed program can run attacker code. With DLL side-loading the process is a real signed EXE and the malicious code is a DLL placed next to it (see Process name spoofing).
- The parent shown is not always the program that asked for the process (see Hidden parents).
- An encoded or obfuscated command tells you nothing until you decode it (see Decode before you judge).
- Some activity never shows as a new process command line (see What the process data doesn't show).

The [playbook](playbook.md) gives the order of actions. This page explains what you are looking at and how to scope it.

---

## Was it blocked?

Check this before you decide how urgent the alert is.

**Detection status** (alert page). Microsoft defines three values:
- Prevented: the attempted action was avoided; for example, a file wasn't written to disk or executed.
- Blocked: the behaviour ran and was then blocked; for example, a process ran and was terminated.
- Detected: an attack was detected and is possibly still active.

Prevented or Blocked covers the action in that alert only. The processes earlier in the chain (the document, the script host, the command that launched it) may have run. Check them in the Device timeline.

**Attack surface reduction (ASR) events.** Some ASR blocks don't raise an EDR alert (Microsoft lists "Block all Office applications from creating child processes" and "Block process creations originating from PSExec and WMI commands" among them). Check the device's events in Advanced Hunting: `DeviceEvents`, `ActionType` starting with `Asr`, from T0.
- An action type ending in `Blocked` means the rule stopped that action.
- An action type ending in `Audited` means the rule is in audit mode: Microsoft describes it as enabled "as if in Block mode, but without taking action". The action ran.
- Action types for the rules this scenario meets most often: `AsrOfficeChildProcessAudited` / `AsrOfficeChildProcessBlocked` (Office child processes), `AsrPsexecWmiChildProcessAudited` / `AsrPsexecWmiChildProcessBlocked` (PsExec and WMI), `AsrAbusedSystemToolAudited` / `AsrAbusedSystemToolBlocked` (copied or impersonated system tools), `AsrObfuscatedScriptAudited` / `AsrObfuscatedScriptBlocked` (obfuscated scripts).
- Microsoft states the Office child-process rule is enforced only when Office is installed under `%ProgramFiles%` or `%ProgramFiles(x86)%`. No ASR event doesn't mean the rule was on.

---

## Suspicious parent-child chains

| Parent | Spawning | Verdict |
|--------|----------|---------|
| `winword.exe` / `excel.exe` / other Office app | `cmd.exe`, `powershell.exe`, `mshta.exe`, `wscript.exe` | 🔴 Treat as malicious until the document and the command are explained. Check ASR (above). Microsoft notes some line-of-business apps do this legitimately |
| `WmiPrvSE.exe` | `powershell.exe`, `cmd.exe`, `mshta.exe`, a script host | 🔴 Started through WMI, locally or from another host. See Hidden parents |
| `explorer.exe` | `powershell.exe`, `mshta.exe`, `cmd.exe` with a URL or encoded arguments | 🔴 Possible Run-dialog paste ([ClickFix](../13-clickfix/investigation.md)) |
| `explorer.exe` | Random `.exe` from `Temp` or `AppData` | 🔴 Investigate |
| `powershell.exe` | Another `powershell.exe` with `-enc` | 🔴 Suspicious; decode it |
| `svchost.exe` (not from System32) | Anything | 🔴 Fake svchost — malicious |
| `svchost.exe` (from System32) | Script host or LOLBin | 🟠 Find what started it: check scheduled tasks and services ([persistence](../04-persistence-detected/investigation.md)) |
| `winword.exe` | `winword.exe` or `splwow64.exe` | 🟢 Usually benign; still read the command line |
| `services.exe` | `svchost.exe` (from System32) | 🟢 Normal |

### Hidden parents

The parent in the alert is the process Windows recorded as the creator. That is not always the program that wanted the process to run:
- **WMI.** A command run through WMI (`wmic process call create`, `Invoke-CimMethod -ClassName Win32_Process -MethodName Create`, or remote WMI from another host) can show the WMI Provider Host, `WmiPrvSE.exe`, as its parent instead of the script or macro that asked for it. MITRE ATT&CK records intrusions that used `wmiprvse.exe` to run encoded PowerShell, and Microsoft ships an ASR rule for WMI-created processes ("Block process creations originating from PSExec and WMI commands"). Find what called WMI: a macro, a script, or a logon from another device (see the [credential compromise investigation, Remote execution tools](../06-credential-compromise/investigation.md#remote-execution-tools)).
- **Run dialog.** Microsoft's ClickFix analysis notes the Run dialog is part of Windows Explorer (`explorer.exe`). A user who pastes a command into Win+R produces `explorer.exe → powershell.exe`. Use the [ClickFix investigation](../13-clickfix/investigation.md).
- **Parent PID spoofing.** ATT&CK T1134.004: adversaries may spoof the parent process identifier of a new process to evade process monitoring. How Defender for Endpoint shows a spoofed parent is not documented in the pages checked (VERIFY (tenant)). If the parent makes no sense for the command (for example a long-running system process launching a downloader), don't rely on it.

---

## Encoded / obfuscated PowerShell

Flags to look for in `ProcessCommandLine`:

```
-e / -ec / -enc / -EncodedCommand  base64 payload (PowerShell accepts abbreviations)
-nop / -NoProfile              skips profile scripts
-noni / -NonInteractive        no interactive prompt
-w h / -w hidden / -WindowStyle Hidden  hiding from the user
IEX / Invoke-Expression        executes a string as code
DownloadString / DownloadFile / WebClient / Invoke-WebRequest (iwr) / Invoke-RestMethod (irm)   downloads from the internet
Reflection.Assembly::Load      loads .NET in memory (fileless)
FromBase64String               decoding a payload
```

These switches are a reason to decode, not a verdict. Management tools (for example SCCM and Intune scripts) also use `-EncodedCommand`. The verdict comes from what the decoded command does.

Microsoft's ClickFix analysis names `iwr` (`Invoke-WebRequest`) and `irm` (`Invoke-RestMethod`) among the most used PowerShell cmdlets in these attacks. The PowerShell query below doesn't match them (or `DownloadFile`); read the command line yourself.

### Decode before you judge

For `-e`, `-ec`, `-enc` or `-EncodedCommand`:
1. Copy the base64 string from the command line into the ticket.
2. Decode it as **UTF-16LE**, not plain text. Microsoft: the `-EncodedCommand` string "must be formatted using UTF-16LE character encoding". A plain base64 decoder shows a null byte between every character.
   - CyberChef: From Base64, then Decode text (UTF-16LE). Use an offline or company-hosted copy, so the payload isn't sent to a third-party site.
   - PowerShell, on an analysis machine: `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PASTE_BASE64_HERE'))`. This only prints the text.
3. Never run the decoded text, and don't open its URLs in a browser.
4. If the result contains another `FromBase64String`, a compressed stream or `-join`/`-replace` string building, decode that layer too. If you can't get to readable text, record it as "not fully decoded".
5. Record every URL, IP, domain, file name and registry path it contains. These are the IOCs for the network, file and scope checks.

What to look for in the decoded text: a download (`iwr`, `irm`, `DownloadString`, `DownloadFile`, `Start-BitsTransfer`, `curl`), execution of what was downloaded (`IEX`, `Invoke-Expression`, `Start-Process`), in-memory loading (`Reflection.Assembly`, `Load(`), shadow copy or recovery changes, Defender changes (`Set-MpPreference`, exclusions), and any of the [escalation triggers](../../reference/escalation-triggers.md).

The same applies to other encoded content: `certutil -decode` input files, `mshta` with `vbscript:` or `javascript:`, and long obfuscated `cmd /c` strings.

---

## LOLBins quick reference

Full detail → [../07-lolbin-abuse/investigation.md](../07-lolbin-abuse/investigation.md)

| Binary | Abused for | Key red flag |
|--------|-----------|--------------|
| `certutil.exe` | Downloading files, decoding base64 | `-urlcache -f http://...` |
| `mshta.exe` | Running remote VBScript/JScript | Any URL argument |
| `regsvr32.exe` | AppLocker bypass via remote scriptlet | `/i:http://...` + `scrobj.dll` |
| `rundll32.exe` | Credential dumping, proxy execution | `comsvcs.dll` anywhere in the command line (`MiniDump` is the documented export; don't rely on the word) |
| `wmic.exe` | Remote execution, shadow deletion | `process call create`, `shadowcopy delete`, `/node:` |
| `bitsadmin.exe` | Background file download | `/transfer http://...` |

**WMIC is gone from current Windows 11.** Microsoft: "WMIC is removed and is no longer available as a Feature on Demand (FoD) on Windows 11, version 24H2 and above", and it is superseded by PowerShell for WMI. On those devices, no `wmic.exe` hit says nothing about WMI abuse. Look in PowerShell command lines for `Invoke-CimMethod`, `Invoke-WmiMethod`, `Get-CimInstance Win32_ShadowCopy` with `Remove-CimInstance`, and `-ComputerName` (another host). A `wmic.exe` run on a 24H2 or later device is itself unusual.

---

## Process name spoofing

Always check the **full file path**, not just the process name.

| Legitimate | Suspicious — same name, wrong path |
|-----------|-----------------------------------|
| `C:\Windows\System32\svchost.exe` | `C:\Users\user\AppData\Local\Temp\svchost.exe` |
| `C:\Windows\System32\lsass.exe` | `C:\Windows\lssas.exe` (typo) |
| `C:\Windows\explorer.exe` | `C:\Windows\Temp\explorer.exe` |

**The other direction: a real Windows binary under a new name.** Compare `FileName` with `ProcessVersionInfoOriginalFileName` in `DeviceProcessEvents`. A mismatch (for example `update.exe` whose original file name is `PowerShell.EXE`) is a renamed copy. Microsoft's ASR rule "Block use of copied or impersonated system tools" targets this: it blocks copies of `System32` and `SysWOW64` executables that run from other locations, even when they are signed. VERIFY (tenant) the original file name values for system binaries before you rely on a mismatch.

**Signed or not.** The `ProcessVersionInfo*` columns are file version metadata. Microsoft: they "don't indicate whether the created process is digitally signed", and `InitiatingProcessSignerType` describes the parent, not the new process. Join the process's `SHA1` to `DeviceFileCertificateInfo` and read `IsSigned`, `Signer` and `IsTrusted`.

**Side-loading.** A signed EXE in a user-writable folder (`AppData`, `Temp`, `Downloads`, `ProgramData`) is not cleared by its signature. ATT&CK T1574.001: "Side-loading positions both the victim application and malicious payload(s) alongside each other." Check `DeviceImageLoadEvents` for DLLs it loaded from its own folder, and check their signer the same way.

---

## Follow the process

**Link the chain.** Process IDs are reused once a process ends (Microsoft: "you cannot use ProcessID alone to monitor a particular process"). Link a child to its parent on two columns: the child's `InitiatingProcessId` and `InitiatingProcessCreationTime` equal the parent's `ProcessId` and `ProcessCreationTime`. `InitiatingProcessParentFileName` gives the grandparent. The Device timeline and the alert's process tree show the same chain.

The time-window query below doesn't return these columns. When you need them, add `ProcessId, ProcessCreationTime, InitiatingProcessId, InitiatingProcessCreationTime, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ProcessVersionInfoOriginalFileName, SHA1` to its `project` line in your portal.

**What the process did.** `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents` and `DeviceImageLoadEvents` all carry `InitiatingProcessId` and `InitiatingProcessCreationTime`. Filter each to the device and to that pair to list the connections, files, registry changes and DLLs the process caused.
- Network: record remote IPs, domains and ports. `RemoteUrl` is the URL or domain connected to. A connection that network protection blocked can still be logged as `ConnectionSuccess` ([network guide](../03-suspicious-network-activity/investigation.md)).
- Files: record path and SHA1 of every file written. A script, `.hta` or DLL that a LOLBin ran is the payload you collect and later remove ([file guide](../05-malicious-file/investigation.md)).
- Registry: Run keys, services, scheduled-task keys and Winlogon values are persistence ([persistence guide](../04-persistence-detected/investigation.md)).

**Is it still running?** Process events record what started, not what is running now. Use the investigation package's Processes and Network connections folders (state at collection time), then Live Response `processes` ("Shows all processes running on the device") and `connections` ("Shows all the active connections"). A downloader often exits within seconds of fetching its next stage, so "not running" is not "not executed".

---

## Scope across the estate

- **A file the chain dropped or ran (EXE, DLL, script):** run the [hash sweep](../05-malicious-file/investigation.md#hash-across-estate) with its SHA1. SHA256 is usually empty in these tables (Microsoft schema note).
- **A Windows binary (LOLBin):** its hash is on every device, so a hash sweep tells you nothing. Run the PowerShell, Office and LOLBin queries below estate-wide with the same T0, and search the network events for the domains and IPs from the decoded command.
- **The same parent agent on many devices** (for example a remote management tool launching shells) is a reason to scope wider, not evidence that the activity is benign.

---

## What the process data doesn't show

- `ProcessCommandLine` holds the command line that created a process. Commands typed into an open PowerShell window, and cmdlets inside a script run with `-File`, don't create a process, so they don't appear there. An empty result for a cmdlet name isn't "clean".
- Whether `DeviceEvents` records PowerShell commands (for example a `PowerShellCommand` action type) depends on the tenant: VERIFY (tenant) with the in-portal schema reference.
- Nothing in process data shows a user pasting text. Ask the user, through the customer contact, what they were doing: did they open a file, paste a command, or follow someone's instructions?

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

It doesn't return the Office app's own command line (`InitiatingProcessCommandLine`, which may name the open document) and can't see a macro that launched through WMI: the parent is then `WmiPrvSE.exe` (Hidden parents, above). Use the Device timeline for both.

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

On Windows 11 24H2 and later its `wmic.exe` clause can't match (WMIC is removed); WMI abuse through PowerShell isn't covered.

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
