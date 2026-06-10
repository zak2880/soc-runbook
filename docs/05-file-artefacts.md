# File artefacts

## What you're looking for

Files written, moved, or executed around the infection window tell you how the malware arrived and what it did next.

---

## Executables dropped in suspicious locations

Legitimate software installs to `Program Files`. Be suspicious of executables in:

```
C:\Users\[user]\AppData\Local\Temp\
C:\Users\[user]\AppData\Roaming\
C:\ProgramData\
C:\Windows\Temp\
C:\Users\Public\
```

File types to watch: `.exe`, `.dll`, `.ps1`, `.vbs`, `.bat`, `.hta`, `.js`, `.wsf`

---

## Double extensions and disguised names

```
invoice.pdf.exe        ← real extension is .exe
document.docx.vbs      ← script disguised as Word doc
photo.jpg.js           ← JavaScript disguised as image
a8f3bc2d.exe           ← random alphanumeric = malware-generated name
```

---

## Self-deleting droppers

Pattern: file created → file executed → file deleted. This is malware cleaning up its dropper.

---

## Ransomware signals

| Signal | What to look for |
|--------|-----------------|
| Mass file renames | Hundreds/thousands renamed in seconds — new extension added |
| New file extension | `.locked`, `.enc`, `.crypted`, `.WNCRY`, random suffix across many files |
| Ransom notes | `README.txt`, `HOW_TO_DECRYPT.html` created in multiple folders |
| VSS deletion | `vssadmin delete shadows` or `wmic shadowcopy delete` |
| Recovery disabled | `bcdedit /set {default} recoveryenabled No` |

> ⚠️ VSS deletion = ransomware is imminent or running. Escalate immediately.

---

## Checking a hash

**In Defender XDR** → File page (search by SHA256):
- Global prevalence — how many machines worldwide have seen it
- Tenant prevalence — how many machines in your estate
- Vendor detections

**VirusTotal** — paste the SHA256:
- Detection ratio (45/72 flagging = bad)
- File first seen date — brand new = suspicious
- Confirm file type matches extension

---

## KQL queries

Standalone query files in [kql/files/](../kql/files/).

### Executables dropped in suspicious paths
```kql
DeviceFileEvents
| where DeviceName == "HOSTNAME"
| where ActionType == "FileCreated"
| where FileName endswith_any (".exe", ".dll", ".ps1", ".vbs", ".bat", ".hta")
| where FolderPath has_any ("AppData", "Temp", "ProgramData", "Public")
| where Timestamp > ago(24h)
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName
```

### Ransomware — mass file renames
```kql
DeviceFileEvents
| where DeviceName == "HOSTNAME"
| where ActionType == "FileRenamed"
| where Timestamp > ago(2h)
| summarize RenameCount = count()
    by bin(Timestamp, 1m), InitiatingProcessFileName
| where RenameCount > 20
| order by Timestamp asc
```

### Hash seen across estate
```kql
DeviceFileEvents
| where SHA256 == "PASTE_HASH_HERE"
| where Timestamp > ago(7d)
| summarize Devices = make_set(DeviceName), Count = count()
| project Count, Devices
```
