# Malicious file — investigation

## What you're looking for

Files written, moved, or executed around the infection window tell you how the malware arrived and what it did next. A SHA256 on its own is a starting point — context around it is what matters.

---

## Executables in suspicious locations

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
a8f3bc2d.exe           ← random alphanumeric = malware-generated name
```

---

## Self-deleting droppers

Pattern: file created → process executes it → file deleted. Malware cleaning up its dropper.

---

## Ransomware signals

| Signal | What to look for |
|--------|-----------------|
| Mass file renames | Hundreds renamed per minute — new extension added |
| New extension | `.locked`, `.enc`, random suffix across many files |
| Ransom notes | `README.txt`, `HOW_TO_DECRYPT.html` in multiple folders |
| VSS deletion | `vssadmin delete shadows` — check immediately |

> VSS deletion = ransomware imminent or running. Escalate now.

---

## Hash enrichment

**Defender XDR file page:** tenant prevalence, global prevalence, Microsoft verdict, signer
**VirusTotal:** detection ratio, first seen, malware family, behaviour tab, relations tab

Low global prevalence + no legitimate signer + phishing delivery = strong malicious indicator.

---

## KQL queries

### Executables dropped in suspicious paths
```kql
DeviceFileEvents
| where DeviceName == "HOSTNAME"
| where ActionType == "FileCreated"
| where FileName has_any (".exe", ".dll", ".ps1", ".vbs", ".bat", ".hta")
| where FolderPath has_any ("AppData", "Temp", "ProgramData", "Public")
| where TimeGenerated > ago(24h)
| project TimeGenerated, FileName, FolderPath, SHA256, InitiatingProcessFileName
```

### Ransomware — mass file renames
```kql
DeviceFileEvents
| where DeviceName == "HOSTNAME"
| where ActionType == "FileRenamed"
| where TimeGenerated > ago(2h)
| summarize RenameCount = count(), SampleFiles = make_set(FileName, 5)
    by bin(TimeGenerated, 1m), InitiatingProcessFileName
| where RenameCount > 20
| order by TimeGenerated asc
```

### Hash across estate
```kql
DeviceFileEvents
| where SHA256 == "PASTE_HASH_HERE"
| where TimeGenerated > ago(7d)
| summarize Devices = make_set(DeviceName), Count = count()
| project Count, Devices
```

### VSS deletion
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "delete shadows", "vssadmin", "wmic shadowcopy delete", "bcdedit /set")
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```
