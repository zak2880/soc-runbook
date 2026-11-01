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

File types to watch: `.exe`, `.dll`, `.ps1`, `.vbs`, `.bat`, `.hta`, `.js`, `.wsf`, `.cmd`, `.scr`, `.lnk`, `.iso`, `.img`

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
// File artefacts — executables written to suspicious locations
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Legitimate software installs to Program Files, not Temp/AppData/ProgramData/Public
// Any executable created in these paths warrants investigation
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// Remove the device filter to hunt estate-wide
// SHA256 is usually empty in DeviceFileEvents; enrich on SHA1
// Ref: docs/scenarios/05-malicious-file/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceFileEvents
| where DeviceName startswith "HOSTNAME"
| where ActionType == "FileCreated"
| where FileName matches regex @"(?i)\.(exe|dll|ps1|vbs|bat|hta|js|wsf|cmd|scr|lnk|iso|img)$"
| where FolderPath has_any (
    "AppData", "Temp", "ProgramData", "Public")
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| project Timestamp, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName
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
// File artefacts — check if a known-bad hash has appeared on other devices
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Use after identifying a malicious file on one device to check for spread and find patient zero
// SHA256 is usually empty in these tables (Microsoft schema note): paste SHA1 from the Defender
// file page as well. Leave an unknown hash as its placeholder — it then matches nothing
// Zero rows does NOT prove no spread: cross-check the file page "Observed in organization" tab
// Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention
// Ref: docs/scenarios/05-malicious-file/investigation.md, docs/scenarios/01-malware-alert/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
let sha1 = "PASTE_SHA1_HERE";
let sha256 = "PASTE_SHA256_HERE";
union withsource = SourceTable DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents
| where Timestamp between ((T0 - 30d) .. (T0 + 30d))
| where (isnotempty(sha1) and SHA1 =~ sha1) or (isnotempty(sha256) and SHA256 =~ sha256)
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Paths = make_set(FolderPath, 5),
    Tables = make_set(SourceTable)
    by DeviceName
| order by FirstSeen asc
```

### VSS deletion
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "delete shadows", "vssadmin", "wmic shadowcopy delete", "bcdedit /set")
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```
