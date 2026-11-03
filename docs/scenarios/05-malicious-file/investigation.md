# Malicious file — investigation

## What you're looking for

A suspicious file has turned up: from an alert, a hunting query or a user report. Answer these in order: is ransomware involved, was the file stopped, did it run, how did it arrive, and has it spread. A hash on its own is a starting point; the context around it decides the verdict.

The [playbook](playbook.md) says what to do and in what order. This page explains what to look at and how to read it. Don't quarantine, delete or block anything from this page.

**Arriving from another guide** (for example step 15 of the [malware alert playbook](../01-malware-alert/playbook.md), or the [suspicious process investigation](../02-suspicious-process/investigation.md)): for each file, record its path and SHA1, whether it ran ([Did it run?](#did-it-run)) and how it arrived ([How did it arrive?](#how-did-it-arrive)). Then go back to that playbook. Its own steps preserve the file before anything removes it. If you see a ransomware signal ([Ransomware signals](#ransomware-signals)), escalate now and contain the device, whichever playbook you are in.

---

## Was it already stopped?

- Read the alert's detection status. Microsoft defines three values:
  - Prevented: the action was avoided; for example, the file wasn't written to disk or executed.
  - Blocked: the behaviour ran and was then blocked; for example, a process ran and was terminated.
  - Detected: an attack was detected and is possibly still active.
- Prevented or Blocked covers the detected file only. The process that wrote it may still be running, and other files it wrote may not be detected.
- A hunting hit or a user report has no detection status. Nothing has stopped it until you check.

---

## Executables in suspicious locations

Software usually installs to `Program Files`, but many per-user applications and updaters also run from `AppData`. A file in one of these folders is a reason to look, not a verdict:
```
C:\Users\[user]\AppData\Local\Temp\
C:\Users\[user]\AppData\Roaming\
C:\ProgramData\
C:\Windows\Temp\
C:\Users\Public\
```

File types to watch: `.exe`, `.dll`, `.ps1`, `.vbs`, `.bat`, `.hta`, `.js`, `.wsf`, `.cmd`, `.scr`, `.lnk`, `.iso`, `.img`

Microsoft supports file hash indicators and Deep analysis for PE files only, naming `.exe` and `.dll`. A script, shortcut or disk image can't be blocked by its hash; block the URL or domain it came from.

---

## Double extensions and disguised names

```
invoice.pdf.exe        ← real extension is .exe
document.docx.vbs      ← script disguised as Word doc
a8f3bc2d.exe           ← random name: a weak signal on its own
```

- Double extension: ATT&CK states the second extension is the true file type, and the operating system may hide it in the file browser.
- Right-to-left override: an invisible Unicode character (U+202E) shows the text after it reversed. ATT&CK's example is a screensaver executable that displays as `March 25 rcs.docx`. A "document" that appears in `DeviceProcessEvents` ran as a program; treat its name as disguised.
- Random names: installers and updaters also unpack files with random or GUID names into `Temp`. A random name adds weight to other signals; it is not a verdict.

---

## Did it run?

- Run the [hash sweep](#hash-across-estate) and read `Tables` for this device. `DeviceProcessEvents` = it ran as a process. `DeviceImageLoadEvents` = it was loaded as a DLL. Only `DeviceFileEvents` = no recorded execution of that hash.
- The file page → Observed in organization → Devices shows the file's execution status on each device.
- A script, shortcut or document doesn't run as its own process. In the Device timeline from T0, look for a process whose command line (`ProcessCommandLine`) contains the file name, for example a script host or an Office app.
- An empty SHA1 returns nothing. Microsoft notes hashes are empty when the file is on remote storage, locked by another process, compressed or marked as virtual. Use the Device timeline instead.

---

## How did it arrive?

Read the file's creation event in `DeviceFileEvents` (Device timeline, or Advanced Hunting with the file name and device). The executables query below doesn't return these columns.

- **Web download:** `FileOriginUrl` (where it was downloaded from), `FileOriginReferrerUrl` (the page that linked to it) and `FileOriginIP`.
- **Network share:** `RequestProtocol` is `SMB` or `NFS`. `RequestSourceIP` and `RequestAccountName` name the remote device and account that wrote it; `ShareName` names the share. An internal `RequestSourceIP` means another device in the estate wrote the file here: that device is in scope, and this is possible lateral movement.
- **Email:** the writer is a mail client. Use Explorer in Defender for Office 365 and the [phishing email investigation](../12-phishing-email/investigation.md).
- **The writer:** `InitiatingProcessFileName`, `InitiatingProcessCommandLine` and `InitiatingProcessParentFileName`. A browser, mail client or archive tool is ordinary. A script host, LOLBin or unknown binary means an earlier stage ran; use the [suspicious process investigation](../02-suspicious-process/investigation.md).
- **None of these:** record the vector as unknown. Don't assume email.

---

## Is it still on disk?

`DeviceFileEvents` is history; it doesn't show what is on disk now.

- Live Response `fileinfo` with the full path gets information about the file. `findfile` with the file name locates it anywhere on the device. Both are basic Live Response commands.
- The file page → Observed in organization lists each device with its first and last seen events.
- Not on disk doesn't mean gone: it may have been moved, renamed, or deleted after it ran (below).

---

## Self-deleting droppers

Pattern: file created → a process runs it → the file is deleted. Malware removing its dropper to hide what ran.

- In the Device timeline from T0, search the file name: a creation, a process started from it, then a deletion of the same path.
- Check the Action center (History) first. If Defender quarantined or removed it, it didn't delete itself.
- A file that deleted itself after running is treated as malicious; escalate. It can't be collected from the device. Check whether the file page offers Download file (Defender already holds a copy). If not, record that.

---

## Ransomware signals

| Signal | What to look for |
|--------|-----------------|
| Mass file renames | Many files renamed within minutes, often with a new or appended extension. ATT&CK says files are "often" renamed, not always, and some ransomware encrypts only part of each file. A lower rate or no extension change doesn't clear it |
| New extension | `.locked`, `.enc`, random suffix across many files |
| Ransom notes | The same file name (for example `README.txt`, `HOW_TO_DECRYPT.html`) created in many folders. No query in this repo covers it; check the Device timeline. VERIFY (tenant): that `.txt` and `.html` creations are recorded |
| Shadow copies or the backup catalog deleted | `vssadmin delete shadows`, `wmic shadowcopy delete`, `vssadmin resize shadowstorage`, `wbadmin delete catalog`, `diskshadow`, or PowerShell removing `Win32_ShadowCopy` |
| Recovery turned off | `bcdedit` setting `recoveryenabled No` |

> Any of these = ransomware may be running or about to run. Escalate now and contain the device (playbook step 1).

- **File shares:** ATT&CK notes ransomware encrypts local and remote drives. When a file server onboarded to Defender is encrypted over the network, its rename events carry `RequestProtocol` `SMB`, and `RequestSourceIP` and `RequestAccountName` name the encrypting device and account (VERIFY (tenant)). Contain that device, not the file server. The renames query below groups by process name only and doesn't show these columns; read them on one renamed file's event.
- **Shadow copies:** the VSS query matches any `vssadmin` or `bcdedit /set` command, including read-only ones such as `vssadmin list shadows`, so read each command line. It doesn't cover `wbadmin`, `diskshadow` or PowerShell, and ATT&CK documents deletion through the Volume Shadow Copy COM interface, which leaves no telling command line. A clean result doesn't prove shadow copies are intact.
- **Backup software** also deletes old snapshots. Don't close a shadow-copy deletion as backup activity yourself; escalate and let the IR lead confirm it.

---

## Hash enrichment

**Defender file page**
- Shows the Microsoft Defender Antivirus detection, the VirusTotal detection ratio, the number of devices where the file was seen in the last 30 days (with first and last seen in the organization), its prevalence outside the organization, and the file names it used.
- The device count follows your role-based access scope. If you can see only some device groups, you will under-count spread.
- Observed in organization shows up to six months of history per device.
- File content and capabilities (file writes, file deletes, network activity) appear only if Microsoft analysed the file, and cover PE files.
- Signer: look up the SHA1 in `DeviceFileCertificateInfo` (`Signer`, and `IsTrusted`, the WinVerifyTrust result). Version information such as company name is not a signature.

**Deep analysis** (file page) runs the file in a secure cloud sandbox and lists its behaviours and observables, including contacted IPs and files created on disk. PE files only. It needs the sample in Defender's sample collection (Collect file first). Analysis takes several minutes, and Microsoft notes up to 10 minutes' latency between submission and the feature being available.

**VirusTotal: search by hash only. Never upload the file.** VirusTotal states that the contents of submitted files may be shared with its premium customers, and that scan reports are shared with the public community. An upload can tell the attacker their file was found, and a document may hold customer data. Upload only with the IR lead's approval.

**Reading the result**
- Low global prevalence + no trusted signer + phishing delivery = strong malicious indicator.
- The reverse does not hold. Signed, widely seen and 0 VirusTotal detections doesn't make a file benign, and neither does a missing VirusTotal report. Attackers install legitimate remote-access tools (ATT&CK T1219 Remote Access Tools; for example, Akira used AnyDesk).
- Treat a remote-access, remote-management or file-transfer tool (for example AnyDesk, ScreenConnect, rclone) as malicious until the customer confirms it with a change record or an approved-software entry. Also check what wrote it ([How did it arrive?](#how-did-it-arrive)) and whether it made outbound connections soon after it was written.
- Stop and Quarantine File can't act on a file signed by Microsoft or a trusted non-Microsoft publisher, so a signed tool goes to the IR lead (playbook).

---

## KQL queries

### Executables dropped in suspicious paths

- `FolderPath has_any ("AppData", ...)` matches every per-user application under `AppData`. Expect noise; judge each hit on its writer, origin and signer, not its folder.
- It matches `FileCreated` only. A file renamed or moved into place may not appear; check the Device timeline.
- It doesn't return `FileOriginUrl`, the `Request*` columns or the writer's command line ([How did it arrive?](#how-did-it-arrive)).
- Remove the device filter to look for the same file name or folder pattern on other devices.

```kql
// File artefacts — executables written to suspicious locations
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: n/a (triage)
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

- One device, from T0 − 1h to T0 + 4h. If the alert is older than that, run it again with T0 set to one hour ago to see current activity.
- It groups by process name only. It doesn't test for a new extension and doesn't show `RequestSourceIP` (see File shares above).
- The threshold of 20 renames a minute is a starting value, not a tuned one. Fewer renames with new extensions still count. Zero rows doesn't clear in-place encryption.

```kql
// Ransomware detection — mass file rename activity
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1486
// Ransomware renames/re-extensions hundreds of files per minute during encryption
// Threshold: >20 renames per minute from a single process — tune for your environment
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// Remove the device filter to monitor estate-wide
// Ref: docs/scenarios/05-malicious-file/investigation.md, docs/reference/escalation-triggers.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceFileEvents
| where DeviceName startswith "HOSTNAME"
| where ActionType == "FileRenamed"
| where Timestamp between ((T0 - 1h) .. (T0 + 4h))
| summarize
    RenameCount = count(),
    SampleFiles = make_set(FileName, 5)
    by bin(Timestamp, 1m), InitiatingProcessFileName
| where RenameCount > 20
| order by Timestamp asc
```

### Hash across estate

- Paste the SHA1 from the file page; SHA256 is usually empty.
- One row per device, earliest `FirstSeen` first. The earliest device is the patient-zero candidate. If its `FirstSeen` is before T0, move T0 and rerun.
- `Tables` shows whether the file only landed (`DeviceFileEvents`) or ran (`DeviceProcessEvents`, `DeviceImageLoadEvents`) on each device.
- Zero rows doesn't prove no spread: the hash can be empty, and a per-device variant has a different hash. Check the file page's Observed in organization tab (your access scope limits it), and run the executables query without the device filter for the same file name or folder pattern.
- More devices is a reason to scope wider and escalate, never evidence that the file is benign.

```kql
// File artefacts — check if a known-bad hash has appeared on other devices
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: n/a (triage)
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

- Estate-wide, from T0 − 24h to T0 + 24h. Read each command line: a read-only `vssadmin` or `bcdedit` command also matches.
- It doesn't cover `wbadmin`, `diskshadow`, PowerShell or the COM interface ([Ransomware signals](#ransomware-signals)). Check the Device timeline for those.

```kql
// Ransomware pre-cursor — VSS and shadow copy deletion
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1490
// Attackers destroy backups before deploying ransomware to prevent recovery
// Seeing these commands = ransomware is imminent or already running — escalate immediately
// Ref: docs/reference/escalation-triggers.md, docs/scenarios/05-malicious-file/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "delete shadows",
    "resize shadowstorage",
    "vssadmin",
    "wmic shadowcopy delete",
    "bcdedit /set")
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| project Timestamp, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
```
