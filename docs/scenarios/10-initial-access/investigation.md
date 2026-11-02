# Initial access — investigation

## What you're looking for

Initial access is how the attacker got in. Before you can fully understand an incident, you need to trace the execution chain back to T0 — the first malicious event. Without knowing the delivery method, you risk missing other victims and leaving the door open for reinfection.

---

## Common vectors

| Vector | What it looks like | MITRE |
|--------|-------------------|-------|
| Phishing attachment | User opens Office doc, PDF, or archive with malicious content | T1566.001 |
| Phishing link | User clicks link → drive-by download or credential harvest | T1566.002 |
| Malicious macro | Office doc with VBA macro spawning a shell | T1204.002, T1059.005 |
| ISO / IMG / ZIP | Archive containing LNK or executable — bypasses Mark of the Web | T1566.001 |
| Drive-by download | Visiting a compromised site triggers a download | T1189 |
| Valid accounts | Attacker logs in with stolen or brute-forced credentials | T1078 |
| Exposed RDP | RDP directly accessible — brute forced or credential stuffed | T1133 |

---

## Tracing back to T0

### Step 1 — find the earliest malicious event

Open Device Timeline in Defender XDR and scroll back before the alert. Look for the browser download, email attachment being opened, or script being executed that started the chain.

### Step 2 — check what files were created before execution

```kql
// 10 — files created on the device around the first malicious event
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// SHA256 is usually empty in DeviceFileEvents; enrich on SHA1

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceFileEvents
| where DeviceName startswith "HOSTNAME"
| where ActionType == "FileCreated"
| where Timestamp between ((T0 - 1h) .. (T0 + 1h))
| project Timestamp, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

### Step 3 — check browser download history

```kql
// 10 — files written by the browser (download history)
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// SHA256 is usually empty in DeviceFileEvents; enrich on SHA1

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceFileEvents
| where DeviceName startswith "HOSTNAME"
| where InitiatingProcessFileName in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe")
| where ActionType == "FileCreated"
| where FileName matches regex @"(?i)\.(exe|dll|ps1|vbs|bat|hta|js|wsf|cmd|scr|lnk|iso|img|zip|doc|docx|xls|xlsm|pdf)$"
| where Timestamp between ((T0 - 7d) .. (T0 + 1h))
| project Timestamp, FileName, FolderPath, SHA1, SHA256
```

---

## ISO / IMG — Mark of the Web bypass

Files extracted from ISO/IMG containers don't get the Zone.Identifier ADS — macros run without Protected View warning.

```kql
// 10 — processes started from a mounted ISO/IMG (drive letters D: to Z:)
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// Two cases: (a) an executable run straight from the mounted image (its own path is on D:-Z:);
// (b) an LNK on the image launching a system binary from C: whose command line points at D:-Z:
// Mapped network drives and USB volumes also use D:-Z: and will appear as false positives

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where DeviceName startswith "HOSTNAME"
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where InitiatingProcessFileName =~ "explorer.exe"
| where FolderPath matches regex @"(?i)^[D-Z]:\\"
    or (FileName in~ (
            "cmd.exe", "powershell.exe", "wscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe")
        and ProcessCommandLine matches regex @"(?i)\b[D-Z]:\\")
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
```

---

## RDP brute force

```kql
// 10 — RDP brute force against this device, grouped by source IP
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// With Network Level Authentication, failed RDP logons are recorded as Network logons, not
// RemoteInteractive, so both types are counted. Public source IPs only
// VERIFY: LogonType and ActionType strings (Learn describes LogonType but does not list the values):
// DeviceLogonEvents | where Timestamp > ago(7d) | summarize count() by LogonType, ActionType

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceLogonEvents
| where DeviceName startswith "HOSTNAME"
| where Timestamp between ((T0 - 14d) .. (T0 + 1d))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| summarize
    FailedAttempts = countif(ActionType == "LogonFailed"),
    SuccessfulLogons = countif(ActionType == "LogonSuccess"),
    Accounts = make_set(AccountName, 50),
    FirstSeen = min(Timestamp),
    FirstSuccess = minif(Timestamp, ActionType == "LogonSuccess")
    by RemoteIP
| where FailedAttempts > 10 or SuccessfulLogons > 0
| order by SuccessfulLogons desc, FailedAttempts desc
```

---

## Email delivery

See [../12-phishing-email/investigation.md](../12-phishing-email/investigation.md) for the full email investigation workflow.
