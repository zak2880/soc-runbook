# Initial access — investigation

## What you're looking for

Initial access is how the attacker got in. Before you can fully understand an incident, you need to trace the execution chain back to T0 — the first malicious event. Without knowing the delivery method, you risk missing other victims and leaving the door open for reinfection.

---

## Common vectors

| Vector | What it looks like | MITRE |
|--------|-------------------|-------|
| Phishing attachment | User opens Office doc, PDF, or archive with malicious content | T1566.001 |
| Phishing link | User clicks link → drive-by download or credential harvest | T1566.002 |
| Malicious macro | Office doc with VBA macro spawning a shell | T1137 |
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
DeviceFileEvents
| where DeviceName == "HOSTNAME"
| where ActionType == "FileCreated"
| where Timestamp between (datetime(YYYY-MM-DDThh:mm) .. datetime(YYYY-MM-DDThh:mm))
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

### Step 3 — check browser download history

```kql
DeviceFileEvents
| where DeviceName == "HOSTNAME"
| where InitiatingProcessFileName in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe")
| where ActionType == "FileCreated"
| where FileName endswith_any (
    ".exe", ".dll", ".zip", ".iso", ".img",
    ".doc", ".docx", ".xls", ".xlsm",
    ".pdf", ".lnk", ".js", ".vbs", ".hta", ".ps1")
| where Timestamp > ago(24h)
| project Timestamp, FileName, FolderPath, SHA256
```

---

## ISO / IMG — Mark of the Web bypass

Files extracted from ISO/IMG containers don't get the Zone.Identifier ADS — macros run without Protected View warning.

```kql
DeviceProcessEvents
| where DeviceName == "HOSTNAME"
| where InitiatingProcessFileName =~ "explorer.exe"
| where FolderPath matches regex @"[D-Z]:\\"
| where FileName in~ (
    "cmd.exe", "powershell.exe", "wscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe")
| where Timestamp > ago(24h)
| project Timestamp, FileName, FolderPath, ProcessCommandLine
```

---

## RDP brute force

```kql
DeviceLogonEvents
| where DeviceName == "HOSTNAME"
| where LogonType == "RemoteInteractive"
| where Timestamp > ago(24h)
| summarize
    FailedAttempts = countif(ActionType == "LogonFailed"),
    SuccessfulLogons = countif(ActionType == "LogonSuccess"),
    SourceIPs = make_set(RemoteIP)
    by AccountName
| where FailedAttempts > 10
| order by FailedAttempts desc
```

---

## Email delivery

See [../12-phishing-email/investigation.md](../12-phishing-email/investigation.md) for the full email investigation workflow.
