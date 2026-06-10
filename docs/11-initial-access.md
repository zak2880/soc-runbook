# Initial access investigation

## What is initial access?

Initial access is how the attacker got in. Before you can fully understand an incident, you need to trace the execution chain back to T0 — the first malicious event. Without knowing the delivery method, you risk missing other victims who received the same payload, leaving the door open for reinfection, and writing an incomplete incident report.

---

## Common initial access vectors

| Vector | What it looks like | MITRE |
|--------|-------------------|-------|
| Phishing attachment | User opens Office doc, PDF, or archive with malicious content | T1566.001 |
| Phishing link | User clicks link → drive-by download or credential harvest page | T1566.002 |
| Malicious macro | Office doc with VBA macro spawning a shell | T1137 |
| ISO / IMG / ZIP delivery | Archive containing LNK or executable — bypasses Mark of the Web | T1566.001 |
| Drive-by download | Visiting a compromised or malicious site triggers a download | T1189 |
| Supply chain | Legitimate software update or installer is trojanised | T1195 |
| Valid accounts | Attacker logs in with stolen or brute-forced credentials | T1078 |
| Exposed RDP | RDP port directly accessible — brute forced or credential stuffed | T1133 |
| Phishing via Teams / Slack | External message with malicious link or attachment | T1566.003 |

---

## Tracing back to T0 — the delivery chain

### Step 1 — find the earliest malicious event

Open the Device Timeline in Defender XDR and scroll back before the alert fired. You're looking for the process or file that started the chain — usually a browser download, an email attachment being opened, or a script being executed.

```kql
DeviceProcessEvents
| where DeviceName == "HOSTNAME"
| where Timestamp between (datetime(YYYY-MM-DDThh:mm) .. datetime(YYYY-MM-DDThh:mm))
| project Timestamp, InitiatingProcessFileName, FileName,
    ProcessCommandLine, FolderPath, AccountName
| order by Timestamp asc
```

### Step 2 — check what files were created just before execution

```kql
DeviceFileEvents
| where DeviceName == "HOSTNAME"
| where ActionType == "FileCreated"
| where Timestamp between (datetime(YYYY-MM-DDThh:mm) .. datetime(YYYY-MM-DDThh:mm))
| project Timestamp, FileName, FolderPath, SHA256,
    InitiatingProcessFileName
| order by Timestamp asc
```

### Step 3 — check browser download history

Browser downloads land in `Downloads/` and create a file event initiated by the browser process. Look for Office docs, ZIPs, ISOs, PDFs, or executables downloaded just before the infection.

```kql
DeviceFileEvents
| where DeviceName == "HOSTNAME"
| where InitiatingProcessFileName in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe")
| where ActionType == "FileCreated"
| where FileName endswith_any (
    ".exe", ".dll", ".zip", ".iso", ".img",
    ".doc", ".docx", ".xls", ".xlsm", ".xlsb",
    ".pdf", ".lnk", ".js", ".vbs", ".hta", ".ps1")
| where Timestamp > ago(24h)
| project Timestamp, FileName, FolderPath, SHA256,
    InitiatingProcessFileName
```

---

## Phishing — email delivery investigation

### Find the email in Defender for Office 365

1. Go to **Security portal → Email & collaboration → Explorer**
2. Search by: sender address, subject line, attachment filename, or SHA256 hash
3. Check: who else received the same email, was it delivered or blocked, did anyone else click?

### Pull the attachment hash and hunt for it

Once you have the attachment SHA256 from the email, check if it landed on any devices:

```kql
DeviceFileEvents
| where SHA256 == "PASTE_HASH_HERE"
| where Timestamp > ago(7d)
| summarize Devices = make_set(DeviceName), Count = count()
| project Count, Devices
```

### Check if the email link was clicked

```kql
DeviceNetworkEvents
| where DeviceName == "HOSTNAME"
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| where RemoteUrl has "SUSPICIOUS_DOMAIN_HERE"
| where Timestamp > ago(24h)
| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessFileName
```

---

## ISO / IMG / ZIP — Mark of the Web bypass

Attackers increasingly deliver payloads inside ISO, IMG, or password-protected ZIP files. Files extracted from these containers do not inherit the Zone.Identifier Alternate Data Stream (Mark of the Web) that triggers Protected View in Office — so macros run without warning.

**What to look for:**
- Virtual drive mounted (ISO/IMG) — look for `explorer.exe` accessing a drive letter that wasn't there before
- LNK file executed from inside the archive or mounted drive
- Process chain: `explorer.exe` → `wscript.exe` / `cmd.exe` / `powershell.exe` from an unusual path

```kql
DeviceProcessEvents
| where DeviceName == "HOSTNAME"
| where InitiatingProcessFileName =~ "explorer.exe"
| where FolderPath matches regex @"[D-Z]:\\"  // mounted drive letters
| where FileName in~ (
    "cmd.exe", "powershell.exe", "wscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe")
| where Timestamp > ago(24h)
| project Timestamp, FileName, FolderPath, ProcessCommandLine
```

---

## Malicious macros

If initial access was via an Office macro, the parent process will be an Office application. The macro execution itself won't always appear as a separate process — look for the child process spawned by the Office app.

**Typical chain:**
```
winword.exe → cmd.exe → powershell.exe -enc ...
excel.exe → wscript.exe → cscript.exe ...
outlook.exe → mshta.exe → http://malicious.com/payload.hta
```

See [02-process-investigation.md](02-process-investigation.md) for the Office-spawning-shells query.

**Check if macros were enabled by the user:**

```kql
DeviceRegistryEvents
| where DeviceName == "HOSTNAME"
| where RegistryKey has "Security\\Trusted Documents"
| where Timestamp > ago(7d)
| project Timestamp, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName
```

---

## Valid accounts / credential-based access

If there's no malware delivery chain and the attacker simply logged in with valid credentials:

**Check for unusual logon times or locations:**

```kql
DeviceLogonEvents
| where AccountName == "USERNAME"
| where Timestamp > ago(30d)
| project Timestamp, DeviceName, LogonType,
    RemoteIP, AccountName, ActionType
| order by Timestamp desc
```

**Check for RDP brute force — many failed logons followed by success:**

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

## Initial access investigation checklist

- [ ] Identified the first malicious event (T0) on the device timeline
- [ ] Determined the delivery method (email / browser / RDP / other)
- [ ] Checked if other devices received the same file or email
- [ ] Checked if any other users clicked the same link or opened the same attachment
- [ ] Confirmed whether the file had Mark of the Web (Protected View) or bypassed it
- [ ] Documented the full delivery chain from initial access to execution
