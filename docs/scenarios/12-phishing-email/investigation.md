# Phishing email — investigation

## Tools you'll use

| Tool | Where | Used for |
|------|-------|----------|
| Threat Explorer | Security portal → Email & collaboration → Explorer | Hunting, pivoting, pulling metadata |
| Email entity page | Click any email in Explorer | Headers, attachments, links, delivery action |
| Message trace | Exchange admin → Message trace | Confirming delivery, finding all recipients |
| Advanced Hunting | Defender XDR → Hunting | KQL across EmailEvents, EmailAttachmentInfo, EmailUrlInfo |
| Action center | Defender XDR → Action center | ZAP status, manual remediation |

---

## Step 1 — find the email

Search Threat Explorer by whichever IOC you have: sender, subject, attachment filename, SHA256, URL.

```kql
// 12 — find the email by sender
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
EmailEvents
| where SenderFromAddress =~ "attacker@malicious.com"
| where Timestamp between ((T0 - 7d) .. (T0 + 1d))
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, DeliveryAction, DeliveryLocation, NetworkMessageId
```

---

## Step 2 — delivery action

| DeliveryAction | Meaning |
|---------------|---------|
| `Delivered` | Reached inbox — user may have seen it |
| `Delivered to junk` | Landed in Junk |
| `Blocked` | MDO blocked before delivery |
| `ZapToDeleted` | Delivered then pulled by ZAP — check if user opened it first |

---

## Step 3 — all recipients

```kql
// 12 — every recipient of this message
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
EmailEvents
| where NetworkMessageId == "PASTE_MESSAGE_ID_HERE"
| project Timestamp, RecipientEmailAddress,
    DeliveryAction, DeliveryLocation
```

---

## Step 4 — attachment investigation

```kql
// 12 — attachments on this message
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// SHA256 is usually empty in this table (Microsoft schema note) and the table has no SHA1 column:
// take the hash from the email entity page
EmailAttachmentInfo
| where NetworkMessageId == "PASTE_MESSAGE_ID_HERE"
| project Timestamp, FileName, FileType, FileSize, SHA256,
    ThreatTypes, ThreatNames, DetectionMethods
```

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

---

## Step 5 — URL / Safe Links

```kql
// 12 — clicks on the suspicious domain
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
UrlClickEvents
| where Url has "SUSPICIOUS_DOMAIN_HERE"
| where Timestamp between ((T0 - 1d) .. (T0 + 7d))
| project Timestamp, AccountUpn, Url, ActionType,
    IsClickedThrough, IPAddress
```

> `IsClickedThrough = true` = user actively bypassed a Safe Links warning. Note in report.

---

## Step 6 — did the user interact?

```kql
// 12 — did anyone who clicked a link in this email run something afterwards?
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Anchored on each click, not on delivery: processes from 5 minutes before to 60 minutes after the click
// T0 = delivery time; clicks are searched from T0-1h to T0+7d
// No result here does NOT rule out credential phishing; check the clicker's sign-ins (06)

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
let Clicks = UrlClickEvents
| where Timestamp between ((T0 - 1h) .. (T0 + 7d))
| where NetworkMessageId == "PASTE_MESSAGE_ID_HERE"
| project ClickTime = Timestamp, Upn = tolower(AccountUpn), Url, ActionType, IsClickedThrough;
let Clickers = Clicks | distinct Upn;
DeviceProcessEvents
| where Timestamp between ((T0 - 1h) .. (T0 + 7d + 1h))
| extend Upn = tolower(AccountUpn)
| where Upn in (Clickers)
| join kind=inner Clicks on Upn
| where Timestamp between ((ClickTime - 5m) .. (ClickTime + 60m))
| where InitiatingProcessFileName in~ ("outlook.exe", "msedge.exe", "chrome.exe", "firefox.exe",
    "winword.exe", "excel.exe", "powerpnt.exe")
| project Timestamp, ClickTime, DeviceName, AccountUpn, InitiatingProcessFileName,
    FileName, ProcessCommandLine, Url
| order by Timestamp asc
```

---

## Common patterns

**Thread hijacking** — attacker compromises a mailbox and replies to existing threads. Email arrives from known trusted sender mid-conversation.

**HTML smuggling** — HTML attachment reconstructs malicious file client-side in the browser. MDO often can't scan it.

**QR code phishing (Quishing)** — malicious URL in a QR code image. Safe Links can't scan an image. User scans with phone — no corporate controls.

**Callback phishing** — no malicious link or attachment. Just a fake invoice and a phone number. No technical IOCs in the email.
