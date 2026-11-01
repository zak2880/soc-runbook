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
EmailEvents
| where SenderFromAddress =~ "attacker@malicious.com"
| where TimeGenerated > ago(7d)
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress,
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
EmailEvents
| where NetworkMessageId == "PASTE_MESSAGE_ID_HERE"
| project TimeGenerated, RecipientEmailAddress,
    DeliveryAction, DeliveryLocation
```

---

## Step 4 — attachment investigation

```kql
EmailAttachmentInfo
| where NetworkMessageId == "PASTE_MESSAGE_ID_HERE"
| project TimeGenerated, FileName, FileType, SHA256,
    MalwareFamily, DetectionMethods
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
UrlClickEvents
| where Url has "SUSPICIOUS_DOMAIN_HERE"
| where TimeGenerated > ago(7d)
| project TimeGenerated, AccountUpn, Url, ActionType,
    IsClickedThrough, IPAddress
```

> `IsClickedThrough = true` = user actively bypassed a Safe Links warning. Note in report.

---

## Step 6 — did the user interact?

```kql
let EmailTime = EmailEvents
| where NetworkMessageId == "PASTE_MESSAGE_ID_HERE"
| project EmailTime = TimeGenerated, RecipientEmailAddress;
DeviceProcessEvents
| join kind=inner EmailTime
    on $left.AccountName == $right.RecipientEmailAddress
| where TimeGenerated between ((EmailTime) .. (EmailTime + 30min))
| project TimeGenerated, DeviceName, FileName,
    ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

## Common patterns

**Thread hijacking** — attacker compromises a mailbox and replies to existing threads. Email arrives from known trusted sender mid-conversation.

**HTML smuggling** — HTML attachment reconstructs malicious file client-side in the browser. MDO often can't scan it.

**QR code phishing (Quishing)** — malicious URL in a QR code image. Safe Links can't scan an image. User scans with phone — no corporate controls.

**Callback phishing** — no malicious link or attachment. Just a fake invoice and a phone number. No technical IOCs in the email.
