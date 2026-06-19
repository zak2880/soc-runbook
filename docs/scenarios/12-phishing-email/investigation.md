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
DeviceFileEvents
| where SHA256 == "PASTE_HASH_HERE"
| where TimeGenerated > ago(7d)
| summarize Devices = make_set(DeviceName), Count = count()
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
