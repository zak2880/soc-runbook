# Email investigation

## Why email investigation matters at an MSSP

The majority of initial access at the organisations you protect starts with a phishing email. Being fast and thorough with email triage directly impacts how many users get compromised after the first hit. Defender for Office 365 (MDO) gives you deep visibility — but only if you know where to look.

---

## Tools you'll use

| Tool | Where to find it | Used for |
|------|-----------------|----------|
| **Threat Explorer** | Security portal → Email & collaboration → Explorer | Hunting, pivoting, pulling email metadata |
| **Email entity page** | Click any email in Explorer | Full headers, attachments, links, delivery action |
| **Message trace** | Security portal → Exchange admin → Message trace | Confirming delivery status, finding all recipients |
| **Advanced Hunting** | Defender XDR → Hunting | KQL across `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo` |
| **Action center** | Defender XDR → Action center | Checking if ZAP (Zero-hour Auto Purge) fired, manual remediation |

---

## Step 1 — find the email

Start in **Threat Explorer**. Search by whichever IOC you have:

| You have | Search by |
|----------|-----------|
| Sender address | Sender field |
| Subject line | Subject field |
| Attachment filename | Attachment name |
| Attachment hash | File hash |
| URL in the body | URL |
| Recipient device name | Cross-reference via `EmailEvents` in Advanced Hunting |

**KQL — find emails by sender:**

```kql
EmailEvents
| where SenderFromAddress =~ "attacker@malicious.com"
| where Timestamp > ago(7d)
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, DeliveryAction, DeliveryLocation, NetworkMessageId
```

**KQL — find emails by subject:**

```kql
EmailEvents
| where Subject has "Invoice"
| where Timestamp > ago(7d)
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, DeliveryAction, DeliveryLocation, NetworkMessageId
```

---

## Step 2 — check delivery action and location

Every email in MDO has a **DeliveryAction** and **DeliveryLocation**. These tell you whether the email reached the user and where it ended up.

| DeliveryAction | Meaning |
|---------------|---------|
| `Delivered` | Landed in inbox — user may have seen it |
| `Delivered to junk` | Landed in Junk folder |
| `Blocked` | MDO blocked before delivery |
| `Replaced` | Attachment was replaced with a warning |
| `ZapToJunk` / `ZapToDeleted` | Delivered initially, then ZAP moved/deleted it |

> `Delivered` + `ZapToDeleted` = email got through initially but was later pulled. Check whether the user opened it before ZAP fired.

---

## Step 3 — find all recipients

A phishing campaign rarely targets one person. Once you have the `NetworkMessageId` or a sender/subject, sweep for everyone who received the same email.

**KQL — all recipients of the same email (by NetworkMessageId):**

```kql
EmailEvents
| where NetworkMessageId == "PASTE_MESSAGE_ID_HERE"
| project Timestamp, RecipientEmailAddress,
    DeliveryAction, DeliveryLocation
```

**KQL — all recipients from the same sender in the campaign window:**

```kql
EmailEvents
| where SenderFromAddress =~ "attacker@malicious.com"
| where Timestamp > ago(7d)
| summarize
    RecipientCount = dcount(RecipientEmailAddress),
    Recipients = make_set(RecipientEmailAddress),
    DeliveryActions = make_set(DeliveryAction)
    by SenderFromAddress, Subject
```

---

## Step 4 — investigate the attachment

**KQL — attachment details for a specific email:**

```kql
EmailAttachmentInfo
| where NetworkMessageId == "PASTE_MESSAGE_ID_HERE"
| project Timestamp, FileName, FileType, SHA256,
    MalwareFamily, DetectionMethods
```

**KQL — hunt for the same attachment hash across all emails:**

```kql
EmailAttachmentInfo
| where SHA256 == "PASTE_HASH_HERE"
| where Timestamp > ago(7d)
| join kind=inner EmailEvents on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    FileName, SHA256, DeliveryAction
```

**KQL — check if the attachment landed on any devices:**

```kql
DeviceFileEvents
| where SHA256 == "PASTE_HASH_HERE"
| where Timestamp > ago(7d)
| summarize Devices = make_set(DeviceName), Count = count()
```

---

## Step 5 — investigate URLs

**KQL — all URLs in a specific email:**

```kql
EmailUrlInfo
| where NetworkMessageId == "PASTE_MESSAGE_ID_HERE"
| project Url, UrlDomain, ClickCount
```

**KQL — check if anyone clicked a malicious URL:**

```kql
UrlClickEvents
| where Url has "SUSPICIOUS_DOMAIN_HERE"
| where Timestamp > ago(7d)
| project Timestamp, AccountUpn, Url, ActionType,
    IsClickedThrough, IPAddress, Workload
```

> `IsClickedThrough = true` = the user clicked through a Safe Links warning. This means they actively bypassed the warning — note it in your report.

**KQL — all URL clicks that bypassed Safe Links:**

```kql
UrlClickEvents
| where ActionType == "ClickAllowed"
| where IsClickedThrough == true
| where Timestamp > ago(7d)
| project Timestamp, AccountUpn, Url, IPAddress
```

---

## Step 6 — check if the user interacted with the email

Cross-reference email delivery time with device activity. Did anything suspicious happen on the device shortly after the email arrived?

```kql
let EmailTime = EmailEvents
| where NetworkMessageId == "PASTE_MESSAGE_ID_HERE"
| project EmailTime = Timestamp, RecipientEmailAddress;
DeviceProcessEvents
| join kind=inner EmailTime
    on $left.AccountName == $right.RecipientEmailAddress
| where Timestamp between (
    (EmailTime) .. (EmailTime + 30min))
| project Timestamp, DeviceName, FileName,
    ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

---

## Step 7 — remediation

Once you've confirmed the email is malicious:

**Soft delete from all mailboxes (requires appropriate permissions):**
- Threat Explorer → select the email → Actions → Delete → Soft delete

**Hard delete if required:**
- Action center → submit for manual remediation

**Block the sender:**
- Security portal → Policies & rules → Threat policies → Tenant Allow/Block List → Add sender to block list

**Block the URL:**
- Tenant Allow/Block List → URLs → Add URL

**Block the file hash:**
- Tenant Allow/Block List → Files → Add SHA256

---

## Phishing investigation checklist

- [ ] Found the email in Threat Explorer
- [ ] Confirmed delivery action — did it reach the inbox?
- [ ] Found all recipients — how many people got it?
- [ ] Checked whether ZAP fired — if so, did it fire before or after the user opened it?
- [ ] Investigated the attachment — SHA256, malware family, device hits
- [ ] Investigated URLs — was Safe Links triggered, did anyone click through?
- [ ] Cross-referenced email delivery time with device process activity
- [ ] Confirmed whether the user executed anything
- [ ] Blocked sender / URL / hash in Tenant Allow/Block List
- [ ] Soft or hard deleted from all affected mailboxes

---

## Common patterns to recognise

### Thread hijacking
Attacker compromises a mailbox and replies to existing email threads with a malicious attachment. The email arrives from a known, trusted sender mid-conversation. Users almost always open it. Red flags: reply-to address differs from sender, attachment is unexpected for the conversation context.

### HTML smuggling
The email body contains an HTML attachment or inline HTML that uses JavaScript to reconstruct a malicious file client-side — the payload never exists on the wire, only in the browser's memory. MDO often can't scan it. Red flags: HTML attachment that creates a download on open, ISO or ZIP files appearing from an HTML email.

### QR code phishing (Quishing)
Malicious URL is embedded in a QR code image in the email body. Safe Links can't scan an image. The user scans with their phone — which has no corporate security controls. Red flags: email with only an image attachment and a prompt to scan, no text content.

### Callback phishing
Email contains no malicious link or attachment — just a phone number and a fake invoice or subscription renewal notice. The user calls the number, gets social engineered into installing remote access software. No technical IOCs in the email itself.
