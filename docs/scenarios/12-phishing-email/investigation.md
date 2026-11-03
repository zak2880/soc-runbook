# Phishing email — investigation

## What you're looking for

Two questions decide severity, and neither is answered by finding the email:
- Did anyone interact? A click, an attachment written to disk or run, credentials entered on a page, a call to a phone number.
- Did it lead to compromise? A payload that ran, an attacker sign-in, changes to the mailbox, mail sent from the victim's account.

A third decides the containment scope: how far the campaign reached, not just this one message.

T0 = delivery time of the first message in the campaign, in UTC. Advanced Hunting holds 30 days of native data, and Explorer searches up to 30 days back; older activity needs Sentinel retention.

---

## Tools you'll use

| Tool | Where | Used for |
|------|-------|----------|
| Threat Explorer (Defender for Office 365 Plan 2) or Real-time detections (Plan 1) | Defender portal → Email & collaboration → Explorer | Hunting, campaign scope, URL clicks. Moving and deleting mail needs Threat Explorer (Plan 2) |
| Email entity page | Explorer → select the subject → Open email entity | Headers, authentication results, attachments (with SHA256), URLs, detonation results, original and latest delivery location, Download email |
| Message trace | Defender portal → Message trace | Confirming delivery; mail a compromised sender sent |
| Advanced Hunting | Defender XDR → Hunting | KQL across EmailEvents, EmailAttachmentInfo, EmailUrlInfo, EmailPostDeliveryEvents, UrlClickEvents |
| Submissions | Defender portal → Actions & submissions → Submissions | User reported tab: who else reported it. Submitting to Microsoft |
| Action center | Defender portal → Actions & submissions → Action center | Pending: email remediation waiting for approval. History: the result of each remediation (ZAP results are in Explorer and EmailPostDeliveryEvents, not here) |
| Entra admin center | Sign-in logs; ID Protection → Risk detections | Sign-ins and risk after a click |

Automated investigation (AIR) still runs for email in Defender for Office 365 Plan 2. Microsoft retired it on 1 September 2026 for Defender for Endpoint only. An automated investigation can start from a ZAP, a user report or a click alert, and can queue a soft delete for approval. For malicious URL and file clusters it approves its own remediation, so a message may already be gone from mailboxes. Check the Action center and the message's Latest delivery location before you act.

---

## Step 1 — find the email

Search Threat Explorer by whichever IOC you have: sender, subject, attachment filename, SHA256, URL. Open the email entity page and record:
- Network message ID and Internet message ID
- Sender address (the From header) and Sender MAIL FROM address (the envelope sender)
- Directionality (Inbound, Intra-org, Outbound) and Time received
- Original and Latest delivery location, Detection technology, Original and Latest threats
- DMARC, DKIM, SPF and Composite authentication (Analysis view → Authentication)
- Cluster ID, Campaign ID, and the Tags section (a Priority account tag on a recipient matters later)

The query below matches the From address only (`SenderFromAddress`). Replace the example address with yours before running; left as it is, it returns nothing. For spoofed or lookalike mail, also search the envelope sender (`SenderMailFromAddress`).

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

**Who sent it?** The answer changes what you block (playbook step 9).

| What you see | Likely case | Where it leads |
|---|---|---|
| Sender in the customer's own domain, Directionality Intra-org, no spoof detection | Internal mailbox compromised (BEC) | Step 8. Don't block the sender |
| From domain differs from the MAIL FROM domain, DMARC fails, or Detection technology shows Spoof DMARC, Spoof external domain or Spoof intra-org | Spoofed From address | Block on the Spoofed senders tab, not the address |
| A known partner's domain, authentication passes, a reply inside an existing thread | Partner mailbox possibly compromised (thread hijacking) | Step 8. Don't block the sender |
| A domain unrelated to the customer or its partners, often newly registered or a lookalike | Attacker-owned sender | The sender can be blocked |

Passing authentication doesn't make a message safe: a compromised mailbox sends authenticated mail.

---

## Step 2 — delivery action

`DeliveryAction` is the action at delivery time. Microsoft documents four values:

| DeliveryAction | Meaning |
|---------------|---------|
| `Delivered` | Reached the mailbox. `DeliveryLocation` says where (for example Inbox/Folder or Deleted items) |
| `Junked` | Reached the Junk Email folder. It is still in the mailbox |
| `Blocked` | Not delivered to the mailbox. `DeliveryLocation` says where it went (for example Quarantine) |
| `Replaced` | Microsoft lists this value without a description. Read the entity page before deciding |

**Where is it now?** Delivery-time values don't show what happened afterwards.
- Email entity page → Latest delivery location: the location after ZAP or an admin action. It doesn't show user actions (the user moving or deleting it), so it isn't a guarantee of the current location.
- Advanced Hunting: `LatestDeliveryLocation` and `LatestDeliveryAction` on `EmailEvents`. These columns aren't in the Streaming API, so they are missing in Sentinel.
- `EmailPostDeliveryEvents`: `ActionType` "Phish ZAP", "Malware ZAP" or "Manual remediation", with the time.
- Entity page → Timeline view lists ZAP and admin actions in order.

**ZAP is not a verdict.** ZAP only searches the last 48 hours of delivered mail. "ZAP didn't act" doesn't mean the message is clean, and for an older message nothing will move it unless you do.

**"Opened" can't be seen.** No tool here records that a user opened or read a message. Purview `MailItemsAccessed` records access, but Microsoft notes it logs an access "even though there's no indication that the mail item was read", and desktop Outlook sync is logged per folder. Use what can be seen: a click (Step 5), the attachment written or run on a device (Steps 4 and 6), and sign-ins after a click (Step 7).

---

## Step 3 — all recipients and the rest of the campaign

The query below lists the recipients of one Network message ID. Microsoft describes that ID only as a unique identifier for the email; it doesn't say whether every recipient of one send shares it. VERIFY (tenant): compare the query's recipient count with the To and Cc on the entity page.

A campaign can also arrive as many separate messages, with rotated subjects, senders or URLs, each with its own ID. Scope the campaign, not the message:
- Explorer → Campaigns view (Plan 2): messages Defender grouped as one coordinated campaign.
- Entity page → Similar emails: other messages with the same body fingerprint.
- Explorer → All email filters, over the last 30 days: Sender domain and Sender mail from domain, URL domain, Attachment filename or Attachment SHA256, Cluster ID or Campaign ID. Cluster ID (`EmailClusterId` in Advanced Hunting) is Microsoft's group of similar emails.
- Submissions → User reported: who else reported it.

For each message, record every recipient and its Latest delivery location. A message in Inbox, Junk or Deleted items is still in the mailbox and can still be clicked.

Many recipients means a wider scope. It is never a reason to close.

Priority accounts: the entity page Tags section, or `Context` "Priority Account Protection" on `EmailEvents`. Record any priority or admin recipient.

In Sentinel, the streamed `EmailEvents` has a new row each time a message's verdict or location changes, so the same recipient can appear several times. Add `| summarize arg_max(TimeGenerated, *) by NetworkMessageId, RecipientEmailAddress` before counting. The query shows the delivery-time location only; use Step 2 for where each copy is now.

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

**The attachment's hash.** `SHA256` in `EmailAttachmentInfo` is usually empty. Take it from the email entity page → Attachments view → Attachment SHA256. The Deep analysis tab (when Safe Attachments detonated the file) shows the detonation chain, the verdict and behaviour details with URLs, IPs and files; export them. Containers such as ZIP or RAR may show no screenshots or behaviour.

**Enrichment.** Look the SHA256 up on VirusTotal by hash. Don't upload the file: VirusTotal's own documentation contrasts its paid Private Scanning with the standard service, which shares uploads with third parties, and an attachment can hold the customer's data.

**Did it reach a device?** The device tables usually have no SHA256 either, so the attachment's SHA256 rarely finds the file on a device. Instead:
1. On each recipient's device timeline, search for the attachment's file name from T0 onward.
2. When you find the file, open its file page and copy the SHA1.
3. Run the hash sweep below with that SHA1.

For ZIP, ISO or HTML attachments, the file that runs is not the attachment and has a different hash. Look at what the archive tool or browser wrote after the attachment was opened, and at `FileOriginUrl` and `FileOriginReferrerUrl` on downloaded files. The sweep's `Paths` column shows where each copy landed (an Outlook temporary folder or Downloads, for example).

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

---

## Step 5 — URL / Safe Links

**List the URLs first.** Email entity page → URL view shows every original or rewritten URL with its threat verdict and any detonation. In Advanced Hunting, `EmailUrlInfo` by `NetworkMessageId` gives `Url`, `UrlDomain` and `UrlLocation`, which says where the URL was (body, attachment, or `QRCode` for a URL extracted from a QR code).

**Enrichment.** Submit a URL to URLScan only with Unlisted or Private visibility. Public scans appear on urlscan.io's front page and public search; urlscan advises Unlisted when a page might contain PII. A phishing URL can carry the recipient's address or a per-target token: remove those parts first. Don't open the URL in your own browser.

**Who clicked.** The query below finds clicks by domain. Step 6 filters on `NetworkMessageId` instead, which catches clicks on every URL in the message. Read these columns:
- `ActionType`: whether Safe Links or a tenant policy allowed or blocked the click.
- `IsClickedThrough`: see the note below the query.
- `Workload`: Email, Office or Teams. A Teams lure shows up here too.
- `UrlChain`: the redirect chain.

`UrlClickEvents` holds Safe Links clicks. A URL the user copied or typed, or opened on a phone from a QR code, may leave no row. No row is not proof that nobody clicked: ask the recipients.

The window runs from T0 − 1 day to T0 + 7 days. If delivery was earlier or clicks may be later, move T0.

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

The query below returns processes started by Outlook, a browser or an Office app from 5 minutes before to 60 minutes after each click on this message. It doesn't see:
- A payload the user ran later, for example by double-clicking it in Downloads (its parent is `explorer.exe`).
- An attachment opened with no click at all (there is no click row to anchor on).
- Clicks that never reached Safe Links (Step 5).

So also check each recipient's device timeline from T0: the attachment's file name (Step 4), files downloaded from the URL domains (`FileOriginUrl`), and shells or script hosts started by Office apps ([Office spawning shells](../02-suspicious-process/investigation.md)).

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

Anything that ran or was written from the email: hand the device to the [malware playbook](../01-malware-alert/playbook.md).

---

## Step 7 — credential phishing: sign-ins and the mailbox after a click

A credential or session-theft page creates no process, and no tool records a form being submitted. The evidence is what the attacker does next. For each clicker, and anyone who says they entered credentials, approved an MFA prompt or typed a code, check from the click time onward:

| Check | Where | What counts |
|---|---|---|
| Risk detections | Entra ID Protection → Risk detections, for the user | Any detection after the click. Watch for Attacker in the Middle, Anomalous token, Unfamiliar sign-in properties, Suspicious inbox forwarding, Suspicious inbox manipulation rules |
| Sign-ins | Entra sign-in logs, interactive and non-interactive. The [credential compromise](../06-credential-compromise/investigation.md) Entra queries, filtered to the UPN | A sign-in from an IP, country, device or app the user doesn't recognise |
| Device code sign-ins | Sign-in logs → Authentication protocol filter → Device code | Any device code sign-in the user can't explain (device code phishing) |
| Authentication methods | The user's registered authentication methods (Entra admin center) | A method added after the click |
| App consents | The applications the user has consented to (Entra admin center, enterprise application permissions) | An app the user consented to after the click (consent phishing) |
| Inbox rules and forwarding | Ask the customer's Exchange admin to run `Get-InboxRule -Mailbox <user> -IncludeHidden` and `Get-Mailbox -Identity <user> \| Format-List Forwarding*Address,DeliverTo*` | A rule or forwarding the user didn't create |
| Mail sent by the user | Explorer, sender = the user, Directionality Intra-org or Outbound | Messages the user didn't send (internal phishing) |

No detection doesn't clear the user. Attacker in the Middle needs Microsoft 365 E5 with EMS E5 and is calculated offline. The inbox detections need Defender for Cloud Apps licensing. Without Entra ID P2, most detections show only as "Additional risk detected".

Any hit: the account is compromised. Hand it to the [credential compromise playbook](../06-credential-compromise/playbook.md).

---

## Step 8 — the sender's mailbox (internal or partner)

**Internal sender.** A message from a mailbox in the customer's own domain that isn't spoofed (Step 1) is an account compromise:
- Run Step 7's checks for the sender, from the earliest suspicious sign-in.
- Explorer, sender = the account, Directionality Intra-org and Outbound: every message it sent since then. Their recipients are in scope, the same as Step 3's.
- Message trace and the Sent Items folder confirm what left the mailbox.
- A mailbox blocked from sending appears on the Restricted entities page. Don't release it yourself.

**Partner sender (thread hijacking).** The partner's mailbox may be compromised. Don't block the partner's address or domain: a Tenant Allow/Block List block also stops the customer's users sending to it. The customer contacts the partner through contact details they already hold, not by replying to the message.

---

## Common patterns

**Thread hijacking** — attacker compromises a mailbox and replies to existing threads. Email arrives from known trusted sender mid-conversation. Authentication passes, because the real mailbox sent it.

**HTML smuggling** — HTML attachment reconstructs malicious file client-side in the browser. MITRE notes that security controls such as web content filters may not identify the smuggled file. The attachment's hash is not the payload's hash: look for files the browser wrote after the attachment was opened (Step 4).

**QR code phishing (Quishing)** — malicious URL in a QR code image. Defender for Office 365 extracts URLs from QR codes: `UrlLocation` "QRCode" in `EmailUrlInfo`, URL source "QR code" in Explorer. A phone that scans the code is outside the corporate device's controls, and the click may not appear in `UrlClickEvents`. Check the user's sign-ins (Step 7).

**Callback phishing** — no malicious link or attachment. Just a fake invoice and a phone number. The email has no technical IOCs, but the incident can: MITRE describes callers directing victims to a malicious URL, malware or a remote management tool. Interview the user. Check their device for remote-access tools installed or first run after delivery. A signed remote-access tool is not evidence it is benign here; only a tool the customer sanctioned for that device is.
