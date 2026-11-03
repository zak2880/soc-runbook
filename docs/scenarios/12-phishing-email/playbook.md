# Phishing email — playbook

Work top to bottom. Each step is one action, what you should see, and what to do if you don't. Preserve the message and its headers before you move, delete or purge anything. Queries are in the [investigation](investigation.md).

T0 = delivery time of the first message in the campaign, in UTC. Advanced Hunting holds 30 days of native data and Explorer searches up to 30 days back; older activity needs Sentinel retention.

Licence: Defender for Office 365 Plan 2 has Threat Explorer, which can move and delete mail. Plan 1 has Real-time detections, which can submit to Microsoft and add Tenant Allow/Block List entries but can't move or delete mail. Record which the customer has.

If you came here from the [malware playbook](../01-malware-alert/playbook.md) (step 20) or the [initial access playbook](../10-initial-access/playbook.md) (step 16): that device is already in hand there. Use this playbook for the email and for every other recipient.

---

## 1. Triage

If you don't hold the rights for a step in 1 to 7 (Explorer read access; the Preview role for Download email), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

1. **Find the message and open its email entity page.** Record the Network message ID, Internet message ID, From and MAIL FROM addresses, Directionality, Time received, Latest delivery location, Detection technology, DMARC, DKIM, SPF and Composite authentication, Cluster ID, and recipient Tags (investigation, Step 1).
   - Expect: all recorded.
   - If you can't find it in Explorer (it searches up to 30 days back): check Message trace, record what you searched and the recipients it lists, and continue with the steps you can do. Do steps 12 to 15 for those recipients. Escalate (message not found in Explorer) if any recipient interacted or any recipient is a priority account; otherwise record it as a ticket note.

2. **Check the incident's other alerts and each recipient's user page.**
   - Expect: email alerts only.
   - If an endpoint alert shows a payload ran on a device: escalate (payload ran) and contain that device now with steps 7 to 10 of the [malware playbook](../01-malware-alert/playbook.md). Then come back here.
   - If a recipient has any Entra ID Protection risk detection since T0, or an alert for a suspicious inbox rule or forwarding: escalate (recipient account compromised) and do steps 13 to 16 of the [credential compromise playbook](../06-credential-compromise/playbook.md) for that user now. Then come back here. The account path in step 14 takes that user on to 06 step 20.
   - If a "potentially malicious URL click" alert names a user: do step 14 for that user before you continue.

3. **Classify the sender** (investigation, Step 1, "Who sent it?"): attacker-owned, spoofed From, partner, or internal.
   - Expect: attacker-owned or spoofed.
   - If internal (the customer's own domain, Directionality Intra-org, not spoofed): escalate (internal mailbox compromised) and do steps 13 to 16 of the credential compromise playbook for the sender now. The account path in step 14 takes the sender on to 06 step 20. Step 18 scopes what the account sent. Don't block the sender (step 9).
   - If a known partner's mailbox (authentication passes, a reply inside an existing thread): escalate (partner mailbox compromised). Don't block the sender (step 9).

4. **Decide whether the message is malicious.** Any one of these is enough: Original or Latest threats show Phish or Malware; a URL or attachment has a threat verdict or a malicious detonation; the From address is spoofed and the message asks for credentials, payment or a call; enrichment of a URL or attachment (step 6) is malicious.
   - Expect: a decision recorded with the evidence.
   - If you can't tell: treat it as malicious and continue. The blocks and the soft delete in steps 8 to 11 can be undone.
   - Close only per [Closing as not malicious](#closing-as-not-malicious) below.

---

## 2. Preserve evidence

Do steps 5 and 6 before step 11 removes any copy. Download email isn't available once a message is soft deleted or hard deleted, so the download in step 5 must come before the soft delete in step 11.

5. **Preserve the message.** On the email entity page: Analysis → Plain-text email header → Copy message header, and paste it into the ticket. Export the Timeline, Attachments and URL views. Then More options → Download email.
   - Expect: the header, the three exports and the downloaded message attached to the ticket.
   - If Latest delivery location is Quarantine: download the password-protected copy from Quarantine instead.
   - If you can't download it (no Preview role, or the message is already soft or hard deleted): record why. Don't move a malicious message back to an inbox to download it. A soft-deleted message stays recoverable by admins, so the header and exports are enough to continue to step 11. A hard delete then needs the IR lead to accept not having the download (step 11).
   - Don't open the downloaded message or its attachments on your workstation.

6. **Record the attachments and URLs.** Attachments view: the Attachment SHA256 of each file; export the Deep analysis detonation chain and behaviour details if shown. URL view: every URL, including URLs from QR codes (investigation, Steps 4 and 5).
   - Look up each hash on VirusTotal by hash; don't upload the file. Submit URLs to URLScan only as Unlisted or Private, with the recipient's address and any tokens removed.
   - Expect: every SHA256 and URL in the ticket with its verdict.

---

## 3. Scope the campaign

7. **Find every copy of the campaign** (investigation, Step 3): Campaigns view (Plan 2), Similar emails on the entity page, then Explorer filters by sender domain and mail from domain, URL domain, attachment name or SHA256, and Cluster ID, over the last 30 days. Check Submissions → User reported.
   - Expect: a list of messages and recipients, each with its Latest delivery location.
   - Many recipients means scope wider. It is never a reason to close.
   - Record any priority-account or admin recipient. If one of them clicked or opened the attachment (steps 12 and 13): escalate (priority or admin recipient interacted).
   - Copies with delivery location On-premises/External, or older than Explorer's 30 days: Explorer can't act on them. Record them for step 11.

---

## 4. Block, then remove

If you don't hold the rights for a step in 8 to 11 (Tenant Allow/Block List entries; the Search and Purge role to move or delete mail; Defender for Endpoint indicators), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

Only after steps 5 and 6. Block first, so new copies and clicks on copies still in mailboxes are stopped; then remove.

8. **Block the URLs and attachments in the Tenant Allow/Block List.** Use Take action → Submit to Microsoft for review → I've confirmed it's a threat, and select the URLs and attachments to block. This also reports them to Microsoft. Or add them on the Tenant Allow/Block Lists page.
   - URLs: mail containing a blocked URL is quarantined as high confidence phishing, and the block also applies at time of click in email, Teams and Office apps. A domain entry such as `contoso.com` also matches its subdomains and every path.
   - Don't block a domain the customer or its partners use for business (a shared file-hosting service, or a legitimate site that was compromised). Block the full path (`contoso.com/path/*`); if that isn't possible, escalate (business domain can't be blocked).
   - Attachments: by SHA256. Mail containing the file is quarantined as malware.
   - Expiry: on the Tenant Allow/Block Lists page the default is 30 days (up to 90 days, or never); in the Take action wizard you choose a date or never. Record the date.
   - Expect: each entry listed. Entries take effect within 5 minutes.
   - If not listed: add it again on the Tenant Allow/Block Lists page and record the error.
   - These entries act on mail and on clicks through Safe Links only. They don't stop a file already on a device, or a URL opened outside Safe Links. That is step 10.

9. **Block the sender only if it is attacker-owned** (step 3), and only if step 4 found evidence that the message is malicious (not when you treated it as malicious because you couldn't tell).
   - Attacker-owned address or domain: block it on Domains & addresses. Users in the organization then can't send mail to it either: the whole message is blocked for every recipient, with a bounce. The entry matches the From address, not MAIL FROM.
   - Block the address, not the domain, when the domain is a public mail provider or one the customer's users write to for business.
   - Spoofed From: don't block the address; that blocks its real owner. Block the domain pair on the Spoofed senders tab. Spoofed sender entries never expire; record the entry for review (step 20).
   - Internal or partner mailbox: don't block. A block applies to internal senders too, and it would stop the customer's users mailing the partner. The account is handled in steps 2, 3 and 18.
   - Expect: the decision and any entry recorded.

10. **Block the URLs on endpoints** with Defender for Endpoint indicators (Settings → Endpoints → Indicators): the URL domains from step 6, and the SHA256 of any attachment that is a PE file (`.exe`, `.dll`).
    - URLs: outside Microsoft Edge, blocking needs Network Protection in block mode. An HTTPS full URL path can be blocked only in Edge; other browsers block by domain, and only with QUIC and Encrypted Client Hello disabled. Blocks can take up to 48 hours; most apply within 2 hours.
    - File hashes: PE files only, and Defender Antivirus must be in active mode. A document, script or archive can't be blocked by hash; its URLs are blocked instead.
    - The same business-domain rule as step 8 applies.
    - Expect: each indicator listed with its expiry.
    - If you can't create one: record why and tell the customer. The Tenant Allow/Block List entries from step 8 still apply to mail and Safe Links clicks.
    - A blocked connection can still appear as `ConnectionSuccess` in network events. Check the alerts queue for the block.

11. **Soft delete every copy from step 7.** Only after step 5 has downloaded the message or recorded why it couldn't: Download email isn't available once a message is soft deleted. First check Action center → Pending: an automated investigation may already have proposed a soft delete for these messages. Approve it if its scope matches step 7. Leave any other pending action on these users (for example turning off forwarding) until step 17 has recorded what it changes. Otherwise, in Threat Explorer select the messages → Take action → Move or delete → Soft deleted items, and give the remediation a name. If the sender is internal (step 3), also select Delete sender's copy.
    - Without the Search and Purge role: Take action → Propose remediation → Create new. Someone with the role approves it in Action center → Pending.
    - Expect: Action center → History shows the remediation, and its action log shows Success or Already in destination for every message.
    - If Failed: retry. A remediation can stay In progress for a few hours.
    - Explorer takes up to 200,000 messages per selection; Microsoft advises batches of 50,000 or fewer.
    - Plan 1 only, copies On-premises/External, or older than 30 days: ask the customer's mail admin to remove them, and record the request. If they can't: escalate (copies can't be removed).
    - Soft delete moves the message to Recoverable Items\Deletions; the user and admins can recover it, and Move to inbox in Explorer undoes it. Don't hard delete yourself. The IR lead decides on hard delete (for example if users keep restoring the message), and only if step 5's download was done or the IR lead accepts not having it. Don't move a message back to an inbox to download it. Admins can recover a hard-deleted message only through single-item recovery.
    - Don't wait for ZAP: it only searches the last 48 hours of delivered mail.

---

## 5. Check who interacted

If you don't hold the rights for a step in 12 to 15 (Entra sign-in logs and ID Protection; Exchange admin for inbox rules and forwarding), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

12. **Check clicks on every message in scope** (investigation, Steps 5 and 6; Explorer → URL clicks).
    - Expect: no allowed click and no `IsClickedThrough` true.
    - If clicks: list each clicker with the click time, and do steps 13 and 14 for each.
    - No click rows don't prove nobody clicked. A QR code scanned on a phone, or a URL copied into a browser, may leave none. Ask the customer to ask every recipient whether they clicked, opened the attachment, entered credentials, approved an MFA prompt, typed a code or called a number. Do steps 13 to 15 for each who says yes.

13. **Check whether anything ran or was written** on each clicker's device and, if the message had an attachment, on each recipient's device. Run the "did the user interact?" query, then search each device timeline from T0 for the attachment's name and for downloads from the URL domains (investigation, Steps 4 and 6).
    - Expect: nothing ran and no payload was written.
    - If you find the file: copy its SHA1 from the file page and run the hash sweep. If it is on more than one device: escalate (same payload on more than one device).
    - If anything ran or a payload was written: escalate (payload ran) and run the [malware playbook](../01-malware-alert/playbook.md) from step 7 for that device.

14. **Check each clicker's account from the click time on** (investigation, Step 7): Entra ID Protection risk detections, sign-ins (interactive and non-interactive, and Authentication protocol Device code), authentication methods added, app consents, inbox rules and forwarding, and mail the user sent.
    - Expect: none of these after the click.
    - If any, or the user says they entered credentials, approved an MFA prompt or typed a code: escalate (recipient account compromised) and run steps 13 to 20 of the [credential compromise playbook](../06-credential-compromise/playbook.md) for that user. A user or sender from steps 2 and 3 comes here too, clicked or not: steps 13 to 16 are done, so continue from 06 step 17. Re-enabling is 06 step 20: you do it, or the customer's IT contact if you don't hold the right, once that step's conditions hold. Then do step 17 for that user straight away; don't leave it for the end.
    - No detection doesn't clear the user: Attacker in the Middle needs Microsoft 365 E5 with EMS E5 and is calculated offline.
    - If the user is a priority account or admin: escalate (priority or admin recipient interacted).

15. **Callback phishing (a phone number, no link or attachment): ask each recipient whether they called,** then search the device timeline of each who did, from T0, for remote-access tools installed or run for the first time.
    - Expect: nobody called, or no new tool.
    - If a remote-access tool appeared: escalate (remote-access tool after a call) and run the malware playbook from step 7 for that device. A signed tool is not evidence it is benign; only a tool the customer sanctioned for that device is.

---

## 6. Remediate

If you don't hold the rights for a step in 16 to 20, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

16. **Check that every device from steps 2, 13 and 15 is in the malware playbook** from its step 7 (isolation, evidence, stop, payload block, removal, release).
    - Expect: each device listed in the ticket with its malware playbook status.

17. **Remove the mailbox changes the attacker made** (step 14), only after each one is recorded in the ticket: inbox rules, forwarding, and app consents. The customer's Exchange or identity admin does this if you don't hold the rights.
    - Expect: each item removed and recorded.

18. **Internal sender only (step 3): scope what the sender's account sent** since its first suspicious sign-in (investigation, Step 8). Add those messages and their recipients to step 7's scope, and do steps 5 to 15 for any message not already covered.
    - If the account is blocked from sending (Restricted entities page): leave it. The IR lead decides when to release it.
    - Expect: the account's sent mail listed and handled.

19. **Tell the customer:** the scope, what was blocked and removed, and the users who need a password reset or device work. Ask them to tell recipients not to restore the message from Deleted Items or Recoverable Items, and to report a click, entered credentials or a call. Partner mailbox (step 3): ask them to warn the partner through contact details they already hold, not by replying to the message.

20. **Set a review date for every block** from steps 8 to 10: Tenant Allow/Block List entries expire after 30 days by default, spoofed sender entries never expire, and indicators expire on the date you set.

---

## 7. Close out

- [ ] Classification set: True positive, Informational expected activity (an authorised phishing simulation), or False positive (only per Closing as not malicious)
- [ ] Message IDs, sender (From and MAIL FROM), subject, URLs, attachment SHA256 and payload SHA1 documented
- [ ] Every block documented (Tenant Allow/Block List, indicators) with its expiry
- [ ] Recipients and Latest delivery location documented; the remediation name and its Action center result; any copy not removed and why
- [ ] Who clicked, opened the attachment, entered credentials or called; which devices and accounts went to the malware and credential compromise playbooks
- [ ] Customer informed
- [ ] Escalated if any trigger below was hit

---

## Phishing pattern quick reference

| Pattern | Key indicator | Action |
|---------|--------------|--------|
| Thread hijacking | Known sender, reply mid-thread, unexpected link or attachment | Step 3: partner or internal mailbox compromise. Don't block the sender |
| HTML smuggling | HTML attachment that builds a file when opened | Step 13: look for files the browser wrote after the open. The attachment's hash is not the payload's |
| Quishing | QR code image, prompt to scan | Steps 12 and 14: a phone click may leave no click row; check the user's sign-ins |
| Callback phishing | No links or attachments, phone number only | Step 15: ask who called; check their devices for remote-access tools |

---

## Closing as not malicious

Close only with a named, verifiable benign cause, and record it. None of these is enough on its own: nobody clicked, few recipients, ZAP didn't act, no Entra detection, authentication passed, or the user says it looked fine. Many recipients means scope wider.

Never close yourself if any trigger in [Escalate if](#escalate-if) was hit, even if a test or simulation is mentioned. Escalate; the IR lead decides.

| Cause | Close only if all of these hold |
|-------|---------------------------------|
| Authorised phishing simulation | The customer's security contact names the simulation in the ticket, with its sender and URLs, and they match this message. For a non-Microsoft simulation, the sending domains and URLs are also in the customer's advanced delivery policy. Classify as Informational, expected activity, not False positive |
| Legitimate business mail | The sending organization is named. DMARC passes for its own From domain. Every URL domain and attachment belongs to that organization or to a service it is confirmed to use. Enrichment (step 6) is clean. The sender confirmed sending it through contact details the customer already holds, not details in the message |

If you soft deleted copies of a message that turns out to be legitimate: select them in Explorer → Take action → Move or delete → Inbox, and remove the blocks from steps 8 to 10.

If any condition can't be confirmed: don't close. Escalate.

---

## Escalate if

See also [escalation triggers](../../reference/escalation-triggers.md).

```
Payload ran on a device (hand off to 01-malware-alert)
Same payload on more than one device
Recipient account compromised: since T0, an Entra ID Protection risk detection, a sign-in the user doesn't recognise, or a new MFA method, app consent, inbox rule or forwarding; or the user entered credentials, approved an MFA prompt or typed a code
Internal mailbox compromised (BEC): the message came from the customer's own domain and isn't spoofed
Partner mailbox compromised: a known partner's authenticated mailbox sent it (thread hijacking)
Priority or admin recipient interacted (clicked, opened the attachment, or entered credentials)
Remote-access tool after a call (callback phishing)
Message not found in Explorer, and any recipient interacted or any recipient is a priority account (otherwise a ticket note)
Copies can't be removed: Plan 1 only, On-premises/External, older than 30 days, or remediation Failed and the customer can't remove them
Business domain can't be blocked: a malicious URL is on a domain the customer uses and its path can't be blocked
```
