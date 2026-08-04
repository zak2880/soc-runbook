## phishing-to-device-compromise.kql

**MITRE:** T1566.001, T1204.002, T1105 — Spearphishing Attachment → User Execution: Malicious File → Ingress Tool Transfer  
**Tables:** EmailEvents, EmailAttachmentInfo, DeviceFileEvents, DeviceProcessEvents  
**Platform:** Defender XDR Advanced Hunting only. `EmailEvents`/`EmailAttachmentInfo` do not flow to Sentinel as native tables — bring MDO alerts into Sentinel via the Microsoft Defender XDR connector instead of querying this directly from Log Analytics; native Advanced Hunting uses `Timestamp` rather than this repo's `TimeGenerated` alias  
**Licence:** Defender for Office 365 Plan 1 (email/attachment events) **and** Defender for Endpoint Plan 2 (device-side events) — both bundled in Microsoft 365 E5  
**When to use:** You've identified a suspicious email (by sender or `NetworkMessageId`) and need to know, in one pass, whether it actually led to code execution on any device — not just delivery.

```kql
// Pivot — phishing email to device compromise timeline
// Starts from a known suspicious email, pulls its attachment hash, then follows that
// hash onto the endpoint to see which devices received it and which ones actually
// executed it — the difference between "was delivered" and "was compromised"
// Chains: email investigation (EmailEvents, EmailAttachmentInfo) -> file artefacts
// (DeviceFileEvents) -> process execution (DeviceProcessEvents)
// Match by NetworkMessageId if you have it (most precise); otherwise leave it empty
// and match by sender instead
// Ref: docs/scenarios/12-phishing-email/investigation.md, docs/scenarios/05-malicious-file/investigation.md, docs/scenarios/01-malware-alert/investigation.md

let target_message_id = "";                      // paste NetworkMessageId here if known
let target_sender = "attacker@malicious.com";     // used only if target_message_id is empty
let lookback = 7d;                                // how far back to search

let EmailStage = EmailEvents
| where TimeGenerated > ago(lookback)
| where (isnotempty(target_message_id) and NetworkMessageId == target_message_id)
    or (isempty(target_message_id) and SenderFromAddress =~ target_sender)
| project EmailTime = TimeGenerated, NetworkMessageId, SenderFromAddress,
    RecipientEmailAddress, Subject;
let AttachmentStage = EmailAttachmentInfo
| where TimeGenerated > ago(lookback)
| join kind=inner EmailStage on NetworkMessageId
| project EmailTime, NetworkMessageId, RecipientEmailAddress, FileName, SHA256;
let FileLandedStage = DeviceFileEvents
| where TimeGenerated > ago(lookback)
| where ActionType == "FileCreated"
| join kind=inner AttachmentStage on SHA256
| project FileLandedTime = TimeGenerated, DeviceName, FileName, SHA256, FolderPath,
    EmailTime, NetworkMessageId, RecipientEmailAddress;
let ExecutionStage = DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| join kind=inner FileLandedStage on SHA256, DeviceName
| where TimeGenerated > FileLandedTime
| project ExecutionTime = TimeGenerated, DeviceName, FileName, SHA256,
    ProcessCommandLine, AccountName, EmailTime, FileLandedTime,
    NetworkMessageId, RecipientEmailAddress;
union
    (EmailStage | extend Stage = "1-EmailReceived", TimelineTime = EmailTime),
    (FileLandedStage | extend Stage = "2-FileLanded", TimelineTime = FileLandedTime),
    (ExecutionStage | extend Stage = "3-ProcessExecuted", TimelineTime = ExecutionTime)
| order by TimelineTime asc
```

### False positives
- File landed but no execution stage present is not itself a false positive — it's the expected, good outcome (attachment saved by MDO/AV scanning, or the user never opened it). Don't escalate on Stage 1/2 alone; the query is designed so Stage 3 (`ProcessExecuted`) is the actual trigger for concern.
- Sandboxing/detonation systems (Safe Attachments, third-party sandboxes) will show the file "landing" and sometimes "executing" on infrastructure that isn't a real user device — check `DeviceName` against your known sandbox/detonation host list before escalating.
- Security awareness phishing simulations delivering a benign "attachment" with a recognisable SHA256 — cross-check the hash against your simulation platform's known-safe test file list.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

phishing-to-device-compromise.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no matching email found, or attachment never landed/executed on any device
        [ ] Results found — see findings below

Findings:
  Email (sender / NetworkMessageId):
  Device(s) attachment landed on:
  Device(s) that executed it:
  Account(s):
  Timeframe (email received -> file landed -> executed):
  Notes:

Conclusion:
  [ ] No suspicious activity identified — attachment was not executed on any device, no device compromise from this email
  [ ] Suspicious activity identified — escalating
  [ ] False positive — reason:

─────────────────────────────────────────────────────────────
```
