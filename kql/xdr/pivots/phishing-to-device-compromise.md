## phishing-to-device-compromise.kql

**MITRE:** T1566.001, T1204.002, T1105 — Spearphishing Attachment → User Execution: Malicious File → Ingress Tool Transfer  
**Tables:** EmailEvents, EmailAttachmentInfo, DeviceFileEvents, DeviceProcessEvents  
**Platform:** Microsoft Defender XDR Advanced Hunting (native). Time column is `Timestamp`. `EmailEvents`/`EmailAttachmentInfo` do not flow to Sentinel as native tables — bring MDO alerts into Sentinel via the Microsoft Defender XDR connector instead of querying this directly from Log Analytics. See [kql/sentinel/pivots/phishing-to-device-compromise.kql](../../sentinel/pivots/phishing-to-device-compromise.kql) for a Sentinel-tree version kept for structural parity only — it will not run against a real Sentinel workspace  
**Licence:** Defender for Office 365 Plan 1 (email/attachment events) **and** Defender for Endpoint Plan 2 (device-side events) — both bundled in Microsoft 365 E5  
**When to use:** You've identified a suspicious email (by sender or `NetworkMessageId`) and need to know, in one pass, whether it actually led to code execution on any device — not just delivery.

### Why this query

A phishing email landing in an inbox tells you almost nothing about impact on its own — MDO delivery status only says the mail engine let it through, not what the recipient did with it. This pivot exists because "was delivered" and "was compromised" are genuinely different questions, and answering the second one by hand means manually carrying a SHA256 from Explorer into Advanced Hunting, then carrying it again from file events into process events. Chaining all three stages into one query removes that manual hand-off and puts the whole timeline — received, landed, executed — in front of you at once.

There's no numeric threshold here; the "detection logic" is structural. The join key is SHA256, not filename, because attackers routinely rename the same payload across campaigns while the file content — and therefore its hash — stays constant. The execution stage is explicitly filtered to `Timestamp > FileLandedTime`, so the timeline can never show a process "executing" a file before that file existed on the device, which would otherwise be possible if an unrelated process happened to touch a file with a coincidentally matching hash.

**What this won't catch:** Fileless or macro-based attachments where the malicious code runs inside Office's own process and never gets written to disk as a separate file with a matching hash — there's nothing for the `DeviceFileEvents` stage to join against, so the chain breaks at Stage 2 even if the document is malicious. Use `office-spawning-shells.kql` for that pattern instead, which looks at what Office spawns rather than what lands on disk. This query is also bounded by `lookback` (7 days by default) — a slow-burn case where the attachment sits unopened for weeks before someone finally clicks it will fall outside that window and return nothing; widen it if you're investigating an old email.

```kql
// Platform: Microsoft Defender XDR Advanced Hunting
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
| where Timestamp > ago(lookback)
| where (isnotempty(target_message_id) and NetworkMessageId == target_message_id)
    or (isempty(target_message_id) and SenderFromAddress =~ target_sender)
| project EmailTime = Timestamp, NetworkMessageId, SenderFromAddress,
    RecipientEmailAddress, Subject;
let AttachmentStage = EmailAttachmentInfo
| where Timestamp > ago(lookback)
| join kind=inner EmailStage on NetworkMessageId
| project EmailTime, NetworkMessageId, RecipientEmailAddress, FileName, SHA256;
let FileLandedStage = DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType == "FileCreated"
| join kind=inner AttachmentStage on SHA256
| project FileLandedTime = Timestamp, DeviceName, FileName, SHA256, FolderPath,
    EmailTime, NetworkMessageId, RecipientEmailAddress;
let ExecutionStage = DeviceProcessEvents
| where Timestamp > ago(lookback)
| join kind=inner FileLandedStage on SHA256, DeviceName
| where Timestamp > FileLandedTime
| project ExecutionTime = Timestamp, DeviceName, FileName, SHA256,
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
