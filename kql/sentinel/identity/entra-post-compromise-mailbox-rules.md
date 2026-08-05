## entra-post-compromise-mailbox-rules.kql

**MITRE:** T1114.003 — Email Collection: Email Forwarding Rule  
**Tables:** OfficeActivity, SigninLogs  
**Platform:** Microsoft Sentinel — via the **Office 365** data connector (`OfficeActivity`) and the Azure AD / Entra ID connector (`SigninLogs`). Time column is `TimeGenerated`. `OfficeActivity` is Sentinel-only — it has no Advanced Hunting equivalent. See [kql/xdr/identity/entra-post-compromise-mailbox-rules.kql](../../xdr/identity/entra-post-compromise-mailbox-rules.kql) for the XDR (`CloudAppEvents`) version  
**Licence:** Microsoft 365 E3+ with unified audit logging enabled, plus the Sentinel Office 365 data connector configured — the licence alone is not sufficient without both  
**When to use:** Run after a suspicious sign-in (device code, AiTM, impossible travel) to check whether the attacker used their live session to plant an inbox rule, or as a standalone daily hunt across the tenant.

### Why this query

Attackers with mailbox access create rules to auto-forward mail out, hide their own follow-on activity (invoice fraud replies, password reset emails), or quietly destroy evidence. This query flags `New-InboxRule`/`Set-InboxRule` operations that do any of three things: forward or redirect externally, delete messages containing finance/credential keywords, or mark messages as read — the last one buys the attacker time before the real user notices anything odd in their own inbox.

Rule parameters live inside `AuditData`, a JSON blob logged by Exchange's own audit pipeline — the property names used here (`Params.ForwardTo`, `Params.SubjectContainsWords`, `Params.MarkAsRead`) mirror the underlying Exchange PowerShell cmdlet parameters, so they track Exchange schema changes rather than anything Sentinel-specific. The join against `SuspiciousSignIns` narrows results to rules created within an hour of a sign-in already flagged as suspicious (device code, or a non-`"none"` `RiskLevelDuringSignIn`) — run this standalone (drop the join) if you want a tenant-wide daily sweep instead of a targeted post-sign-in check.

**What this won't catch:** Rules created through mailbox rule UI paths that don't route through the `New-InboxRule`/`Set-InboxRule` cmdlets at the audit layer, or through a mail client's own rule feature if it's implemented client-side rather than server-side (rare, but happens with some third-party mail clients). Mailbox auditing must be enabled on the target mailbox for any of this to log at all — check that before trusting a clean result. And because the join requires a sign-in already flagged as suspicious, an inbox rule planted using a session token stolen without the sign-in itself looking anomalous (a very well-executed AiTM attack) won't correlate — run this on its own, unjoined, as a periodic tenant-wide sweep to cover that gap.

```kql
// Platform: Microsoft Sentinel
// Identity — inbox rules created post-compromise (OfficeActivity)
// Attackers with mailbox access create rules to auto-forward, hide, or destroy
// evidence of their own activity (invoice fraud replies, password reset emails)
// Flags New-InboxRule / Set-InboxRule operations that do any of:
//   - forward or redirect externally (ForwardTo, ForwardAsAttachmentTo, RedirectTo
//     pointing outside the tenant's own domains)
//   - delete based on finance/credential keywords (invoice, payment, wire, password, MFA)
//   - mark items as read (hides the message from an unsuspecting user re-opening
//     their inbox, buys the attacker more time before discovery)
// Correlated against a suspicious sign-in window — drop the join for a tenant-wide
// daily sweep instead of a targeted post-sign-in check
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/scenarios/12-phishing-email/investigation.md

let lookback = 7d;
let correlation_window = 1h;
let SuspiciousSignIns = SigninLogs
| where TimeGenerated > ago(lookback)
| where AuthenticationRequirement != "singleFactorAuthentication" or RiskLevelDuringSignIn != "none"
| project UserPrincipalName, SignInTime = TimeGenerated;
OfficeActivity
| where TimeGenerated > ago(lookback)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| extend AuditParsed = parse_json(AuditData)
| extend Params = AuditParsed.Parameters
| extend
    ForwardsExternally = isnotempty(Params.ForwardTo) or isnotempty(Params.ForwardAsAttachmentTo) or isnotempty(Params.RedirectTo),
    DeletesByKeyword = Params.SubjectContainsWords has_any ("invoice", "payment", "wire", "password", "mfa"),
    MarksAsRead = tostring(Params.MarkAsRead) =~ "true"
| where ForwardsExternally or DeletesByKeyword or MarksAsRead
| join kind=inner SuspiciousSignIns on $left.UserId == $right.UserPrincipalName
| where TimeGenerated between (SignInTime .. (SignInTime + correlation_window))
| project TimeGenerated, UserId, Operation, ForwardsExternally,
    DeletesByKeyword, MarksAsRead, Params, ClientIP, SignInTime
| order by TimeGenerated desc
```

### False positives
- Users legitimately setting up forwarding to a personal address before leaving the company, or configuring a rule to forward to a delegate during leave — confirm with the account owner or their manager before escalating.
- Mark-as-read rules set up for high-volume automated notification mailboxes (ticketing systems, alert distribution lists) — check whether `UserId` is a shared/service mailbox with a known legitimate triage workflow.
- Keyword-based delete rules configured by users to manage newsletter/marketing spam that happens to contain one of the watched keywords (e.g. a "payment reminder" newsletter) — check the rule's full keyword list and target folder, not just whether one keyword matched.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

entra-post-compromise-mailbox-rules.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no suspicious inbox rules created in the post-compromise window
        [ ] Results found — see findings below

Findings:
  Account(s):
  IP address(es):
  Rule action (forward / delete / mark as read):
  Timeframe:
  Notes:

Conclusion:
  [ ] No suspicious activity identified — inbox rule activity for this account in the post-compromise window appears clean
  [ ] Suspicious activity identified — escalating
  [ ] False positive — reason:

─────────────────────────────────────────────────────────────
```
