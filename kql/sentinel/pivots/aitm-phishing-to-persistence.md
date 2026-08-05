## aitm-phishing-to-persistence.kql

**MITRE:** T1556.006, T1098.001, T1114.003, T1528 — Modify Authentication Process → Account Manipulation: Additional Cloud Credentials → Email Forwarding Rule → Steal Application Access Token  
**Tables:** SigninLogs, OfficeActivity, AuditLogs  
**Platform:** Microsoft Sentinel — via the Azure Active Directory / Entra ID connector (`SigninLogs`, `AuditLogs`) and the Office 365 connector (`OfficeActivity`). Time column is `TimeGenerated`. This is a genuine rewrite of the XDR version against Sentinel-native tables, not a column rename — see [kql/xdr/pivots/aitm-phishing-to-persistence.kql](../../xdr/pivots/aitm-phishing-to-persistence.kql) for the `EntraIdSignInEvents`/`CloudAppEvents` version  
**Licence:** Microsoft Entra ID P1 minimum for `SigninLogs`/`AuditLogs` retention (P2 adds `RiskLevelDuringSignIn`); Microsoft 365 E3+ with unified audit logging enabled, plus the Sentinel Office 365 connector, for `OfficeActivity` — Microsoft 365 E5 covers all of it  
**When to use:** You've identified a device code or risky sign-in and need to know, in one pass, whether the attacker has already planted persistence — not just whether the sign-in itself was suspicious.

### Why this query

Once a token is stolen, the reflexive first remediation is to reset the account's password — which does nothing against any of the three persistence mechanisms this query hunts for. A new authentication method survives a password reset. An inbox rule survives it. An OAuth grant or a rogue service principal, being its own identity with its own credential, was never tied to the user's password in the first place. An attacker who's gone to the effort of device-code or AiTM phishing knows this, and typically moves to plant at least one of these before the victim (or the SOC) catches on and locks them out.

The 24-hour persistence window reflects that urgency — an attacker with a freshly stolen token usually acts on it quickly, both because the token may be short-lived and because they don't know how long they have before detection. Unlike the XDR version, which can run all four checks against a single `CloudAppEvents` table, this Sentinel version has to span three genuinely different tables — `OfficeActivity` for inbox rules (no Advanced Hunting equivalent) and `AuditLogs` for OAuth grants and service principals (the Sentinel-native directory audit table, more direct than routing through `OfficeActivity`'s Azure AD event copy). That's a structural consequence of the platform split documented in `docs/reference/sentinel-vs-advanced-hunting.md`, not a design choice — the detection logic is the same, just spread across the tables that actually carry it in Sentinel.

**What this won't catch:** An attacker who waits longer than `persistence_window` before acting evades every check here, since all three are time-boxed to the sign-in; if initial results come back empty and the sign-in still looks wrong, re-run with a wider window before concluding the tenant is clean. This query also only recognises the specific `Operation`/`OperationName` strings currently listed — if Microsoft renames these audit events, or the attacker uses a persistence mechanism outside this list entirely (a new email alias, or an app password on a tenant that still permits them), it produces no signal. This is the least battle-tested query in the repo — the persistence window and the exact operation names are the two things most likely to need adjustment once you've run this against a real tenant.

```kql
// Platform: Microsoft Sentinel
// Pivot — AiTM / device code phishing to persistence timeline (SigninLogs -> OfficeActivity -> AuditLogs)
// TUNING WARNING: this is a forward hunt, not a standalone trigger. It's meant to
// run against a sign-in you've already triaged as suspicious via
// entra-device-code-auth-flow.md or entra-aitm-session-anomalies.kql —
// RiskLevelDuringSignIn != "none" alone catches a lot of noise on its own
// (impossible-travel-by-VPN, new device enrollment, first-time app use). If you run
// CompromisedSignIns cold against the whole tenant instead of feeding it a sign-in
// you already suspect, expect a lot of benign rows in Stage 0 that then get
// (correctly) filtered out by the absence of any Stage 1-3 hit — don't mistake a
// long Stage 0 list for a long list of compromises.
// Once a token is stolen, the reflexive first remediation is to reset the account's
// password — which does nothing against any of the mechanisms this hunts for. A new
// MFA-capable auth method, an inbox rule, and an OAuth grant / service principal all
// survive a password reset
// Starts from a suspicious device code or risky sign-in (SigninLogs), then hunts
// forward for: inbox rules (OfficeActivity — Sentinel-only, no Advanced Hunting
// equivalent) and OAuth consent grants / new service principals (AuditLogs — the
// Sentinel-native directory audit table via the Azure AD / Entra ID connector)
// Persistence window: 24h post-sign-in — widen if the attacker was patient
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/scenarios/12-phishing-email/investigation.md

let lookback = 7d;                // how far back to search for the initial sign-in
let persistence_window = 24h;     // how far forward from the sign-in to hunt

let CompromisedSignIns = SigninLogs
| where TimeGenerated > ago(lookback)
| where AuthenticationRequirement != "singleFactorAuthentication" or RiskLevelDuringSignIn != "none"
| project UserPrincipalName, SignInTime = TimeGenerated, IPAddress, Location;
let NewInboxRules = OfficeActivity
| where TimeGenerated > ago(lookback)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| join kind=inner CompromisedSignIns on $left.UserId == $right.UserPrincipalName
| where TimeGenerated between (SignInTime .. (SignInTime + persistence_window))
| project TimeGenerated, UserPrincipalName = UserId, ActionType = Operation, SignInTime;
let NewOAuthGrants = AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| extend InitiatedByUpn = tostring(InitiatedBy.user.userPrincipalName)
| join kind=inner CompromisedSignIns on $left.InitiatedByUpn == $right.UserPrincipalName
| where TimeGenerated between (SignInTime .. (SignInTime + persistence_window))
| project TimeGenerated, UserPrincipalName = InitiatedByUpn, ActionType = OperationName, SignInTime;
let NewServicePrincipals = AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in ("Add service principal", "Add application")
| extend InitiatedByUpn = tostring(InitiatedBy.user.userPrincipalName)
| join kind=inner CompromisedSignIns on $left.InitiatedByUpn == $right.UserPrincipalName
| where TimeGenerated between (SignInTime .. (SignInTime + persistence_window))
| project TimeGenerated, UserPrincipalName = InitiatedByUpn, ActionType = OperationName, SignInTime;
union
    (CompromisedSignIns | extend Stage = "0-SuspiciousSignIn", TimelineTime = SignInTime, ActionType = "SignIn"),
    (NewInboxRules | extend Stage = "1-NewInboxRule", TimelineTime = TimeGenerated),
    (NewOAuthGrants | extend Stage = "2-NewOAuthGrant", TimelineTime = TimeGenerated),
    (NewServicePrincipals | extend Stage = "3-NewServicePrincipal", TimelineTime = TimeGenerated)
| order by UserPrincipalName, TimelineTime asc
```

### False positives
- `RiskLevelDuringSignIn != "none"` alone catches a lot of noise (impossible-travel-by-VPN, new device enrollment, first-time app use) — this query is a forward hunt intended to run against sign-ins you've already triaged as suspicious via `entra-device-code-auth-flow.md` or `entra-aitm-session-anomalies.kql`, not as a standalone trigger.
- A user genuinely registering a new authentication method (new phone, lost device) around the same time as an unrelated risky-but-benign sign-in — check the registration against a helpdesk ticket or self-service reset log before escalating on Stage 1 alone.
- IT deploying a new line-of-business app registration or service principal during the same window, coincidentally — cross-check `TargetResources`/`UserPrincipalName` against your change log.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

aitm-phishing-to-persistence.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no new authentication methods, inbox rules, OAuth grants, or service principals detected within 24h of the suspicious sign-in
        [ ] Results found — see findings below

Findings:
  Account(s):
  Persistence mechanism(s) found:
  IP address(es):
  Timeframe (sign-in -> persistence):
  Notes:

Conclusion:
  [ ] No suspicious activity identified — no persistence mechanisms identified for this account in the post-sign-in window
  [ ] Suspicious activity identified — escalating
  [ ] False positive — reason:

─────────────────────────────────────────────────────────────
```
