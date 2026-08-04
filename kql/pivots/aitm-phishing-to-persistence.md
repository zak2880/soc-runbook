## aitm-phishing-to-persistence.kql

**MITRE:** T1556.006, T1098.001, T1114.003, T1528 — Modify Authentication Process → Account Manipulation: Additional Cloud Credentials → Email Forwarding Rule → Steal Application Access Token  
**Tables:** AADSignInEventsBeta, CloudAppEvents  
**Platform:** Defender XDR Advanced Hunting only. Neither table is Sentinel-native — the closest Sentinel equivalents are `SigninLogs` (Azure AD connector) and `OfficeActivity` (Office 365 connector), which have different schemas; native Advanced Hunting also uses `Timestamp` rather than this repo's `TimeGenerated` alias  
**Licence:** Microsoft Defender for Cloud Apps (for both `AADSignInEventsBeta` visibility and `CloudAppEvents`), or Entra ID P1/P2 with Identity Protection integrated into Defender XDR for the sign-in portion — Microsoft 365 E5 covers all of it  
**When to use:** You've identified a device code or AiTM-flagged sign-in and need to know, in one pass, whether the attacker has already planted persistence — not just whether the sign-in itself was suspicious.

```kql
// Pivot — AiTM / device code phishing to persistence timeline
// Starts from a suspicious device code or AiTM-flagged sign-in, then hunts forward
// for the persistence mechanisms an attacker plants once they have a live session —
// the point of this query is to catch the attacker BEFORE they finish setting up
// their way back in, not just after the fact
// Chains: identity sign-in (AADSignInEventsBeta) -> MFA registration, inbox rules,
// OAuth consent, and app registration (CloudAppEvents)
// Uses CloudAppEvents as the single source table for the forward hunt (Defender
// XDR Advanced Hunting, requires Defender for Cloud Apps). If your tenant is
// Sentinel-only without MDCA, run the OfficeActivity versions of
// entra-post-compromise-persistence.kql, entra-post-compromise-mailbox-rules.kql,
// and entra-post-compromise-oauth-grants.kql individually instead
// Persistence window: 24h post-sign-in — widen if the attacker was patient
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/scenarios/12-phishing-email/investigation.md

let lookback = 7d;                // how far back to search for the initial sign-in
let persistence_window = 24h;     // how far forward from the sign-in to hunt

let CompromisedSignIns = AADSignInEventsBeta
| where TimeGenerated > ago(lookback)
| where AuthenticationProtocol == "deviceCode" or RiskLevelDuringSignIn != "none"
| project AccountUpn, SignInTime = TimeGenerated, IPAddress, Country;
let NewMfaMethods = CloudAppEvents
| where ActionType in ("Add strong authentication method.", "Update user.")
| join kind=inner CompromisedSignIns on $left.AccountId == $right.AccountUpn
| where TimeGenerated between (SignInTime .. (SignInTime + persistence_window))
| project TimeGenerated, AccountUpn = AccountId, ActionType, SignInTime;
let NewInboxRules = CloudAppEvents
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| join kind=inner CompromisedSignIns on $left.AccountId == $right.AccountUpn
| where TimeGenerated between (SignInTime .. (SignInTime + persistence_window))
| project TimeGenerated, AccountUpn = AccountId, ActionType, SignInTime;
let NewOAuthGrants = CloudAppEvents
| where ActionType in ("Consent to application.", "Add OAuth2PermissionGrant.")
| join kind=inner CompromisedSignIns on $left.AccountId == $right.AccountUpn
| where TimeGenerated between (SignInTime .. (SignInTime + persistence_window))
| project TimeGenerated, AccountUpn = AccountId, ActionType, SignInTime;
let NewServicePrincipals = CloudAppEvents
| where ActionType in ("Add service principal.", "Add application.")
| join kind=inner CompromisedSignIns on $left.AccountId == $right.AccountUpn
| where TimeGenerated between (SignInTime .. (SignInTime + persistence_window))
| project TimeGenerated, AccountUpn = AccountId, ActionType, SignInTime;
union
    (CompromisedSignIns | extend Stage = "0-SuspiciousSignIn", TimelineTime = SignInTime),
    (NewMfaMethods | extend Stage = "1-NewMfaMethod", TimelineTime = TimeGenerated),
    (NewInboxRules | extend Stage = "2-NewInboxRule", TimelineTime = TimeGenerated),
    (NewOAuthGrants | extend Stage = "3-NewOAuthGrant", TimelineTime = TimeGenerated),
    (NewServicePrincipals | extend Stage = "4-NewServicePrincipal", TimelineTime = TimeGenerated)
| order by AccountUpn, TimelineTime asc
```

### False positives
- `RiskLevelDuringSignIn != "none"` alone catches a lot of noise (impossible-travel-by-VPN, new device enrollment, first-time app use) — this query is a forward hunt intended to run against sign-ins you've already triaged as suspicious via `entra-device-code-auth-flow.kql` or `entra-aitm-session-anomalies.kql`, not as a standalone trigger.
- A user genuinely registering a new MFA method (new phone, lost device) around the same time as an unrelated risky-but-benign sign-in — check the MFA registration against a helpdesk ticket or self-service reset log before escalating on Stage 1 alone.
- IT deploying a new line-of-business app registration or service principal during the same window, coincidentally — cross-check `Application`/`AccountUpn` against your change log.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

aitm-phishing-to-persistence.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no new MFA methods, inbox rules, OAuth grants, or service principals detected within 24h of the suspicious sign-in
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
