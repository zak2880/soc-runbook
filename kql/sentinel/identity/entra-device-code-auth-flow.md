## entra-device-code-auth-flow.kql

**MITRE:** T1556.006 — Modify Authentication Process: Multi-Factor Authentication  
**Tables:** SigninLogs  
**Platform:** Microsoft Sentinel — via the Azure Active Directory / Entra ID data connector. Time column is `TimeGenerated`. `SigninLogs` is the Sentinel-native equivalent of Defender XDR's `EntraIdSignInEvents` — different schema, same underlying sign-in event. See [kql/xdr/identity/entra-device-code-auth-flow.md](../../xdr/identity/entra-device-code-auth-flow.md) for the XDR version  
**Licence:** Microsoft Entra ID P1 at minimum for sign-in log retention in Sentinel; P2 adds Identity Protection risk signals (`RiskLevelDuringSignIn`)  
**When to use:** You suspect device code phishing — a user reports being asked to enter a code at microsoft.com/devicelogin, or you're proactively hunting for this initial-access vector across the tenant.

### Why this query

Device code phishing works by getting the victim to complete a normal, legitimate-looking sign-in — the user goes to microsoft.com/devicelogin themselves, enters a code the attacker generated, and satisfies MFA as usual. The attacker never sees a password prompt and never needs to defeat MFA, because the real user does both steps for them; what the attacker gets back is a valid token. That's why this can't be caught by anything that looks for failed authentication or MFA bypass — from Entra ID's perspective, this was a normal successful sign-in. The only anomaly is the authentication *protocol* itself: device code is a flow built for CLI tools and headless devices, and it's rare for a typical office worker to use it at all.

`SigninLogs` doesn't expose the device code flow as cleanly as `EntraIdSignInEvents` does — there's no single `AuthenticationProtocol == "deviceCode"` column. This query checks both a `ClientAppUsed == "Device Code Flow"` value (the string Entra ID's sign-in UI itself uses for this flow) and a fallback text search over the `AuthenticationDetails` dynamic column, since the exact surfacing of device-code-flow metadata has changed between schema versions and tenant configurations — treat the fallback as a safety net, not the primary signal, and confirm a hit either way in the Entra sign-in log's `Authentication Details` tab before escalating.

The query surfaces every device-code sign-in regardless of location or time — `NewLocation` and `OutsideBusinessHours` are prioritisation flags, not filters, because device-code auth itself is already a narrow enough signal that hiding any of it would be a mistake. The 07:00–19:00 UTC business-hours window is a reasonable default for a single-timezone SME/mid-market org, which is this repo's stated target audience, but it's a guess, not a measured baseline — for a global or follow-the-sun organisation this threshold needs tuning, and you should lean more heavily on `NewLocation` in that case.

**What this won't catch:** An attacker who already knows the victim's usual working hours and approximate location can time the device-code prompt to land inside both flags and still get flagged as suspicious — but only because the query returns everything, not because the flags caught them; if you filter down to just the flagged rows before triage, you could miss it. This query also only detects the device-code vector specifically — it has nothing to say about AiTM reverse-proxy phishing, which is a different mechanism entirely; use `entra-aitm-session-anomalies.kql` for that. And because `SigninLogs` lacks a clean, dedicated device-code column, the `ClientAppUsed`/`AuthenticationDetails` check here is inherently less certain than the XDR version's — if you get a genuinely ambiguous result, cross-check the same window against `EntraIdSignInEvents` in Advanced Hunting if you have access.

```kql
// Platform: Microsoft Sentinel
// Identity — Entra ID device code authentication flow abuse (SigninLogs)
// Device code phishing tricks a user into entering an attacker-generated code at
// microsoft.com/devicelogin, handing the attacker a valid token without the victim
// ever seeing a credential prompt on the attacker's side — MFA gets satisfied by
// the real user, so it doesn't get bypassed, which is what makes this hard to catch
// on MFA-based alerting alone
// SigninLogs has no dedicated AuthenticationProtocol column for this — check both
// ClientAppUsed and a text search over AuthenticationDetails, then confirm any hit
// manually in the sign-in log's Authentication Details tab
// Flags all device-code sign-ins, then highlights the ones from a country the account
// has never signed in from and/or outside business hours — treat any hit as a likely
// initial compromise
// Business hours window: 07:00-19:00 UTC — adjust for your customer timezone
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/scenarios/12-phishing-email/investigation.md

let lookback = 7d;
let baseline_lookback = 37d;
let baseline_gap = 7d;
let business_hours_start = 7;
let business_hours_end = 19;
let KnownLocations = SigninLogs
| where TimeGenerated between (ago(baseline_lookback) .. ago(baseline_gap))
| where ResultType == "0"
| summarize by UserPrincipalName, Location;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ClientAppUsed == "Device Code Flow" or tostring(AuthenticationDetails) has "deviceCode"
| extend HourUTC = hourofday(TimeGenerated)
| extend OutsideBusinessHours = HourUTC !between (business_hours_start .. business_hours_end)
| extend MfaNotRequired = AuthenticationRequirement != "multiFactorAuthentication"
| join kind=leftouter KnownLocations on UserPrincipalName, Location
| extend NewLocation = isnull(Location1)
| project TimeGenerated, UserPrincipalName, Location, IPAddress,
    ResultType, ConditionalAccessStatus, AuthenticationRequirement,
    MfaNotRequired, NewLocation, OutsideBusinessHours, DeviceDetail
| order by TimeGenerated desc
```

### False positives
- Legitimate device code flows for CLI tools and headless devices (Azure CLI on a server, `az login --use-device-code`, some IoT/kiosk enrollment flows). Confirm with the account owner or IT whether they intentionally used a device-code sign-in — this is rare enough in most SME/mid-market tenants that any hit should still be verified, not auto-dismissed.
- Conference-room or shared devices enrolling via device code during initial setup — check the device/location against known IT deployment activity.
- New starters signing in for the first time will always show `NewLocation = true`; that flag alone isn't suspicious, correlate it with `OutsideBusinessHours` and the account's onboarding date.
- See [docs/reference/common-false-positives.md](../../../docs/reference/common-false-positives.md) for the wider false-positive reference.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

entra-device-code-auth-flow.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no device code authentication flows detected in the review window
        [ ] Results found — see findings below

Findings:
  Account(s):
  IP address(es):
  Location(s):
  Timeframe:
  Notes:

Conclusion:
  [ ] No suspicious activity identified — no device code sign-ins identified for this account/tenant in the review window
  [ ] Suspicious activity identified — escalating
  [ ] False positive — reason:

─────────────────────────────────────────────────────────────
```
