## entra-device-code-auth-flow.kql

**MITRE:** T1556.006 — Modify Authentication Process: Multi-Factor Authentication  
**Tables:** EntraIdSignInEvents  
**Platform:** Defender XDR Advanced Hunting only. `EntraIdSignInEvents` is not a Sentinel-native table — the Sentinel equivalent is `SigninLogs` (via the Azure AD / Entra ID connector), which has a different schema; native Advanced Hunting also uses `Timestamp` rather than this repo's `TimeGenerated` alias  
**Licence:** Microsoft Defender for Cloud Apps, or Entra ID P1/P2 with Identity Protection integrated into Defender XDR  
**When to use:** You suspect device code phishing — a user reports being asked to enter a code at microsoft.com/devicelogin, or you're proactively hunting for this initial-access vector across the tenant.

### Why this query

Device code phishing works by getting the victim to complete a normal, legitimate-looking sign-in — the user goes to microsoft.com/devicelogin themselves, enters a code the attacker generated, and satisfies MFA as usual. The attacker never sees a password prompt and never needs to defeat MFA, because the real user does both steps for them; what the attacker gets back is a valid token. That's why this can't be caught by anything that looks for failed authentication or MFA bypass — from Entra ID's perspective, this was a normal successful sign-in. The only anomaly is the authentication *protocol* itself: `deviceCode` is a flow built for CLI tools and headless devices, and it's rare for a typical office worker to use it at all.

The query surfaces every device-code sign-in regardless of location or time — `NewLocation` and `OutsideBusinessHours` are prioritisation flags, not filters, because device-code auth itself is already a narrow enough signal that hiding any of it would be a mistake. The 07:00–19:00 UTC business-hours window is a reasonable default for a single-timezone SME/mid-market org, which is this repo's stated target audience, but it's a guess, not a measured baseline — for a global or follow-the-sun organisation this threshold needs tuning, and you should lean more heavily on `NewLocation` in that case.

**What this won't catch:** An attacker who already knows the victim's usual working hours and approximate location (easy to infer from a prior phishing email, LinkedIn, or a previous reconnaissance pass) can time the device-code prompt to land inside both flags and still get flagged as suspicious — but only because the query returns everything, not because the flags caught them; if you filter down to just the flagged rows before triage, you could miss it. This query also only detects the device-code vector specifically — it has nothing to say about AiTM reverse-proxy phishing, which is a different mechanism entirely and doesn't use `deviceCode` as the `AuthenticationProtocol`; use `entra-aitm-session-anomalies.kql` for that.

```kql
// Identity — Entra ID device code authentication flow abuse
// Device code phishing tricks a user into entering an attacker-generated code at
// microsoft.com/devicelogin, handing the attacker a valid token without the victim
// ever seeing a credential prompt on the attacker's side — MFA gets satisfied by
// the real user, so it doesn't get bypassed, which is what makes this hard to catch
// on MFA-based alerting alone
// Flags all deviceCode sign-ins, then highlights the ones from a country the account
// has never signed in from and/or outside business hours — treat any hit as a likely
// initial compromise
// ASN is not a native column on this table — cross-reference IPAddress against known
// corporate/ISP ranges manually for the unusual-ASN check
// Business hours window: 07:00-19:00 UTC — adjust for your customer timezone
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/scenarios/12-phishing-email/investigation.md

let KnownLocations = EntraIdSignInEvents
| where TimeGenerated between (ago(37d) .. ago(7d))
| where ErrorCode == 0
| summarize by AccountUpn, Country;
EntraIdSignInEvents
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol == "deviceCode"
| extend HourUTC = hourofday(TimeGenerated)
| extend OutsideBusinessHours = HourUTC !between (7 .. 19)
| join kind=leftouter KnownLocations on AccountUpn, Country
| extend NewLocation = isnull(Country1)
| project TimeGenerated, AccountUpn, Country, IPAddress, UserAgent,
    ErrorCode, NewLocation, OutsideBusinessHours, AuthenticationRequirement
| order by TimeGenerated desc
```

### False positives
- Legitimate device code flows for CLI tools and headless devices (Azure CLI on a server, `az login --use-device-code`, some IoT/kiosk enrollment flows). Confirm with the account owner or IT whether they intentionally used a device-code sign-in — this is rare enough in most SME/mid-market tenants that any hit should still be verified, not auto-dismissed.
- Conference-room or shared devices enrolling via device code during initial setup — check the device/location against known IT deployment activity.
- New starters signing in for the first time will always show `NewLocation = true`; that flag alone isn't suspicious, correlate it with `OutsideBusinessHours` and the account's onboarding date.

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
