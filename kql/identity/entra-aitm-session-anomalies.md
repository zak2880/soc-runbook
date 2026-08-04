## entra-aitm-session-anomalies.kql

**MITRE:** T1539 — Steal Web Session Cookie  
**Tables:** AADSignInEventsBeta  
**Platform:** Defender XDR Advanced Hunting only. `AADSignInEventsBeta` is not a Sentinel-native table — the Sentinel equivalent is `SigninLogs` (via the Azure AD / Entra ID connector), which has a different schema; native Advanced Hunting also uses `Timestamp` rather than this repo's `TimeGenerated` alias  
**Licence:** Microsoft Defender for Cloud Apps, or Entra ID P1/P2 with Identity Protection integrated into Defender XDR  
**When to use:** MFA was satisfied but something about the session still looks wrong — a risky sign-in alert fired despite successful MFA, or you're proactively hunting for AiTM reverse-proxy phishing (Evilginx, EvilProxy) across the tenant.

```kql
// Identity — Adversary-in-the-Middle (AiTM) phishing session anomalies
// AiTM reverse-proxy kits (Evilginx, Modlishka, EvilProxy) sit between the user and
// Entra ID, relay the real MFA challenge, then steal the resulting session token —
// the attacker never needs the password or a second factor, just the cookie
// Four independent indicators, unioned with a Reason column:
//   1. Token replay      — non-interactive activity from an IP that differs from the
//                          IP that completed the MFA challenge, within 30 minutes
//   2. Impossible travel  — two countries for the same account within 1 hour of MFA
//   3. Compliance drop    — account was previously seen from a compliant device, then
//                          shows a sign-in with no compliant device state
//   4. UserAgent mismatch — the client string on the MFA approval differs from the
//                          client string on subsequent activity in the same session
// Any single hit warrants investigation; multiple hits for the same account in the
// same window = high-confidence AiTM token theft
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/scenarios/12-phishing-email/investigation.md

let Window = 30m;
let TokenReplay = AADSignInEventsBeta
| where TimeGenerated > ago(24h)
| where ErrorCode == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| project AccountUpn, MfaTime = TimeGenerated, MfaIP = IPAddress, MfaCountry = Country
| join kind=inner (
    AADSignInEventsBeta
    | where TimeGenerated > ago(24h)
    | where ErrorCode == 0
    | where IsInteractive == false
    | project AccountUpn, ActTime = TimeGenerated, ActIP = IPAddress, ActCountry = Country
) on AccountUpn
| where ActTime between (MfaTime .. (MfaTime + Window))
| where ActIP != MfaIP
| extend Reason = "Token replay — activity IP differs from MFA sign-in IP"
| project TimeGenerated = ActTime, AccountUpn, Reason, MfaIP, ActIP, MfaCountry, ActCountry;
let ImpossibleTravelPostMfa = AADSignInEventsBeta
| where TimeGenerated > ago(24h)
| where ErrorCode == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize Countries = make_set(Country), IPs = make_set(IPAddress)
    by AccountUpn, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1
| extend Reason = "Impossible travel following successful MFA"
| project TimeGenerated, AccountUpn, Reason,
    MfaIP = tostring(IPs[0]), ActIP = tostring(IPs[-1]),
    MfaCountry = tostring(Countries[0]), ActCountry = tostring(Countries[-1]);
let ComplianceDrop = AADSignInEventsBeta
| where TimeGenerated > ago(30d) and TimeGenerated < ago(24h)
| where ErrorCode == 0
| where IsCompliant == true
| summarize by AccountUpn
| join kind=inner (
    AADSignInEventsBeta
    | where TimeGenerated > ago(24h)
    | where ErrorCode == 0
    | where IsCompliant == false or isempty(IsCompliant)
) on AccountUpn
| extend Reason = "No device compliance state after previously compliant sessions"
| project TimeGenerated, AccountUpn, Reason,
    MfaIP = "", ActIP = IPAddress, MfaCountry = "", ActCountry = Country;
let UserAgentMismatch = AADSignInEventsBeta
| where TimeGenerated > ago(24h)
| where ErrorCode == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| project AccountUpn, MfaTime = TimeGenerated, MfaUA = UserAgent
| join kind=inner (
    AADSignInEventsBeta
    | where TimeGenerated > ago(24h)
    | where ErrorCode == 0
    | project AccountUpn, ActTime = TimeGenerated, ActUA = UserAgent,
        ActIP = IPAddress, ActCountry = Country
) on AccountUpn
| where ActTime between (MfaTime .. (MfaTime + Window))
| where ActUA != MfaUA
| extend Reason = "UserAgent mismatch between MFA approval and subsequent activity"
| project TimeGenerated = ActTime, AccountUpn, Reason,
    MfaIP = "", ActIP, MfaCountry = "", ActCountry;
union TokenReplay, ImpossibleTravelPostMfa, ComplianceDrop, UserAgentMismatch
| order by TimeGenerated desc
```

### False positives
- Corporate VPN or proxy egress changing the apparent IP mid-session for entirely legitimate reasons (split-tunnel VPN switching, load-balanced egress). Confirm whether the org uses a VPN/proxy that rotates egress IPs before treating token replay as confirmed.
- Mobile users switching between Wi-Fi and cellular mid-session — can trigger both token-replay and impossible-travel indicators over a short window. Check whether the two IPs/countries are geographically plausible for a fast network handover (e.g. same city, different ASN) vs genuinely impossible (different continents).
- A device compliance policy change or re-enrollment can cause a legitimate temporary compliance-state drop. Check Intune/Entra device management logs for a corresponding re-enrollment event before escalating on Compliance Drop alone.
- Browser vs native-app UserAgent differences for the same user during normal multi-app use (e.g. approving MFA in a browser, then working from a desktop client) — confirm both UserAgents belong to legitimate, expected software before treating a mismatch as suspicious.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

entra-aitm-session-anomalies.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no AiTM session anomalies or token replay indicators detected
        [ ] Results found — see findings below

Findings:
  Account(s):
  IP address(es):
  Location(s):
  Timeframe:
  Notes:

Conclusion:
  [ ] No suspicious activity identified — no token replay, post-MFA impossible travel, compliance-state drop, or UserAgent mismatch identified for this account
  [ ] Suspicious activity identified — escalating
  [ ] False positive — reason:

─────────────────────────────────────────────────────────────
```
