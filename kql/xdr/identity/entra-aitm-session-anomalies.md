## entra-aitm-session-anomalies.kql

**MITRE:** T1539 — Steal Web Session Cookie  
**Tables:** EntraIdSignInEvents  
**Platform:** Microsoft Defender XDR Advanced Hunting (native). Time column is `Timestamp`. `EntraIdSignInEvents` is not a Sentinel-native table — the Sentinel equivalent is `SigninLogs` (via the Azure AD / Entra ID connector), which has a different schema. See [kql/sentinel/identity/entra-aitm-session-anomalies.kql](../../sentinel/identity/entra-aitm-session-anomalies.kql) for the Sentinel version  
**Licence:** Microsoft Defender for Cloud Apps, or Entra ID P1/P2 with Identity Protection integrated into Defender XDR  
**When to use:** MFA was satisfied but something about the session still looks wrong — a risky sign-in alert fired despite successful MFA, or you're proactively hunting for AiTM reverse-proxy phishing (Evilginx, EvilProxy) across the tenant.

### Why this query

An AiTM reverse proxy sits between the victim and Entra ID, transparently relaying every step of a real sign-in — including the MFA challenge — so the victim completes an entirely normal, successful authentication. What the attacker actually steals isn't a password or a second factor; it's the session token issued at the end of that exchange, which they lift from the proxied traffic and replay from their own infrastructure. Because the sign-in itself was genuine, there's no failed-MFA or wrong-password signal to catch. What's left are the downstream artefacts of the token being used somewhere the real user wasn't: a different IP picking up the session, the account appearing in two countries too close together in time, a "compliant device" session suddenly showing no compliance state, or a client string that doesn't match what approved the MFA prompt.

Each of the four checks reuses a window chosen to match how fast a stolen token typically gets used. The 30-minute window on token replay and UserAgent mismatch is short enough that ordinary causes — a VPN rotating egress IPs, a user switching from Wi-Fi to cellular — are less likely to coincide by chance, but long enough to catch an attacker who doesn't act on the stolen token instantly. The impossible-travel window is 1 hour, reused directly from `entra-impossible-travel.kql` so the two queries agree on what "impossible" means across this repo.

**What this won't catch:** An AiTM kit that's careful about IP hygiene — relaying through infrastructure in the same country or city as the victim — won't trip Token Replay or Impossible Travel, since those depend on the attacker's IP looking geographically wrong. A kit that proxies the *entire* session end-to-end, not just the login, may never show a distinct "activity from a different IP" at all. And an attacker who sits on a stolen token for longer than these windows before using it evades every check here, since they're all time-boxed. This query detects the aftermath of token theft, not the phishing email that delivered it — see `docs/scenarios/12-phishing-email/investigation.md` for the delivery-stage indicators, and pair this with `aitm-phishing-to-persistence.kql` to check whether the attacker has already moved on to planting persistence.

```kql
// Platform: Microsoft Defender XDR Advanced Hunting
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

let lookback = 24h;
let baseline_lookback = 30d;
let Window = 30m;
let TokenReplay = EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where ErrorCode == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| project AccountUpn, MfaTime = Timestamp, MfaIP = IPAddress, MfaCountry = Country
| join kind=inner (
    EntraIdSignInEvents
    | where Timestamp > ago(lookback)
    | where ErrorCode == 0
    | where IsInteractive == false
    | project AccountUpn, ActTime = Timestamp, ActIP = IPAddress, ActCountry = Country
) on AccountUpn
| where ActTime between (MfaTime .. (MfaTime + Window))
| where ActIP != MfaIP
| extend Reason = "Token replay — activity IP differs from MFA sign-in IP"
| project Timestamp = ActTime, AccountUpn, Reason, MfaIP, ActIP, MfaCountry, ActCountry;
let ImpossibleTravelPostMfa = EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where ErrorCode == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize Countries = make_set(Country), IPs = make_set(IPAddress)
    by AccountUpn, bin(Timestamp, 1h)
| where array_length(Countries) > 1
| extend Reason = "Impossible travel following successful MFA"
| project Timestamp, AccountUpn, Reason,
    MfaIP = tostring(IPs[0]), ActIP = tostring(IPs[-1]),
    MfaCountry = tostring(Countries[0]), ActCountry = tostring(Countries[-1]);
let ComplianceDrop = EntraIdSignInEvents
| where Timestamp > ago(baseline_lookback) and Timestamp < ago(lookback)
| where ErrorCode == 0
| where IsCompliant == true
| summarize by AccountUpn
| join kind=inner (
    EntraIdSignInEvents
    | where Timestamp > ago(lookback)
    | where ErrorCode == 0
    | where IsCompliant == false or isempty(IsCompliant)
) on AccountUpn
| extend Reason = "No device compliance state after previously compliant sessions"
| project Timestamp, AccountUpn, Reason,
    MfaIP = "", ActIP = IPAddress, MfaCountry = "", ActCountry = Country;
let UserAgentMismatch = EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where ErrorCode == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| project AccountUpn, MfaTime = Timestamp, MfaUA = UserAgent
| join kind=inner (
    EntraIdSignInEvents
    | where Timestamp > ago(lookback)
    | where ErrorCode == 0
    | project AccountUpn, ActTime = Timestamp, ActUA = UserAgent,
        ActIP = IPAddress, ActCountry = Country
) on AccountUpn
| where ActTime between (MfaTime .. (MfaTime + Window))
| where ActUA != MfaUA
| extend Reason = "UserAgent mismatch between MFA approval and subsequent activity"
| project Timestamp = ActTime, AccountUpn, Reason,
    MfaIP = "", ActIP, MfaCountry = "", ActCountry;
union TokenReplay, ImpossibleTravelPostMfa, ComplianceDrop, UserAgentMismatch
| order by Timestamp desc
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
