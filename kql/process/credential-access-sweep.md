## credential-access-sweep.kql

**MITRE:** T1003, T1558 — OS Credential Dumping / Steal or Forge Kerberos Tickets  
**Tables:** DeviceProcessEvents  
**Platform:** Defender XDR / Sentinel — native Defender Advanced Hunting uses `Timestamp` as the time column; this repo's queries use `TimeGenerated` to match the Sentinel Log Analytics schema (rename if pasting directly into the Defender portal)  
**Licence:** Microsoft Defender for Endpoint Plan 2 (bundled in Microsoft 365 E5)  
**When to use:** Run estate-wide as a daily/hourly hunt, or scoped to a device already flagged for suspicious activity, to catch Mimikatz-style credential theft, DCSync, Kerberoasting, or AS-REP roasting in command-line telemetry.

```kql
// Process — credential access sweep
// Hunts for Mimikatz keywords, credential dumping tools, and related command patterns
// Covers: sekurlsa, lsadump, kerberos ticket dumping, NTLM hash dumping, DCSync
// Any hit here = escalate immediately
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/reference/escalation-triggers.md

DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has_any (
    // Mimikatz modules
    "sekurlsa::", "lsadump::", "kerberos::",
    "privilege::debug", "token::elevate",
    "vault::cred", "dpapi::",
    // Common Mimikatz invocations
    "mimikatz", "mimi32", "mimilib",
    // DCSync (domain credential replication abuse)
    "DCSync", "dcsync",
    "drsuapi", "DrsGetNCChanges",
    // Credential dumping tools
    "LaZagne", "lazagne",
    "pwdump", "fgdump",
    "gsecdump", "wce.exe",
    // NTDS / SAM dumping
    "ntdsutil", "ntds.dit",
    "reg save HKLM\\SAM",
    "reg save HKLM\\SYSTEM",
    "reg save HKLM\\SECURITY",
    // Kerberoasting
    "GetUserSPNs", "Invoke-Kerberoast",
    "Request-SPNTicket",
    // AS-REP roasting
    "GetNPUsers", "ASREPRoast",
    // Token manipulation
    "Invoke-TokenManipulation",
    "ImpersonateLoggedOnUser")
| project TimeGenerated, DeviceName, AccountName,
    FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

### False positives
- Authorised penetration testing or red team engagements running these exact tools — confirm against the client's scan/engagement schedule before treating as a true positive; this is one of the very few detections in this repo where an FP is expected to be rare and should still be verified with the client, not silently dismissed.
- Security awareness/training platforms that simulate credential-dumping command lines for phishing/attack simulation exercises — check `InitiatingProcessFileName` and parent process against known simulation tooling (e.g. KnowBe4, Attack simulator).
- `reg save HKLM\SAM`/`SYSTEM`/`SECURITY` used by legitimate backup or migration tooling taking a system-state backup — confirm the initiating process is a known backup agent (Veeam, Acronis) rather than an interactive shell.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

credential-access-sweep.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no Mimikatz, DCSync, Kerberoasting, AS-REP roasting, or credential-dumping tool command lines detected
        [ ] Results found — see findings below

Findings:
  Device(s):
  Account(s):
  Command line / tool observed:
  Timeframe:
  Notes:

Conclusion:
  [ ] No suspicious activity identified — no credential dumping tool signatures identified in process command lines for the review window
  [ ] Suspicious activity identified — escalating
  [ ] False positive — reason:

─────────────────────────────────────────────────────────────
```
