## device-compromise-to-lateral-movement.kql

**MITRE:** T1078, T1021.002, T1021.006 — Valid Accounts → Remote Services: SMB/Windows Admin Shares, Windows Remote Management  
**Tables:** DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents  
**Platform:** Microsoft Sentinel — via the Microsoft Defender XDR data connector. Time column is `TimeGenerated`. See [kql/xdr/pivots/device-compromise-to-lateral-movement.kql](../../xdr/pivots/device-compromise-to-lateral-movement.kql) for the XDR version  
**Licence:** Microsoft Defender for Endpoint Plan 2 (bundled in Microsoft 365 E5)  
**When to use:** You have a confirmed patient-zero device and an infection time (T0) and need to know, in one pass, whether the compromise actually spread — not just what happened locally on that device.

### Why this query

Once a device is compromised, the attacker's next move is usually to use whatever credentials were live on it to reach further into the network — PsExec, WMI, or WinRM remote execution against internal IPs, using accounts that had no prior reason to log into anywhere else. Seeing remote-execution tooling run *on* the patient-zero device only tells you the attacker tried; it doesn't tell you they succeeded. The actual spread event is a different signal entirely — one of those same accounts authenticating to a *different* device — which is why this query's real payload is the fourth stage, not the third.

The 72-hour forward window is deliberately generous rather than tight, because lateral movement doesn't always happen in the first hour after compromise — a patient attacker may sit for a day or two doing reconnaissance before moving. There's no scoring or threshold beyond that window; every account, internal IP, and remote-exec tool seen in it is surfaced, and the analyst decides what's routine IT activity versus what isn't, using the false-positive guidance below.

**What this won't catch:** The `AccountsUsed` set is built entirely from logons observed *on* the patient-zero device — an attacker who harvests a credential from memory or a config file for an account that never actually logged into that machine interactively (a service account password sitting in a script, for example) will pivot using an account this query never learns about, and `SpreadToOtherDevices` will silently miss it. This also depends heavily on an accurate T0: set it too late and you miss the real first movement; set it too early and you'll pull in unrelated pre-compromise activity that just adds noise to the timeline.

```kql
// Platform: Microsoft Sentinel
// Pivot — device compromise to lateral movement timeline
// Takes a compromised device and its infection time (T0), then follows the account(s)
// used on it forward: internal IPs touched, remote-execution tools observed on the
// patient-zero device, and — the key extra hop — whether any of those same accounts
// subsequently logged into a DIFFERENT device, which is the actual spread event
// Chains: identity (DeviceLogonEvents) -> network (DeviceNetworkEvents) -> process
// (DeviceProcessEvents) -> identity again, estate-wide, for the second-hop spread check
// Remote-execution parents to watch for: wsmprovhost.exe (WinRM), psexesvc.exe
// (PsExec), wmiprvse.exe (WMI)
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/scenarios/10-initial-access/investigation.md

let target_device = "HOSTNAME";                   // patient-zero device
let T0 = datetime(2024-01-01T00:00:00Z);          // infection / compromise time
let window = 72h;                                 // how far forward to look

let AccountsUsed = DeviceLogonEvents
| where DeviceName == target_device
| where TimeGenerated between (T0 .. (T0 + window))
| where LogonType in ("Network", "RemoteInteractive", "Interactive", "Batch", "Service")
| summarize FirstSeen = min(TimeGenerated) by AccountName;
let InternalIPsAccessed = DeviceNetworkEvents
| where DeviceName == target_device
| where TimeGenerated between (T0 .. (T0 + window))
| where RemoteIPType == "Private"
| project TimeGenerated, RemoteIP, RemotePort;
let RemoteExecTools = DeviceProcessEvents
| where DeviceName == target_device
| where TimeGenerated between (T0 .. (T0 + window))
| where InitiatingProcessFileName in~ ("psexesvc.exe", "wmiprvse.exe", "wsmprovhost.exe")
    or FileName in~ ("psexec.exe", "psexec64.exe")
| project TimeGenerated, InitiatingProcessFileName, FileName, ProcessCommandLine;
let SpreadToOtherDevices = DeviceLogonEvents
| where TimeGenerated > T0
| where AccountName in ((AccountsUsed | project AccountName))
| where DeviceName != target_device
| where LogonType in ("Network", "RemoteInteractive", "Interactive")
| project TimeGenerated, DeviceName, AccountName, LogonType;
union
    (AccountsUsed | extend Stage = "1-AccountUsedOnPatientZero", TimelineTime = FirstSeen),
    (InternalIPsAccessed | extend Stage = "2-InternalIPAccessed", TimelineTime = TimeGenerated),
    (RemoteExecTools | extend Stage = "3-RemoteExecTool", TimelineTime = TimeGenerated),
    (SpreadToOtherDevices | extend Stage = "4-AccountSpreadToOtherDevice", TimelineTime = TimeGenerated)
| order by TimelineTime asc
```

### False positives
- SCCM/Intune/RMM agents legitimately use WMI, WinRM, and service accounts across many devices — a `Stage 4` hit for a known IT service account performing a scheduled patch deployment is expected. Confirm `AccountName` against your list of automation/service accounts before escalating.
- Helpdesk staff performing legitimate remote support (RDP/WinRM) to the same device shortly after a user reported an issue — check whether the "spread" account is a known IT admin and whether the timing lines up with a support ticket.
- `InternalIPsAccessed` will always include normal infrastructure (DNS, DHCP, print servers, domain controllers) — focus on ports/hosts outside routine business traffic (SMB/RDP/WinRM to peer workstations) rather than every row.

### Investigation notes
```
─────────────────────────────────────────────────────────────
INVESTIGATION NOTES — copy paste into ticket / incident report
─────────────────────────────────────────────────────────────

device-compromise-to-lateral-movement.kql — [date run: YYYY-MM-DD] — Analyst: [initials]

Result: [ ] No results — no accounts, internal IPs, remote-execution tools, or cross-device account spread identified in the window following T0
        [ ] Results found — see findings below

Findings:
  Patient-zero device:
  Account(s) used:
  Internal IP(s) accessed:
  Other device(s) account spread to:
  Timeframe:
  Notes:

Conclusion:
  [ ] No suspicious activity identified — no lateral movement identified from this device following compromise
  [ ] Suspicious activity identified — escalating
  [ ] False positive — reason:

─────────────────────────────────────────────────────────────
```
