# Credential compromise — investigation

## Why this is the critical pivot point

If malware has credentials, a single infected device becomes a full breach. This is where you check whether containment has already failed.

---

## Credential dumping

### lsass.exe access

`lsass.exe` holds cached credentials in memory. Mimikatz and similar tools access it directly.

> Any non-Windows process accessing `lsass.exe` = escalate immediately.

**Classic dump via comsvcs.dll:**
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Users\Public\lsass.dmp full
```
The number (624) is the PID of lsass.exe. Near-certain credential theft — escalate now.

### SAM and NTDS.dit

- `SAM` — local account password hashes
- `NTDS.dit` — full Active Directory credential database

Either accessed by a non-system process = critical indicator.

---

## Lateral movement

### Account on new devices post-infection

After T0, does the account appear on devices it doesn't normally access? Advanced Hunting holds 30 days of native data; activity older than that needs Sentinel retention.

### Remote execution tools

| Tool | What to look for |
|------|-----------------|
| PsExec | `psexec.exe` / `psexesvc.exe`, `ADMIN$` share access |
| WMI remote | `wmic.exe /node:"IP" process call create` |
| WinRM | `wsmprovhost.exe` as parent on the remote host |
| RDP | `LogonType = RemoteInteractive` from unusual source IP |

---

## Entra ID anomalies

| Indicator | What to look for |
|-----------|-----------------|
| New location | Country/city the user has never used |
| Impossible travel | Two countries within minutes of each other |
| MFA fatigue | Many MFA push prompts in a short window |
| Legacy auth | Sign-in via IMAP/POP3/SMTP — bypasses MFA |

---

## KQL queries

### lsass access
```kql
// Identity — lsass.exe access (credential dumping signal)
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1003.001
// Any non-Windows process opening lsass = likely credential theft attempt
// Covers: Mimikatz-style direct access and comsvcs.dll MiniDump technique
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// Remove the device filter to monitor estate-wide
// VERIFY: the lsass target may be in FileName rather than AdditionalFields; compare before trusting
// an empty result: DeviceEvents | where ActionType == "OpenProcessApiCall" | where FileName =~ "lsass.exe" | take 10
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/reference/escalation-triggers.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceEvents
| where DeviceName startswith "HOSTNAME"
| where ActionType == "OpenProcessApiCall"
| where AdditionalFields has "lsass"
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| project Timestamp, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AdditionalFields
```

### Credential dumping tools in command lines
```kql
// Process — credential access sweep
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1003.001, T1003.002, T1003.003, T1003.006, T1558.003, T1558.004
// Hunts for Mimikatz keywords, credential dumping tools, and related command patterns
// Covers: sekurlsa, lsadump, kerberos ticket dumping, NTLM hash dumping, DCSync
// Any hit here = escalate immediately
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/reference/escalation-triggers.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
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
| project Timestamp, DeviceName, AccountName,
    FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### User on multiple devices
```kql
// Identity — compromised user account appearing on multiple devices
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1021.001
// Indicates lateral movement using stolen credentials
// Run after identifying a compromised account to check for spread since T0
// Replace USERNAME with the SAM account name (e.g. jsmith), not the UPN or display name
// Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention
// Ref: docs/scenarios/06-credential-compromise/investigation.md, docs/scenarios/01-malware-alert/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceLogonEvents
| where Timestamp between ((T0 - 1h) .. (T0 + 30d))
| where AccountName =~ "USERNAME"
| where LogonType in ("Network", "RemoteInteractive")
    // VERIFY: LogonType strings (Learn describes them, does not list the exact values):
    // DeviceLogonEvents | where Timestamp > ago(7d) | summarize count() by LogonType, ActionType
| summarize
    Devices = make_set(DeviceName),
    LogonCount = count()
    by AccountName
| where array_length(Devices) > 2
```

### Entra ID impossible travel
```kql
// Identity — Entra ID impossible travel detection
// Runs in: Defender XDR Advanced Hunting only
// MITRE: T1078
// AADSignInEventsBeta is deprecated (Microsoft: replaced by EntraIdSignInEvents from 19 Oct 2026);
// not migrated in this batch. In Sentinel use SigninLogs instead
// Flags accounts signing in from two different countries within a short window
// Indicates credential compromise and use from a foreign location
// Adjust the window (currently 1 hour) based on your environment
// Ref: docs/scenarios/06-credential-compromise/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
let Window = 1h;
AADSignInEventsBeta
| where Timestamp between ((T0 - 7d) .. (T0 + 1d))
| where ErrorCode == 0  // successful sign-ins only
| summarize
    Locations = make_set(Country),
    SignInCount = count(),
    IPAddresses = make_set(IPAddress)
    by AccountUpn, bin(Timestamp, Window)
| where array_length(Locations) > 1
| project Timestamp, AccountUpn, Locations,
    SignInCount, IPAddresses
| order by Timestamp desc
```

### MFA fatigue
```kql
// Identity — Entra ID MFA fatigue / MFA push bombing
// Runs in: Defender XDR Advanced Hunting only
// MITRE: T1621
// AADSignInEventsBeta is deprecated (Microsoft: replaced by EntraIdSignInEvents from 19 Oct 2026);
// not migrated in this batch. In Sentinel use SigninLogs instead
// Attacker has valid credentials and hammers the user with MFA prompts hoping
// they approve one to make it stop
// Threshold: 5+ MFA prompts in 10 minutes — tune for your environment
// Ref: docs/scenarios/06-credential-compromise/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
AADSignInEventsBeta
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ErrorCode != 0  // failed sign-ins — MFA not yet approved
| summarize
    MFAPrompts = count(),
    SourceIPs = make_set(IPAddress),
    Countries = make_set(Country)
    by AccountUpn, bin(Timestamp, 10m)
| where MFAPrompts >= 5
| order by MFAPrompts desc
```
