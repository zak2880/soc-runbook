# Credential compromise — investigation

## Why this is the critical pivot point

If malware has credentials, a single infected device becomes a full breach. This is where you check whether containment has already failed.

---

## Credential dumping

Other credential-theft queries in the library, beyond the ones below: [credential-dump-artefacts.kql](../../../kql/identity/credential-dump-artefacts.kql) (comsvcs, procdump, ntdsutil IFM, esentutl, shadow-copy copies and the files they leave), [browser-credential-theft.kql](../../../kql/identity/browser-credential-theft.kql) (browser stores and session cookies), [credential-store-and-secret-hunting.kql](../../../kql/identity/credential-store-and-secret-hunting.kql) (Credential Manager, vaults, secret files), and, once theft is confirmed, [entra-signin-after-endpoint-compromise.kql](../../../kql/identity/entra-signin-after-endpoint-compromise.kql) and [m365-mailbox-forwarding-rules.kql](../../../kql/exfiltration/m365-mailbox-forwarding-rules.kql) to see whether the stolen access was used.

### lsass.exe access

`lsass.exe` is the Local Security Authority process. Without Credential Guard, Windows keeps secrets such as NTLM password hashes and Kerberos TGTs in its memory. Mimikatz and similar tools read them from there.

> Any process opening `lsass.exe` that is not a verified security product, any lsass dump command or tool, or an lsass dump file on disk = isolate the device and escalate. This is the one lsass rule for this scenario.

"Non-Windows process" is not the test. The comsvcs dump below runs as `rundll32.exe`, a Windows binary.

A security product counts as verified only when both hold:
- The process runs from the vendor's install folder.
- `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` and `IsTrusted` is true.

Don't rely on `InitiatingProcessVersionInfoCompanyName`. It is read from the file's own version information, which whoever built the file sets.

**Classic dump via comsvcs.dll:**
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Users\Public\lsass.dmp full
```
The number (624 here) is the PID of `lsass.exe` on that host when the command ran. Confirm it against `lsass.exe` in `DeviceProcessEvents` for that device; don't search for 624 on other hosts. The last path is the dump file. The [lolbin sweep](../../../kql/process/lolbin-sweep.kql) matches `comsvcs` and `MiniDump` in rundll32 command lines; the credential sweep below does not.

**The dump file.** Record the output path from the command line and what Live Response `fileinfo` returns for it. Don't download it: it holds the stolen credentials. Don't delete it. The IR lead decides on collection. If the file is gone, it may have been moved or exfiltrated; that doesn't mean there was no dump.

**Was it blocked?** If the ASR rule "Block credential stealing from the Windows local security authority subsystem" is deployed, check `DeviceEvents` for `AsrLsassCredentialTheftBlocked` or `AsrLsassCredentialTheftAudited` from the suspect process. Microsoft says most of this rule's audit events are safe to ignore, so weigh only events from the process you are investigating. A block means that one access was denied. It doesn't clear the device: the attacker had the rights to try and may have used another route (comsvcs, a dump tool, the SAM hive). Still escalate.

**Who is exposed after a dump.** Treat every account with a logon on the host as exposed, not only the user in the alert. That includes other users, admins who connected for support, and service and scheduled-task accounts. List them from `DeviceLogonEvents` for this device: successful logons, every `LogonType` (including `Service` and `Batch`), from 30 days before T0 to now. Flag privileged accounts first.

Credential Guard doesn't change this. Microsoft lists what it doesn't protect, including local accounts, Kerberos service tickets and NTLM credentials typed at a prompt. It also doesn't stop malware on the device from using the privileges of any credential there.

### SAM and NTDS.dit

- `SAM` — local account password hashes
- `NTDS.dit` — full Active Directory credential database (domain controllers)

Don't look for a "SAM read" or "NTDS.dit accessed" event. Microsoft describes `DeviceFileEvents` as file creation, modification and other file system events, and documents no read events. Hunt the theft method instead:

- `reg save HKLM\SAM`, `HKLM\SYSTEM` or `HKLM\SECURITY`: in the credential sweep below.
- `ntdsutil` or `ntds.dit` in a command line: in the credential sweep below.
- Shadow-copy routes: any `vssadmin` command line is matched by [vss-shadow-copy-deletion.kql](../../../kql/ransomware/vss-shadow-copy-deletion.kql), whose header is about deletion but whose filter matches `vssadmin create shadow` too. `esentutl` and copies from `HarddiskVolumeShadowCopy` are in no query here; search the device timeline by hand.
- DCSync: `DCSync`, `drsuapi` or `DrsGetNCChanges` in the credential sweep. If Defender for Identity is deployed, also check for its alert "Suspected DCSync attack (replication of directory services)".

Any of these = escalate. NTDS.dit theft or DCSync puts every domain credential at risk.

### Kerberoasting and AS-REP roasting

The credential sweep matches `GetUserSPNs`, `Invoke-Kerberoast`, `GetNPUsers` and `ASREPRoast`. A hit means the targeted accounts' tickets may already be off the network for offline cracking; isolating the device doesn't undo that. Record every account named in the command line and treat it as exposed. If Defender for Identity is deployed, check for "Suspected Kerberos SPN exposure" and "Suspected AS-REP Roasting attack".

---

## Lateral movement

### Account on new devices post-infection

After T0, does any exposed account appear on devices it has no documented reason to access? Check every account from "Who is exposed after a dump", not only the one in the alert. Advanced Hunting holds 30 days of native data; activity older than that needs Sentinel retention.

An account seen on many devices is a reason to scope wider, never a reason to close. A service account that was a Kerberoasting or AS-REP target, or had a logon on the dumped host, is the attacker's until you prove otherwise.

### Remote execution tools

| Tool | What to look for |
|------|-----------------|
| PsExec | `psexec.exe` on the source; a new service and `ADMIN$` share access on the target. PsExec's `-r` option sets the service name, so don't rely on the name `psexesvc.exe` alone |
| WMI remote | Source: `wmic.exe /node:"IP" process call create`. Target: processes started by the WMI provider host `WmiPrvSE.exe` around that time. VERIFY (tenant): that remote WMI shows this parent in your data. Remote WMI doesn't need `wmic.exe`, so no `wmic.exe` command line doesn't clear the account |
| WinRM | `wsmprovhost.exe` as parent on the remote host |
| RDP | `LogonType = RemoteInteractive` from unusual source IP |

---

## Entra ID anomalies

| Indicator | What to look for |
|-----------|-----------------|
| Entra ID Protection | Check first: Risky users and Risk detections for the account. Relevant detections include "Suspicious MFA authentication approval", "Attacker in the Middle", "Anomalous token", "Password spray" and "Unfamiliar sign-in properties". Without Entra ID P2, most appear only as "Additional risk detected" |
| New location | Country/city the user has never used |
| Impossible travel | Two countries within minutes of each other |
| MFA fatigue | Many MFA push prompts in a short window, then whether one was approved (see the success check under the MFA fatigue query) |
| Legacy auth | Sign-in via IMAP/POP3/SMTP. Legacy protocols don't support MFA, so the password alone is enough. In the Entra sign-in logs, filter on the Client App column, on both the interactive and the non-interactive tabs |

No row firing doesn't clear the account. A stolen session token replayed from the user's usual country trips none of the location rows; the ID Protection token detections are the check for that.

The two Entra queries below run tenant-wide. Filter the results to the account under investigation by `AccountUpn` (the full UPN, not the SAM name).

---

## KQL queries

### lsass access

An empty result doesn't clear the device. The query's VERIFY note says the lsass target may be in `FileName`, not `AdditionalFields`; run the check query in that note first.

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
// not yet migrated to EntraIdSignInEvents. In Sentinel use SigninLogs instead
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
// not yet migrated to EntraIdSignInEvents. In Sentinel use SigninLogs instead
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

**Success check.** The query keeps only failed sign-ins, so it shows the attempt, not the outcome. Then open the Entra sign-in logs (interactive and non-interactive), filter to the user, and look for a successful sign-in from the first failed prompt to now. A success from an IP or country in the burst's `SourceIPs` or `Countries`, or one the user doesn't recognise = the account is compromised.

No success still isn't a clear. Treat the password as known to the attacker unless the sign-in details show the first factor failed. VERIFY (tenant): where your sign-in logs show the result of each authentication step.
