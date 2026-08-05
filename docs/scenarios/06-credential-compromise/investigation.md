# Credential compromise — investigation

## Why this is the critical pivot point

If malware has credentials, a single infected device becomes a full breach. This is where you check whether containment has already failed.

---

> **Before escalating:** check [common false positives — Credential access](../../reference/common-false-positives.md#credential-access) — confirm this isn't one of the known benign patterns before treating it as a true positive.

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

After T0, does the account appear on devices it doesn't normally access?

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
DeviceEvents
| where DeviceName == "HOSTNAME"
| where ActionType == "OpenProcessApiCall"
| where AdditionalFields has "lsass"
| where TimeGenerated > ago(24h)
| project TimeGenerated, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AdditionalFields
```

### Credential dumping tools in command lines
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has_any (
    "sekurlsa::", "lsadump::", "mimikatz",
    "DCSync", "GetUserSPNs", "Invoke-Kerberoast",
    "GetNPUsers", "ntdsutil",
    "reg save HKLM\\SAM", "reg save HKLM\\SYSTEM")
| project TimeGenerated, DeviceName, AccountName,
    FileName, ProcessCommandLine
```

### User on multiple devices
```kql
DeviceLogonEvents
| where AccountName == "USERNAME"
| where LogonType in ("Network", "RemoteInteractive")
| where TimeGenerated > ago(24h)
| summarize Devices = make_set(DeviceName), LogonCount = count() by AccountName
| where array_length(Devices) > 2
```

### Entra ID impossible travel
```kql
EntraIdSignInEvents
| where TimeGenerated > ago(7d)
| where ErrorCode == 0
| summarize Locations = make_set(Country), SignInCount = count()
    by AccountUpn, bin(TimeGenerated, 1h)
| where array_length(Locations) > 1
| project TimeGenerated, AccountUpn, Locations, SignInCount
```

### MFA fatigue
```kql
EntraIdSignInEvents
| where TimeGenerated > ago(24h)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ErrorCode != 0
| summarize MFAPrompts = count(), SourceIPs = make_set(IPAddress)
    by AccountUpn, bin(TimeGenerated, 10m)
| where MFAPrompts >= 5
| order by MFAPrompts desc
```
