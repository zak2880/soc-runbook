# Identity & credentials

## Why this is the critical pivot point

If malware has credentials, a single infected device becomes a full breach. This is where you check whether containment has already failed.

---

## Credential dumping

### lsass.exe access

`lsass.exe` holds cached credentials in memory. Tools like Mimikatz access it directly.

> ⚠️ Any non-Windows process accessing `lsass.exe` = escalate immediately.

**Classic dump via comsvcs.dll:**
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Users\Public\lsass.dmp full
```
The number (624) is the PID of lsass.exe. Near-certain credential theft — escalate.

### SAM and NTDS.dit

- `SAM` (`C:\Windows\System32\config\SAM`) — local account password hashes
- `NTDS.dit` (`C:\Windows\NTDS\NTDS.dit`) — full Active Directory credential database

Accessing either outside a legitimate backup = critical indicator.

---

## Lateral movement

### Account on new devices post-infection

After T0, does the compromised user's account appear on devices they don't normally access?

### Remote execution tools

| Tool | What to look for in logs |
|------|--------------------------|
| PsExec | `psexec.exe` / `psexesvc.exe`, `ADMIN$` share access + service creation |
| WMI remote | `wmic.exe /node:"IP" process call create` |
| WinRM / PSRemoting | `wsmprovhost.exe` as parent on the remote host |
| RDP | `LogonType = RemoteInteractive` from an unusual source IP |

### Pass the Hash / Pass the Ticket

- **Pass the Hash** — network logons (Type 3) from a machine that shouldn't be accessing the target, using a domain admin account
- **Pass the Ticket** — logon events using a Kerberos TGT issued on a different machine

---

## New local accounts

Malware may create backdoor local admin accounts to maintain access after cleanup.

---

## Entra ID / Azure AD anomalies

| Indicator | What to look for |
|-----------|-----------------|
| New location | Sign-in from country/city the user has never used |
| Impossible travel | UK at 09:00, US at 09:15 |
| MFA fatigue | Many MFA push notifications in a short window |
| Legacy auth | Sign-in via IMAP/POP3/SMTP — bypasses MFA |

---

## Privilege escalation

Look for:
- Standard user suddenly running processes as SYSTEM
- `whoami /priv` — checking current privileges
- `net localgroup administrators` — listing admin members
- UAC bypass: `fodhelper.exe`, `eventvwr.exe`, `computerdefaults.exe` spawning elevated processes

---

## KQL queries

Standalone query files in [kql/identity/](../kql/identity/).

### lsass access
```kql
DeviceEvents
| where DeviceName == "HOSTNAME"
| where ActionType == "OpenProcessApiCall"
| where AdditionalFields has "lsass"
| where Timestamp > ago(24h)
| project Timestamp, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AdditionalFields
```

### User on multiple devices
```kql
DeviceLogonEvents
| where AccountName == "USERNAME"
| where LogonType in ("Network", "RemoteInteractive")
| where Timestamp > ago(24h)
| summarize Devices = make_set(DeviceName), LogonCount = count() by AccountName
| where array_length(Devices) > 2
```

### New local accounts
```kql
DeviceEvents
| where DeviceName == "HOSTNAME"
| where ActionType == "UserAccountCreated"
| where Timestamp > ago(7d)
| project Timestamp, AccountName, InitiatingProcessFileName,
    InitiatingProcessCommandLine
```

### Entra ID sign-in anomalies
```kql
AADSignInEventsBeta
| where AccountUpn == "user@domain.com"
| where Timestamp > ago(7d)
| project Timestamp, AccountUpn, IPAddress, Location,
    DeviceName, ConditionalAccessStatus, AuthenticationRequirement, IsInteractive
| order by Timestamp desc
```
