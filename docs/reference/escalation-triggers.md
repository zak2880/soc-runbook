# Escalation triggers

> If you see any of these, stop investigating and escalate. Follow your IR runbook.

This is the single reference. Each playbook's Escalate if section lists the triggers for that scenario, and links here.

---

## Escalate immediately — no exceptions

No exceptions means always escalate. Severity is set in the [Severity guide](#severity-guide).

### Ransomware
- Shadow copies or the backup catalog deleted: `vssadmin delete shadows`, `wmic shadowcopy delete`, `Win32_ShadowCopy` removed through PowerShell, `wbadmin delete catalog`, `diskshadow`
- `bcdedit ... recoveryenabled No`
- Mass file renames
- Ransom-note files created in many folders
- Source of the encryption can't be identified (RequestSourceIP blank, or the source device isn't onboarded or can't be identified)
- File server needs isolating (only with the IR lead)

### Credential access
- `lsass.exe` opened by anything other than a verified security product (Windows binaries such as `rundll32.exe` included), an lsass dump command or tool, or a dump file on disk
- `rundll32.exe` with `comsvcs.dll` in the command line, whatever follows it
- `NTDS.dit` copied (`ntdsutil`, shadow copy, `esentutl`) or DCSync seen; MDE documents no file-read events, so hunt the method
- SAM, SYSTEM or SECURITY hive saved (`reg save HKLM\SAM`)
- Mimikatz, `sekurlsa::` or other credential-tool keywords in a command line, or a known credential dumper (for example Mimikatz)
- Any hit in step 2 of the [credential compromise playbook](../scenarios/06-credential-compromise/playbook.md#1-triage)
- Kerberoasting or AS-REP roasting seen
- New accounts on the device

### Active C2 session
- Beaconing confirmed from a process that isn't a named, sanctioned product
- Network activity from a process that isn't a named, sanctioned product, a documented script or an approved scanner
- Confirmed C2 beaconing (live session), or C2 that looks live (connections to an IOC still happening)
- Shells or recon commands started by the connecting or beaconing process
- A beacon or connections from inside a signed or Microsoft process
- A DNS tunnelling pattern (long, changing labels under one parent domain)
- Cobalt Strike default named pipe (`msagent_*`, `status_*`, `postex_*`, `MSSE-*`). Names are configurable, so finding no match proves nothing
- Reverse shell: an interactive shell over an outbound connection (`cmd.exe` or `powershell.exe`), or a decoded command opening a connection to an external host
- Class C or D client (LOTS & cloud C2 playbook, step 5) contacting the Telegram Bot API, Discord (CDN or webhook), a paste site, a webhook service or Microsoft Graph
- Dead-drop resolver confirmed
- A file from a cloud service that ran (payload downloaded and executed)
- C2 over Microsoft 365: C2 or upload runs over Microsoft 365 or Graph, whether isolation is full or selective

### Lateral movement confirmed
- Account logged on to a device it has no documented reason to use
- PsExec or psexesvc execution to or from another host
- WMI execution to or from another host, including `-ComputerName` on `Invoke-CimMethod` or `Invoke-WmiMethod`
- PsExec, WMI or WinRM remote execution by an exposed account
- Lateral movement from the device (a logon or remote execution on an internal target)
- Internal scanning not explained by the device's role or an approved scanner
- The file arrived over SMB from another internal device

### Spread
Severity: Critical. Spread means scope wider; it is never evidence of a false positive.
- Same malicious file, destination or payload on more than one device
- Same hash, delivery URL, command pattern, persistence, evasion technique, client (SHA1, URL or command line), lure or domain on more than one device
- More than one user ran the same payload
- Same source IP logged on to more than one device

### Data exfiltration indicators
- Possible exfiltration: an upload or sync tool, a staged archive, or a script host or unknown program reaching a webhook, the Telegram Bot API, Microsoft Graph or storage outside the customer's tenant. MDE has no byte counts; volume needs proxy or firewall logs
- Staging directory — files collected and compressed before sending
- `rclone`, `MEGASync` uploading from unexpected process

### Defence evasion — attacker covering tracks
- Defender or EDR tampered with or stopped: protection off or weakened with no change record, a tamper alert, a TamperingAttempt event, or a security service stopped or killed
- Event logs cleared or deleted (`wevtutil cl`, `Clear-EventLog`, `Remove-EventLog`, Event Viewer, `.evtx` files deleted, or Security event 1102)
- Audit policy or event logging turned off (`auditpol /clear`, `/remove` or `/set` with disable; `wevtutil sl` with `/e:false`; EventLog service stopped or disabled)
- Defender exclusion with no change record
- Defender change from central policy with no change record (Group Policy, Intune, Configuration Manager)
- Unknown or vulnerable driver written or loaded
- Sensor stopped reporting or lost health during the incident
- Firewall turned off, or a rule allowing inbound connections added, with no change record
- AMSI bypass followed by any download, child process or persistence
- Process injection: a Defender injection alert, or a legitimate process with an unexplained public connection
- Protection can't be restored, or it is turned off again

### Identity and initial access
- RDP exposed to the internet with a successful brute force
- Valid account used from a new country or unfamiliar IP: possible credential compromise, unless the user confirms travel or VPN
- Initial access to a server, domain controller or jump host
- Privileged, admin or service account used for access, or among the exposed accounts
- Public-facing service or appliance exploited
- Access through a supplier's or service provider's account or tool
- Remote-access (RMM) tool not on the customer's approved list, or installed outside a change record
- A remote-access or admin tool installed with no change record or approved-software entry
- Delivery vector can't be found, and attacker code ran or an account was used
- Successful sign-in after an MFA burst, or a High-risk user or token / AiTM detection in Entra ID Protection
- Successful legacy-auth sign-in since T0
- Suspicious sign-in for an exposed account since T0

### ClickFix
- Privileged user, service account, server or jump host
- macOS device
- Command, decoded if it was encoded, downloads or runs code from an external host, or loads an assembly from memory, and no ticket from the customer's helpdesk names that exact command
- User reports a verification or fix-an-error prompt before pasting
- User was told to paste by someone the helpdesk can't confirm
- Second-stage payload ran (a script, EXE, DLL, MSI or HTA that the pasted command fetched or wrote)
- Network callout confirmed to the staging or C2 URL: payload likely delivered
- Browser credential theft signal
- EtherHiding variant confirmed: flag for TI; standard domain blocklists won't catch it
- Persistence established after the paste

### Phishing or mailbox compromise
- Payload ran on a device (hand off to [01-malware-alert](../scenarios/01-malware-alert/playbook.md))
- Recipient account compromised: since T0, an Entra ID Protection risk detection, a sign-in the user doesn't recognise, or a new MFA method, app consent, inbox rule or forwarding; or the user entered credentials, approved an MFA prompt or typed a code
- Internal mailbox compromised (BEC): the message came from the customer's own domain and isn't spoofed
- Partner mailbox compromised: a known partner's authenticated mailbox sent it (thread hijacking)
- Priority or admin recipient interacted (clicked, opened the attachment, or entered credentials)
- Remote-access tool after a call (callback phishing)
- Message not found in Explorer, and any recipient interacted or any recipient is a priority account (otherwise a ticket note)
- Copies can't be removed: Plan 1 only, On-premises/External, older than 30 days, or remediation Failed and the customer can't remove them
- Business domain can't be blocked: a malicious URL is on a domain the customer uses and its path can't be blocked

### Execution and payloads
- Office app or WmiPrvSE.exe started PowerShell, cmd, mshta, a script host or another LOLBin, ASR didn't block it, and the caller is not the customer's confirmed management agent or application
- Decoded command downloads or runs code from an external host, or loads an assembly from memory, and its parent is not the customer's confirmed management agent
- A LOLBin fetched a file or script from an external host (IP or domain name), and the caller is not the customer's confirmed management agent
- Encoded content that can't be decoded to readable text
- Windows binary name running from a folder other than its usual Windows folder, or a renamed copy of a Windows binary
- BITS job with a notify command, or one the customer can't name
- BITS jobs can't be listed or cancelled
- Infostealer or unknown payload executed, or one can't be ruled out
- A downloaded file that ran, outside a documented script or job
- The file deleted itself after running

### Persistence
- WMI event subscription found (any)
- Hidden scheduled task (task key with no SD value, or a task in telemetry or C:\Windows\System32\Tasks\ that the task list doesn't show)
- Persistence is a changed legitimate entry, not a new one (for example Winlogon Userinit, Shell or Notify, or an existing service's ImagePath)
- Persistence created from another device (for example psexesvc, or schtasks with /s)
- Persistence on a domain controller or other Tier 0 server
- SYSTEM-context task or service whose target is unsigned or in a user-writable folder
- New service whose image file is a Windows binary
- Persistence target is a credential dumper, C2 stager, infostealer or unknown payload
- Persistence comes back after removal

### Containment and remediation
- Device can't be isolated (pending, offline, domain controller, other Tier 0 server, Hyper-V host)
- Stop and Quarantine File can't be used or the process still runs (Microsoft-signed or trusted-publisher file, scripting engine), or Defender warns the file is widely used
- More than 1,000 devices have the file
- A hash or domain to block is software or a site the customer uses for business
- Destination is a cloud or business service the customer uses
- Containment needs a shared service host blocked whole
- URL content must be fetched to understand it
- A target file can't be preserved before removal
- Remediation failed and can't be completed
- Full antivirus scan after removal finds new detections
- Isolation will auto-lift before the release criteria hold
- Any escalation trigger in a playbook the current one hands you to

---

## What to have ready when you escalate

```
Device:          hostname, OS, last logged-in user
T0 (first seen): timestamp of first malicious activity
Alert name:      Defender / Sentinel alert title
Malware family:  if identified
What ran:        key process chain
What it did:     network connections, files dropped, each persistence item (location, data before and after)
Spread:          yes/no — other devices, other accounts
Status:          device isolated / not isolated
Trigger:         which item above caused escalation
```

---

## Severity guide

| Scenario | Severity |
|----------|----------|
| Remediation confirmed, nothing executed, the writing process benign, no other alerts ([malware playbook, Closing at Low](../scenarios/01-malware-alert/playbook.md#closing-at-low)) | Low — record each check and close |
| Executed, no persistence, no spread, no C2 | Medium — full investigation, confirm contained |
| Executed with persistence, no spread, no C2 | High — escalate |
| C2 beaconing confirmed (live) | High — isolate, escalate |
| Infostealer or unknown payload executed | High — isolate, escalate, treat browser credentials as exposed |
| Credential dumping detected | Critical — escalate immediately |
| Lateral movement confirmed | Critical — escalate immediately |
| Ransomware indicators | Critical — escalate immediately, consider P1 |
| Multiple devices affected | Critical — escalate immediately |
| Phishing delivered, nobody clicked | Low |
| Phishing clicked by a priority or admin recipient | High — escalate |
| Phishing clicked by any other recipient, no execution, no sign of account compromise | Medium |
| Compromised mailbox or account | High — escalate |
| Priority, admin, privileged or service account compromised | Critical — escalate immediately |
