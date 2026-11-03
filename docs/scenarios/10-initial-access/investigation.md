# Initial access — investigation

## What you're looking for

Initial access is how the attacker got in. Before you can fully understand an incident, you need to trace the execution chain back to T0 — the first malicious event. Without knowing the delivery method, you risk missing other victims and leaving the door open for reinfection.

T0 = the first malicious event on the device or account (delivery, first logon or first execution), in UTC. It is not the alert time. You usually start from a later alert, so T0 moves earlier as you trace back. Rerun the queries each time it moves: a query anchored on a T0 that is too late returns nothing, and that doesn't mean "not this vector".

Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention. If T0 may be older than that, record the gap in the ticket. Don't record "no delivery found". The Device timeline may reach further back: Microsoft states 90 days by default (VERIFY (tenant)).

This page covers the vectors and how to scope them. The order of actions is in the [playbook](playbook.md). If another playbook sent you here to find how the attacker got in, the device is already in hand there. Use this page to name the vector, then go back: containment and removal stay in that playbook.

---

## Common vectors

| Vector | What it looks like | MITRE | Check |
|--------|-------------------|-------|-------|
| Phishing attachment | User opens Office doc, PDF, or archive with malicious content | T1566.001 | [Email delivery](#email-delivery) |
| Phishing link | User clicks link → download or credential harvest | T1566.002 | [Email delivery](#email-delivery) |
| Malicious macro | Office doc with VBA macro spawning a shell | T1204.002, T1059.005 | [Macros](#macros) |
| ISO / IMG / ZIP | Archive or disk image containing LNK or executable. Files inside may not inherit Mark of the Web | T1566.001 | [ISO / IMG containers](#iso--img-containers) |
| HTML smuggling | HTML attachment or page that builds the payload in the browser, so the attachment's hash is not the payload's | T1027.006 | [Email delivery](#email-delivery), Step 3 |
| Drive-by compromise | A website exploits the browser or a plug-in on visit, with no decision by the user. The browser itself starts a child process | T1189 | Step 1 |
| Fake update or malvertised installer | User downloads and runs something that looks legitimate: a download followed by execution, not a browser exploit | T1204.002 | Step 3 |
| ClickFix (paste and run) | A page tells the user to paste a command | T1204.004 | [ClickFix](../13-clickfix/investigation.md) |
| Social-engineered remote access | A caller posing as IT support has the user install a remote-access tool or open a remote session | T1566.004, T1219 | [Remote-access tools](#remote-access-tools) |
| Valid accounts | Attacker logs in with stolen or brute-forced credentials | T1078 | [Valid accounts](#valid-accounts-and-remote-services) |
| Exposed RDP | RDP directly accessible — brute forced or credential stuffed | T1133 | [RDP brute force](#rdp-brute-force) |
| Other remote services | VPN, Citrix or RD Gateway logon with valid credentials | T1133 | [Valid accounts](#valid-accounts-and-remote-services) |
| Public-facing application | VPN or firewall appliance, Exchange or a web app exploited. There is no user chain | T1190 | [Server-side and third-party access](#server-side-and-third-party-access) |
| Trusted relationship | Access through a supplier's or service provider's account or tool | T1199 | [Server-side and third-party access](#server-side-and-third-party-access) |
| Removable media | Payload run from a USB drive | T1091 | [ISO / IMG containers](#iso--img-containers) |

---

## Tracing back to T0

### Step 1 — find the earliest malicious event

Open Device Timeline in Defender XDR and scroll back before the alert. Use the custom date range: the timeline shows the past 30 days by default. Look for the browser download, email attachment being opened, remote logon, or script being executed that started the chain.

In the event details, Additional information "Warning bypassed by user" means the user dismissed a SmartScreen warning.

**Was it blocked?** Check the alert's detection status and the device's ASR events first ([what the values mean](../02-suspicious-process/investigation.md#was-it-blocked)). `DeviceEvents`, `ActionType` starting with `Asr`, from T0. Besides the rules listed there, these fit delivery:
- `AsrExecutableEmailContentBlocked`: executable, script or archive content from email.
- `AsrExecutableOfficeContentBlocked`: Office writing executable content.
- `AsrScriptExecutableDownloadBlocked`: JavaScript or VBScript launching downloaded content.
- `AsrUntrustedUsbProcessBlocked`: an unsigned or untrusted process from USB.

Each has an `Audited` form, which means the action ran. A block covers that one action; what ran earlier in the chain still ran.

### Step 2 — check what files were created before execution

The query covers one hour either side of T0 and `FileCreated` only. Its `project` line leaves out the columns that build the chain. In your copy, add `FileOriginUrl, FileOriginReferrerUrl, FileOriginIP, InitiatingProcessCommandLine, InitiatingProcessParentFileName`.

```kql
// 10 — files created on the device around the first malicious event
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// SHA256 is usually empty in DeviceFileEvents; enrich on SHA1

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceFileEvents
| where DeviceName startswith "HOSTNAME"
| where ActionType == "FileCreated"
| where Timestamp between ((T0 - 1h) .. (T0 + 1h))
| project Timestamp, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

### Step 3 — check where the file came from

`DeviceFileEvents` records where a downloaded file came from:
- `FileOriginUrl`: the URL it was downloaded from.
- `FileOriginReferrerUrl`: the web page that links to the download. This is usually the lure or compromised site, and the initial-access IOC to block and sweep.
- `FileOriginIP`: the IP it was downloaded from.

The query below doesn't project these. In your copy, add them to the `project` line. Don't browse to them. Microsoft doesn't say how the columns are filled, so an empty value doesn't prove the file was local or had no Mark of the Web.

What the query misses, and how to widen your copy:
- **Other writers.** It covers four browsers. A mail client, Teams or another browser isn't in the list, so most email attachments don't show. Replace the `InitiatingProcessFileName` filter with `| where isnotempty(FileOriginUrl)`.
- **Other file types.** The list misses `.docm`, `.xlsx`, `.one`, `.msi`, `.vhd`, `.vhdx`, `.html`, `.htm`, `.svg`, `.rar`, `.7z`, `.jar` and `.cpl`. Remove the `FileName` line if nothing turns up.
- **Renamed downloads.** A browser may write a temporary file and rename it, and Learn doesn't list the `ActionType` values. VERIFY (tenant): if the file you expect is missing, change the line to `ActionType in ("FileCreated", "FileRenamed")`.

```kql
// 10 — files written by the browser (download history)
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// SHA256 is usually empty in DeviceFileEvents; enrich on SHA1

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceFileEvents
| where DeviceName startswith "HOSTNAME"
| where InitiatingProcessFileName in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe")
| where ActionType == "FileCreated"
| where FileName matches regex @"(?i)\.(exe|dll|ps1|vbs|bat|hta|js|wsf|cmd|scr|lnk|iso|img|zip|doc|docx|xls|xlsm|pdf)$"
| where Timestamp between ((T0 - 7d) .. (T0 + 1h))
| project Timestamp, FileName, FolderPath, SHA1, SHA256
```

---

## ISO / IMG containers

Mark of the Web (MotW) is an NTFS feature. MITRE notes a container downloaded from the internet is marked, but "the files within may not inherit the MOTW" once it is mounted or extracted. It can happen; don't assume it did or didn't. Without MotW, Office doesn't treat the file as from the internet (see [Macros](#macros)).

The query below reads process starts from drive letters D: to Z:.
- It is a lead, not a finding. Mapped network drives and USB volumes use the same letters. Corroborate with a `DeviceFileEvents` row for the `.iso`, `.img` or `.vhd` file, and its `FileOrigin*` columns. Ask the customer what the drive is.
- A hit on a USB volume with no container file: treat it as removable media, and check the `AsrUntrustedUsbProcess` events from Step 1.
- An LNK using a relative path may not show a drive letter in the command line, and a DLL side-loaded from the mount isn't in the query. Use the Device timeline.
- The window is T0 ± 24 hours. Move T0 if the container was opened earlier.

```kql
// 10 — processes started from a mounted ISO/IMG (drive letters D: to Z:)
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// Two cases: (a) an executable run straight from the mounted image (its own path is on D:-Z:);
// (b) an LNK on the image launching a system binary from C: whose command line points at D:-Z:
// Mapped network drives and USB volumes also use D:-Z: and will appear as false positives

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where DeviceName startswith "HOSTNAME"
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where InitiatingProcessFileName =~ "explorer.exe"
| where FolderPath matches regex @"(?i)^[D-Z]:\\"
    or (FileName in~ (
            "cmd.exe", "powershell.exe", "wscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe")
        and ProcessCommandLine matches regex @"(?i)\b[D-Z]:\\")
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
```

---

## Macros

Office blocks VBA macros in files from the internet by default, on Windows, in Access, Excel, PowerPoint, Project, Publisher, Visio and Word. The user sees a Security Risk banner, and the banner has no Enable content button. So "did the user enable it?" is the wrong question. Ask how the macro got past the block.

Run [Office spawning shells](../02-suspicious-process/investigation.md#office-spawning-shells) with T0, then look for how the file reached that state.

| How it got past the block | What you can check |
|---|---|
| No MotW: the file came out of a container, or sits on a non-NTFS volume (Microsoft: MotW applies to NTFS only) | The container in Step 3 and [ISO / IMG containers](#iso--img-containers) |
| No MotW: OneDrive sync client downloaded it, Open in Desktop App was used, or it is in a known folder synced to OneDrive | The file's `FolderPath`; ask the user |
| MotW removed: Properties → Unblock, or `Unblock-File` | `Unblock-File` in `DeviceProcessEvents` command lines. Properties → Unblock has no documented event; ask the user |
| Trusted Location, or a location in the Trusted sites or Local intranet zone | The file's `FolderPath`; ask the customer's IT contact |
| Macro signed, and the device holds the matching Trusted Publisher certificate | Ask the customer's IT contact |
| User enabled content on this file before the block reached this Office version, so it is a Trusted Document | Ask the user |
| Policy allows macros | Ask the customer's IT contact |

Without MotW the file isn't treated as from the internet, but macros still don't run on their own: the default setting, "Disable all macros with notification", shows a Trust Bar and the user has to select Enable Content.

Record the route if you can tell. If you can't, record it as unknown. It decides what to harden, not whether this is an incident.

---

## RDP brute force

**Reading the results.** One row per public source IP.
- `SuccessfulLogons` above 0 and high `FailedAttempts` from the same IP: a successful brute force. Go to Contain in the [playbook](playbook.md).
- Many names in `Accounts`, few attempts each: password spray. A success in that row counts the same.
- `SuccessfulLogons` above 0 with few or no failures: a stolen credential, or a remote user the customer knows about. Check the account ([Valid accounts](#valid-accounts-and-remote-services)).
- `FailedAttempts` only: the host is exposed and under attack. That isn't a compromise on its own, but the customer needs to know.

**What it can't show.**
- Public sources only. RDP through a VPN, RD Gateway or NAT may show a private or gateway address. To include those, remove the `RemoteIPType` line in your copy and expect internal admin logons in the result.
- `Network` logons also cover share access and PsExec, so a `Network` row isn't always RDP. Rerun the query without the `summarize` block to read `LogonType` per event.
- Microsoft doesn't document how a failed Network Level Authentication logon appears in this table. VERIFY (tenant): whether failed logons on this host carry a `RemoteIP` at all. If they don't, this query undercounts; read the Security event log in the investigation package.
- `DeviceLogonEvents` isn't collected on Windows 7 or Windows Server 2008 R2. An empty result on those hosts means nothing.
- The window is T0 − 14 days to T0 + 1 day.

**Is the device exposed?**
- Device inventory: the "internet facing" tag. Hover over it for the reason: detected by an external scan, or received external incoming communication.
- `IsInternetFacing` in `DeviceInfo`, and the Microsoft function `InboundExternalNetworkEvents("PASTE_DEVICE_ID_HERE")`, which returns the last 7 days of incoming communication from public IPs.
- No tag doesn't prove the device isn't exposed. Only Windows devices are identified, and the tag is removed after 48 hours with no new events. Ask the customer whether RDP is meant to be reachable from the internet.

**What happened in the session.** `IsProcessRemoteSession` and `ProcessRemoteSessionIP` on `DeviceProcessEvents`, and `IsInitiatingProcessRemoteSession` and `InitiatingProcessRemoteSessionIP` on `DeviceFileEvents`, show what ran under an RDP session and from which IP. Filter them to the source IP from `FirstSuccess` onward. For accounts the attacker added, use the package's Users and Groups folder and step 12 of the [credential compromise playbook](../06-credential-compromise/playbook.md).

```kql
// 10 — RDP brute force against this device, grouped by source IP
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// With Network Level Authentication, failed RDP logons may be recorded as Network logons, not
// RemoteInteractive, so both types are counted. Public source IPs only
// VERIFY: LogonType and ActionType strings (Learn describes LogonType but does not list the values):
// DeviceLogonEvents | where Timestamp > ago(7d) | summarize count() by LogonType, ActionType

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceLogonEvents
| where DeviceName startswith "HOSTNAME"
| where Timestamp between ((T0 - 14d) .. (T0 + 1d))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| summarize
    FailedAttempts = countif(ActionType == "LogonFailed"),
    SuccessfulLogons = countif(ActionType == "LogonSuccess"),
    Accounts = make_set(AccountName, 50),
    FirstSeen = min(Timestamp),
    FirstSuccess = minif(Timestamp, ActionType == "LogonSuccess")
    by RemoteIP
| where FailedAttempts > 10 or SuccessfulLogons > 0
| order by SuccessfulLogons desc, FailedAttempts desc
```

---

## Valid accounts and remote services

A logon with a real password leaves no delivery chain on the device, so the T0 method above doesn't find it. Look at the account instead:
- **Entra sign-ins:** [Entra ID anomalies](../06-credential-compromise/investigation.md#entra-id-anomalies), filtered to the UPN.
- **Device logons:** [User on multiple devices](../06-credential-compromise/investigation.md#user-on-multiple-devices), with the SAM name.
- **VPN, Citrix and RD Gateway:** the gateway's own logs usually aren't in Defender. Ask the customer's IT contact for the logs for the account, from T0 − 14 days.

A new country alone doesn't prove compromise: it also fits travel, VPN egress or a mobile carrier. Write "possible credential compromise" until you know. Ask the user through the customer contact, and check the [impossible travel row](../06-credential-compromise/playbook.md#closing-as-a-false-positive) of the credential compromise playbook. Escalate unless travel or VPN is confirmed.

Where the password came from may be outside this device: a phishing page, or another service. Check [Email delivery](#email-delivery) for the user. Record "source of the credential unknown" if you can't find it. Treat the password as known to the attacker either way.

---

## Remote-access tools

If the trace back ends at a remote-access tool (for example ScreenConnect, AnyDesk, TeamViewer or Quick Assist), that tool may be the way in, not noise. MITRE describes callers posing as IT staff directing victims to install remote management tools (T1566.004).

A vendor signature, a vendor domain and a fixed connection interval prove nothing here: an attacker-installed agent passes all three. Check:
- Is the product on the customer's approved list?
- Does a change record or ticket explain this install, its time and its installer?
- Did anyone phone the user or message them before the install?

If not, the install or the call is T0.

---

## Server-side and third-party access

**Public-facing application.** There is no user chain, so Steps 1 to 3 don't apply. Look in the Device timeline for shells or script hosts started by a service process (for example `w3wp.exe` on a web server), and for new script files in a web folder. An appliance such as a VPN or firewall usually has no Defender sensor. The first thing you see may be a logon from its internal address, and its own logs are the evidence. Ask the customer's IT contact for them.

**Trusted relationship.** The access came through a supplier's or service provider's account or tool. MITRE's examples include IT services contractors and managed security providers. Escalate. Don't contact the supplier yourself.

---

## Email delivery

**Find the message.** In Explorer (Defender for Office 365), search for the recipient around T0, with the attachment name from Step 2 or the URL domain from Step 3. In Advanced Hunting, search `EmailAttachmentInfo` on `FileName` and `RecipientEmailAddress`. Hashes rarely work here: `SHA256` in that table is usually empty and it has no SHA1 column. A ZIP, ISO or HTML attachment also has a different hash from the file that ran.

No tool records that a user opened an email ([why](../12-phishing-email/investigation.md#step-2--delivery-action)). The file written to disk, the click and the sign-in are what you can see.

**Then scope it.** See the [phishing email investigation](../12-phishing-email/investigation.md) for how to scope the campaign and who interacted, and take the actions in order from the [phishing email playbook](../12-phishing-email/playbook.md). Before you go there:
- 12 uses its own T0: the delivery time of the first message in the campaign. If that is earlier than your T0, move yours.
- 12 hands devices to the malware playbook. A device you already hold in this scenario stays here; every other device goes there.
- Don't remove or block mail from this page. 12 preserves the message before anything is deleted.

---

## Spread

Spread is a reason to scope wider, never evidence that the activity is benign. Start each query with the same `let T0 = datetime(PASTE_TIME_UTC);` line as the queries above.

- **Same payload:** the [hash sweep](../01-malware-alert/investigation.md#step-4--check-for-spread), with SHA1 from the file page. `Tables` shows where it only landed and where it ran.
- **Same delivery source:** `DeviceFileEvents | where Timestamp between ((T0 - 30d) .. (T0 + 1d)) | where FileOriginUrl has "PASTE_DOMAIN_HERE" or FileOriginReferrerUrl has "PASTE_DOMAIN_HERE" | summarize Files = make_set(FileName, 20), FirstSeen = min(Timestamp) by DeviceName`
- **Same source IP:** `DeviceLogonEvents | where Timestamp between ((T0 - 14d) .. (T0 + 1d)) | where RemoteIP == "PASTE_IP_HERE" | summarize Failed = countif(ActionType == "LogonFailed"), Succeeded = countif(ActionType == "LogonSuccess"), Accounts = make_set(AccountName, 50) by DeviceName`. The RDP query's VERIFY note applies to these `ActionType` values.
- **Same account:** [User on multiple devices](../06-credential-compromise/investigation.md#user-on-multiple-devices).
- **Same email:** Step 3 of the [phishing email investigation](../12-phishing-email/investigation.md#step-3--all-recipients-and-the-rest-of-the-campaign).

Zero rows doesn't prove no spread: each of these reads one column, and an attacker can change the host, the IP or the file between victims.
