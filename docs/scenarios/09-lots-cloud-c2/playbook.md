# LOTS & cloud C2 — playbook

Work top to bottom. Each step is one action, what you should see, and what to do if you don't. Capture evidence before you stop, block, remove or delete anything. Queries and methods are in the [investigation](investigation.md).

T0 = first malicious event: the first connection to the service by the suspicious process, or the arrival of the file or script it ran, whichever is earlier. It is not the alert time. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

Never browse to, call or submit a URL from this incident to a public scanner (step 11).

---

## 1. Triage

1. **Record the incident:** severity, title, how many alerts are grouped. Run [All alerts for this device](../01-malware-alert/investigation.md#all-alerts-for-this-device).
   - Expect: one alert, or alerts that all belong to this connection.
   - If other categories appear (malware, credential access, lateral movement): record them and treat this as a multi-stage incident. Check them against Escalate if before you continue.

2. **Record the device FQDN and OS, the user's SAM name and UPN, and from the network event: `Timestamp`, `RemoteUrl`, `RemoteIP`, and the client's file name, folder path, SHA1, command line, `InitiatingProcessId` and `InitiatingProcessCreationTime`.** SHA256 is usually empty; use SHA1.
   - Expect: all known.
   - If no SHA1: use the Device timeline for the checks that need it.
   - For HTTPS, `RemoteUrl` is the host, not the full URL. Step 11 recovers the rest.

3. **Set T0** from the Device timeline: the earliest of the client's first connection to the service, the client's start, and the arrival of the file or script it ran.
   - Expect: T0 at or before the alert time.
   - If you can't find it: use the client's start time and mark T0 as an estimate.

4. **Check whether the connection was blocked** ([investigation, Step 2](investigation.md#step-2--was-it-blocked)): the alerts queue, and `DeviceEvents` with `ExploitGuardNetworkProtectionBlocked` or `ExploitGuardNetworkProtectionAudited` for this device and host.
   - Expect: the result recorded (blocked, audited, or no Network Protection event).
   - A `ConnectionSuccess` row in `DeviceNetworkEvents` doesn't prove the connection worked; a blocked site can still log one. Audited means it was allowed.
   - Blocked doesn't clear the device: the client still ran. Continue.

5. **Classify the client** ([investigation, Step 1](investigation.md#step-1--identify-the-client)). Check its folder and signer; a name alone isn't evidence.
   - A. Browser from its normal install folder.
   - B. Sync or collaboration client (OneDrive, Teams, Dropbox, Google Drive) from its normal install folder, and `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` with `IsTrusted` true.
   - C. Scripting engine or downloader (`powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `curl.exe`, `certutil.exe`, `bitsadmin.exe`). `cmd.exe` usually starts the downloader: classify the child. If `cmd.exe` itself connected, treat it as C.
   - D. Anything else: unsigned, an unexpected signer, a known name in an unusual folder, a signed program that loaded a DLL from its own or a user-writable folder, or a non-Microsoft process calling Microsoft Graph.
   - Expect: one class recorded, with the folder and signer that support it.

6. **Decide the path.** Take the first line that matches.
   - C or D contacting the Telegram Bot API, Discord (CDN or webhook), a paste site, a webhook service or Microsoft Graph: escalate now and go to step 7.
   - C running a script the customer has documented (named script path, change record or scheduled job) against GitHub, SharePoint, OneDrive, Google Drive, Dropbox or object storage: check Closing as a false positive now. If every condition holds, close there. Otherwise go to step 7.
   - Any other C or D: go to step 7.
   - A: do steps 13 and 14 now. If a file from a cloud service ran, or the browser started a script host, LOLBin or unknown binary: go to step 7. Otherwise check Closing as a false positive (browser row).
   - B: check Closing as a false positive (sync client row). If any condition fails, treat it as D and go to step 7.
   - You can't tell: go to step 7.

---

## 2. Contain the device

If you don't hold the rights for a step here, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

7. **Check the device type and network before isolating.**
   - Domain controller, other Tier 0 server, or Hyper-V host: don't isolate it yourself. Escalate now. Isolating a Hyper-V host blocks network traffic to every VM on it.
   - Production server: tell the customer contact you are isolating it, and record the time.
   - Full-tunnel VPN: Microsoft says the device can't reach the Defender service once isolated. Do step 9 first, then step 8.
   - Behind a web proxy (PAC, WPAD or static): Microsoft warns such devices might not recover from full isolation and says to use selective isolation.
   - Selective isolation lets excluded processes and destinations through (for example Outlook and Teams), and Microsoft warns that any exclusion weakens isolation. If the C2 or upload runs over Microsoft 365 (Graph, OneDrive, SharePoint, Teams) or through an excluded process, and the device needs selective isolation: isolate selectively, then escalate. The channel may still be open.
   - Expect: an ordinary workstation or member server. Go to step 8 and use full isolation.

8. **Isolate the device** (device page → Isolate device). Isolation keeps the device connected to the Defender service.
   - Expect: the Action center shows the isolation as completed.
   - If not (pending or offline): Defender retries for up to three days. Escalate and report the device as not isolated.
   - Microsoft states isolation is lifted automatically after seven days (VERIFY (tenant)). Put the date in the ticket and re-check it.

9. **Collect the investigation package** (device page → Collect investigation package). It records autoruns, running processes, network connections and the DNS cache, prefetch, scheduled tasks, services and the Security event log.
   - Expect: the package is downloadable from the Action center.
   - If not: collection can fail on low battery or a metered connection. Retry once, then record the failure and continue.
   - Don't run an antivirus scan, Stop and Quarantine File, or Live Response `remediate` until this step is done or recorded as failed. Those actions remove files, processes and registry entries the package would have recorded.

10. **Preserve the client and what it ran.** Copy the client's full command line, and its parent's, into the ticket. Then, on the file page, select Collect file for the malicious file: a class D binary, the script a class C client ran (path from the command line), or the DLL a signed program loaded. Don't collect `powershell.exe` or another Windows binary. If Download file is shown instead, Defender already holds a copy.
    - Expect: the sample is held by Defender, or the script saved with Live Response `getfile`.
    - If Collect file is disabled: the file hasn't been seen in the past 30 days, or you lack the permission. Record which.
    - If there is no file (the command ran inline or was passed with `-EncodedCommand`, `-ec` or `-e`): the command line in the ticket is the evidence. An encoded command is Base64 of UTF-16LE text: decode it as text, never run it, and record the URLs in it.
    - Don't open or run the file on your own workstation.

---

## 3. Investigate

If you don't hold the rights for a step here (Collect file, Live Response), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

11. **Recover the full URL and what it points to, without touching it** ([investigation, Step 3](investigation.md#step-3--recover-the-full-url)): the command line, the script from step 10, `FileOriginUrl` and `FileOriginReferrerUrl` on files the client wrote, and the customer's proxy logs if they have them.
    - Don't browse to, download from or call the URL from any device. Don't submit it to public URL scanners: a share link can lead to the customer's data, and a Telegram Bot API URL carries the bot token.
    - Record share links, bot tokens and webhook URLs as IOCs.
    - If the content must be fetched to understand it: escalate. The IR lead decides how.
    - Expect: each URL recorded with what it appears to be (payload, config, resolver, upload target).
    - If you can't recover it: record the host only and continue.

12. **Check for a dead-drop resolver** ([investigation, Step 4](investigation.md#step-4--check-for-a-dead-drop-resolver)): run the dead-drop query, then read the Device timeline for the minutes after each fetch from a paste or storage service.
    - Expect: no follow-on connection from the client or its children to a host or IP outside the service.
    - If found: escalate (dead-drop resolver confirmed). Add the follow-on host and IP to the IOCs.
    - Zero rows from the query don't clear it. It covers only scripting engines, the same process, and raw-IP follow-ons.

13. **Trace the process chain** ([investigation, Step 5](investigation.md#step-5--trace-the-process-chain)): what started the client, what it started, and which DLLs it loaded.
    - Expect: a documented parent and no unexpected children or DLLs.
    - If a script host, LOLBin or unknown binary started it, or it started others: they are in scope. Record each one with its SHA1.

14. **Find what it downloaded or wrote** ([investigation, Step 6](investigation.md#step-6--find-what-it-downloaded-or-wrote)). Record the path and SHA1 of each file. Collect file for each one you'll need (step 10 limits apply). Submit an unknown PE for Deep analysis on the file page.
    - Expect: nothing, or only files that never ran.
    - If a file from a cloud service ran: escalate (payload downloaded and executed).

15. **Check whether anything is still running or connecting.** Use the package's Processes and Network connections folders, then Live Response `processes` and `connections` for the current state.
    - Expect: nothing from the chain running; no connections to the service or the IOCs from it.
    - If C2 looks live: escalate now.

16. **Check persistence** with the [persistence playbook](../04-persistence-detected/playbook.md): run keys, scheduled tasks, services, startup folders and WMI. Compare with the package's Autoruns, Scheduled tasks and Services.
    - Expect: nothing the attacker added.
    - If found: record each item. Don't remove anything yet; that is step 24.

17. **Check identity:** lsass access, credential-tool keywords, new accounts. Use step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md).
    - Expect: no hits.
    - If any hit: escalate, and follow the 06 playbook from step 2 for this device.

18. **Work out what was sent** ([investigation, Step 7](investigation.md#step-7--work-out-what-was-sent)). MDE has no byte counts; ask the customer for proxy or firewall logs if volume matters.
    - Expect: no class C or D connection to a webhook service, the Telegram Bot API, Microsoft Graph, or a storage host outside the customer's tenant.
    - If there is one, or a stealer or unknown payload ran (steps 13 and 14): escalate. Treat the browser-saved passwords and signed-in web sessions of every user who logged on to the device (06 playbook step 8) as exposed. Follow 06 playbook steps 13 to 18 for each of those users (capture evidence, revoke sessions, reset passwords). Tell the customer which users need resets for other sites they saved in the browser.
    - Upload to the customer's own SharePoint or OneDrive: record the account and site, and ask the customer to review what was shared from it.

---

## 4. Scope

19. **Search for the same client on other devices.** Run the three queries (they cover the estate; read `DeviceName`) and the hash sweep for each SHA1 from steps 2, 13 and 14 ([investigation, Step 8](investigation.md#step-8--first-contact-and-spread)).
    - Expect: only this device.
    - If other devices: escalate (multiple devices affected). Run steps 2 to 18 for each one. Many devices is a reason to scope wider, never to close.
    - Zero rows don't prove no spread: the queries match listed file names and whole terms only (investigation, Queries).

20. **Find the first contact:** rerun the query that hit with `T0 - 24h` changed to `T0 - 30d` on every `between` line ([investigation, Step 8](investigation.md#step-8--first-contact-and-spread)).
    - Expect: nothing before T0.
    - If earlier: move T0 to the earliest row, record it, and rerun step 19 with the new T0.

21. **Find how it arrived:** `FileOriginUrl` and `FileOriginReferrerUrl` on the creation event of the file or script the client ran (web), `RequestSourceIP` and `ShareName` (network share), Explorer in Defender for Office 365 (email).
    - Expect: the delivery vector recorded, with the URL, sender or source device.
    - If email reached other users: use the [phishing email playbook](../12-phishing-email/playbook.md).
    - If a share: the source device is in scope; run this playbook for it.
    - If none is found: record the vector as unknown. See [initial access](../10-initial-access/investigation.md) for other vectors.

---

## 5. Stop, block, remove

Only after step 9 is done (or recorded as failed) on every device in scope. If you don't hold the rights for a step here, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

22. **Stop and quarantine each malicious non-Microsoft file** from steps 10, 13 and 14 (file page → Stop and Quarantine File). This stops its running processes, quarantines the file and deletes persistent data such as registry keys, on every device where it was seen in the last 30 days.
    - Expect: the Action center shows Success for each device.
    - If Failed: record the reason. If Pending: the device is offline; the action times out after three days.
    - If Defender warns that the file is widely used in the organization: cancel and escalate. It may be a business application.
    - It can't be used on a file signed by Microsoft or by a trusted non-Microsoft publisher. Check the signer in `DeviceFileCertificateInfo` first; expect this for Windows scripting engines and downloaders, and for a signed program hosting a malicious DLL. Quarantine the script or DLL instead. Don't use Live Response `remediate` on the Windows process: on a process it stops the process and deletes the image file. If the malicious file itself is signed by a trusted publisher: escalate; the IR lead decides.
    - A quarantined script or DLL is no evidence that the process running it stopped. Recheck step 15. If it still runs: escalate; the IR lead decides how to stop it. The device stays isolated meanwhile.
    - A quarantined file can be restored if it turns out to be clean.

23. **Block what you can enforce** with Defender for Endpoint indicators (Settings → Endpoints → Indicators).
    - Host names the attacker owns (a registered domain, a storage bucket's own host name, the follow-on host from step 12): block the domain. For a SharePoint host of a tenant that isn't the customer's, first confirm with the customer that they don't work with that tenant.
    - Shared service hosts (`raw.githubusercontent.com`, `cdn.discordapp.com`, `discord.com`, `api.telegram.org`, `graph.microsoft.com`, the customer's own SharePoint): a full-URL indicator blocks only in Microsoft Edge, so it doesn't stop a non-browser client. The only enforceable block is the whole host name, which stops all business use of it. Don't create it. Escalate; the IR lead and the customer decide. Isolation (step 8) is the control meanwhile.
    - IPs: external IPs only, one address per indicator. Don't block a shared service's IPs; block only follow-on IPs from step 12.
    - Files: the SHA1 of each malicious PE (`.exe`, `.dll`), with Defender Antivirus in active mode. A script can't be blocked by hash.
    - Outside Edge, domain and IP indicators need Network Protection in block mode, and other browsers need QUIC and Encrypted Client Hello disabled. Blocks can take up to 48 hours; most apply within 2 hours.
    - Don't contact the provider, and don't post to or call the attacker's bot or webhook. Ask the IR lead whether to report the account to the provider.
    - Expect: each indicator listed with its expiry. Later, confirm blocks in `DeviceEvents` (`ExploitGuardNetworkProtectionBlocked`) or the alerts queue, not in `DeviceNetworkEvents`.

24. **Remove persistence and remaining files** found in steps 13, 14 and 16, using the [persistence playbook](../04-persistence-detected/playbook.md).
    - Expect: each item removed and recorded.
    - Accounts the attacker created: disable them; delete only with the IR lead's agreement.

25. **Confirm every action in the Action center** (History tab): isolation, package, quarantine, antivirus remediation, Live Response actions.
    - Expect: every action Success.
    - If an action failed, or an item from steps 13, 14 and 16 has no action: do it from the device or file page, or with Live Response `remediate` (not on Windows binaries). Record each.
    - If it still fails: escalate. Don't release the device.

26. **Run a full antivirus scan** (device page → Run antivirus scan → Full).
    - Expect: the scan completes with no new detections.
    - If it finds anything: treat each detection as a new alert with the [malware alert playbook](../01-malware-alert/playbook.md).

---

## 6. Clean or reimage, then release

If you don't hold the rights for a step here (reimage, release from isolation), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

27. **Decide clean or reimage.** Reimage when an unknown or stealer payload ran, someone had hands-on access, or you can't account for every item the client created. For High and above, the IR lead decides.
    - Reimaging destroys what is left on the disk. Do it only after steps 9 and 10 are done or recorded as failed, and after the IR lead says no further collection (for example a disk image) is needed.
    - Expect: the decision and who made it in the ticket.

28. **Release only when all of these hold:**
    - Steps 22 to 26 done, every action Success.
    - Credentials handled (steps 17 and 18).
    - Indicators in place (step 23), or the IR lead has accepted that a shared host can't be blocked.
    - No new alerts and no connections from the chain to the service or the IOCs while isolated, for the period the IR lead sets.
    - For High and above, the IR lead approves the release.
    - If isolation will auto-lift (step 8) before these hold: escalate before that date.
    - Then: device page → Release from isolation. Tell the customer the outcome.

---

## 7. Close out

- [ ] Classification set: True positive, Informational expected activity (authorised test, sanctioned tool), or False positive (only per Closing as a false positive)
- [ ] Client (class, folder, signer, SHA1), cloud service, host and recovered URLs documented
- [ ] IOCs documented (SHA1, hosts, IPs, URLs, bot tokens, webhook URLs) and which were blocked; shared hosts not blocked and why
- [ ] What was sent: channel, and volume only if proxy or firewall logs gave it
- [ ] Findings written up: vector, execution, C2 channel, persistence, spread, credentials, remediation, clean or reimage
- [ ] Escalated if any trigger below was hit

---

## Closing as a false positive

Close only with a named, verifiable benign cause, and record it. "Nothing else found", low volume, or "seen on many devices" is never enough; spread means scope wider.

Never close these yourself, even if a test or a business tool is mentioned:
- A class C or D client (step 5) contacting the Telegram Bot API, Discord (CDN or webhook), a paste site, a webhook service or Microsoft Graph
- Dead-drop resolver confirmed
- A file from a cloud service that ran
- Possible exfiltration to a webhook service, the Telegram Bot API, Microsoft Graph or a storage host outside the customer's tenant
- Stealer or unknown payload ran
- C2 that looks live

Escalate; the IR lead confirms any authorised test.

| Client | Close only if all of these hold |
|--------|---------------------------------|
| A. Browser | It runs from the browser's normal install folder. The visit is explained: the user confirms it, or the page that linked to it is a known business site. Nothing was downloaded from the host, or every downloaded file is identified (name, SHA1, what it is) and none ran or was opened by a script host. It started nothing but its own processes. No other alert on the device or user since T0 |
| B. Sync or collaboration client | It runs from the vendor's install folder, and `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` with `IsTrusted` true. The product is deployed at this customer (asset list or ticket). It loaded no DLL from a user-writable folder and started nothing unexpected. For SharePoint or OneDrive, the host belongs to the customer's own tenant |
| C. Documented script or tool | The customer names the script or tool, its path and owner, with a change record or documented scheduled job. The command line and script content match that record. The destination repo, account or bucket belongs to the customer or a named vendor. Not for Telegram, Discord, paste sites, webhook services or Microsoft Graph |

A sanctioned test or tool that was detected correctly: classify as Informational, expected activity, not False positive.

If any condition can't be confirmed: don't close. Escalate.

---

## Escalate if

See also [escalation triggers](../../reference/escalation-triggers.md).

```
Class C or D client (step 5) contacting the Telegram Bot API, Discord (CDN or webhook), a paste site, a webhook service or Microsoft Graph
Dead-drop resolver confirmed
A file from a cloud service that ran (payload downloaded and executed)
Possible exfiltration to a webhook service, the Telegram Bot API, Microsoft Graph or a storage host outside the customer's tenant
Stealer or unknown payload ran
C2 that looks live
Same client (SHA1, URL or command line) on more than one device
lsass access, credential-tool keywords or new accounts on the device (06 playbook step 2)
URL content must be fetched to understand it
Device can't be isolated (pending, offline, domain controller, Tier 0 server, Hyper-V host), or only selective isolation is possible while C2 runs over Microsoft 365 or an excluded process
Stop and Quarantine not possible or the process still runs (Microsoft-signed or trusted-publisher file, scripting engine), or Defender warns the file is widely used
Containment needs a shared service host blocked whole
Remediation failed and can't be completed
Isolation will auto-lift before the release criteria hold
```
