# ClickFix — playbook

Work top to bottom. Each step is one action, what you should see, and what to do if you don't. Capture evidence before you stop, quarantine, remove or delete anything. Queries and background are in the [investigation](investigation.md).

The process the paste started is usually a Windows binary. Never quarantine, block, delete or `remediate` the binary itself; act on what it fetched, ran or wrote.

T0 = the first malicious event in the chain (the command pasted, or the first suspicious process), in UTC. It is not the alert time. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

**Working the [suspicious process](../02-suspicious-process/playbook.md) or [LOLBin](../07-lolbin-abuse/playbook.md) playbook?** Stay there. They use the [ClickFix investigation](investigation.md) for scope only. Start here only when the alert or the user's report is ClickFix from the outset.

---

## 1. Triage

1. **Record the incident:** severity, title, how many alerts are grouped. Run [All alerts for this device](../01-malware-alert/investigation.md#all-alerts-for-this-device).
   - Expect: alerts that all belong to this process chain.
   - If other categories appear (credential access, lateral movement, C2): record them and treat this as a multi-stage incident. Check them against Escalate if before you continue.
   - If a user reported it and there is no alert: find the chain in the user's Device timeline around the time they give.

2. **Record the device, the user and the process.** Device FQDN, OS and role (workstation, server, jump host); the user's SAM name and UPN, and whether the account is privileged; for the process the paste started: name, full path, SHA1, full command line, PID and creation time; the parent's name and command line; the grandparent's name. Take them from the alert's process tree or the Device timeline.
   - Expect: all known.
   - If the PID or creation time is missing: identify the process in the Device timeline. Don't match on the process name alone; PIDs are reused.
   - If the user is privileged, or the device is a server or jump host: escalate now (privileged user, server or jump host) and continue.
   - If the device is a Mac: escalate (macOS device). This playbook covers Windows.

3. **Set T0** from the Device timeline: the earliest event in the chain.
   - Expect: T0 at or before the alert time.
   - If you can't find it: use the process's creation time and mark T0 as an estimate.

4. **Check whether it was blocked** ([Was it blocked?](investigation.md#was-it-blocked)): the alert's detection status, then the device's ASR events from T0.
   - Expect: Prevented or Blocked, and an ASR event ending in `Blocked` if a rule was involved.
   - If Detected, or an ASR event ends in `Audited`: the action ran. Do steps 5 and 6, then go to step 8.
   - Blocked covers that one action. Other processes in the chain may have run, and the user may have pasted again; step 7 checks them.
   - No detection is inconclusive, not all-clear. Don't wait for an antivirus verdict.

5. **Check the whole process tree for an immediate trigger.** Read every command line in the tree for:
   - Shadow copy deletion: `vssadmin delete shadows`, `wmic shadowcopy delete`, or `Win32_ShadowCopy` removed through PowerShell
   - `bcdedit` ... `recoveryenabled No`
   - `rundll32.exe` with `comsvcs.dll` in the command line, whatever follows it
   - Mimikatz, `sekurlsa::` or other credential-tool keywords in a command line
   - Event logs cleared (`wevtutil cl`)
   - PsExec, `psexesvc` or WMI execution to or from another host
   - Defender or EDR tampered with or stopped
   - Expect: none.
   - If any: escalate now and go to step 8. Do step 6 after step 11. For a credential item, also run step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md) for this device.
   - WMI to another host includes `wmic /node:` and `-ComputerName` on `Invoke-CimMethod` or `Invoke-WmiMethod`. Defender tampering includes `Set-MpPreference` changes and new exclusions.

6. **Decode the command before you judge it** ([Decode the command](investigation.md#decode-the-command)): `-e`, `-ec`, `-enc`, `-EncodedCommand`, `FromBase64String`, hex strings, caret-split words, script arguments to `mshta`. Decode PowerShell as UTF-16LE on your analysis machine. Never run the result, and don't open its URLs in a browser. A paste into an open window has no command line of its own: decode the command lines of what it started.
   - Expect: readable text whose action you can name. Record every URL, IP, domain and file name it contains. Steps 15, 21 and 25 use them.
   - If it contains a step 5 item: escalate now and go to step 8.
   - If the command, decoded if it was encoded, downloads or runs code from an external host, or loads an assembly from memory, and no ticket from the customer's helpdesk names that exact command: escalate and go to step 8. Don't hold containment while you wait for an answer about a ticket.
   - If the encoded content can't be decoded to readable text: escalate and go to step 8.
   - The switches alone (`-nop`, `-w h`, `-enc`) are not a verdict. Management tools use them too.

7. **Decide the path.**
   - It looks like a sanctioned paste (a helpdesk ticket, a documented internal script or a vendor's repair command): do steps 12 to 15. Close only if every condition in Closing as a false positive holds; otherwise go to step 8.
   - Detection status Prevented or Blocked, no ASR event ends in `Audited`, and the Device timeline shows nothing else from the chain ran after T0 (no other child processes, connections, file writes or registry changes apart from the `RunMRU` value): you don't need to isolate. Do steps 10 to 23. If any of them finds something, go to step 8. If not: do step 25 for the domains and URLs you recorded, and close out as a true positive.
   - Anything else, or you can't tell: go to step 8. Don't wait to see whether the process is still running. A downloader can exit within seconds of fetching its next stage.

---

## 2. Contain the device

If you don't hold the rights for a step here (isolation, investigation package, Live Response), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

8. **Check the device type and network before isolating.**
   - Domain controller, other Tier 0 server, or Hyper-V host: don't isolate it yourself. Escalate now. Isolating a Hyper-V host blocks network traffic to every VM on it.
   - Production server: tell the customer contact you are isolating it, and record the time.
   - Full-tunnel VPN: Microsoft says the device can't reach the Defender service once isolated. Do step 10 first, then step 9.
   - Behind a web proxy (PAC, WPAD or static): use selective isolation. Microsoft warns such devices might not recover from full isolation.
   - Expect: an ordinary workstation or member server. Go to step 9.

9. **Isolate the device** (device page → Isolate device). Isolation disconnects the device from the network and keeps it connected to the Defender service.
   - Expect: the Action center shows the isolation as completed.
   - If not (pending or offline): Defender retries for up to three days. Escalate and report the device as not isolated.
   - Microsoft states isolation is lifted automatically after seven days (VERIFY (tenant)). Put the date in the ticket and re-check it.

10. **Collect the investigation package** (device page → Collect investigation package). It records autoruns, running processes, network connections, prefetch, scheduled tasks, services, `%Temp%` listings and the Security event log.
    - Expect: the package is downloadable from the Action center.
    - If not: collection can fail on low battery or a metered connection. Retry once, then record the failure and continue.
    - Don't stop a process, run an antivirus scan, Stop and Quarantine File, or Live Response `remediate` until this step is done or recorded as failed. Those actions remove the processes, files and registry entries the package would have recorded.

11. **Preserve the payload:** every file the chain fetched, ran or wrote that is not a Windows binary, for example a `.ps1`, `.bat`, `.vbs`, `.hta`, `.msi`, archive, DLL or EXE named in steps 2 and 6. Not the LOLBin itself. On the file page, select Collect file if it is shown; Download file instead means Defender already holds a copy. If the file page doesn't offer either, use Live Response `getfile` with the full path.
    - Expect: each payload held by Defender or downloaded, with its path and SHA1 in the ticket.
    - If Collect file is disabled: the file hasn't been seen in the past 30 days, or you lack the permission. Record which, and try `getfile`.
    - If a script or HTA was loaded from a URL and no file was written: record the full URL. Don't visit it.
    - Don't download an lsass dump file; follow step 7 of the [credential compromise playbook](../06-credential-compromise/playbook.md). Don't open or run any payload on your own workstation.

---

## 3. Investigate

12. **Trace the whole chain** in the alert's process tree and the Device timeline from T0: grandparent, parent, process, children and grandchildren. Link each child to its parent on PID plus creation time ([Follow the chain](investigation.md#follow-the-chain)).
    - Expect: every process recorded with path, SHA1 and command line, and a parent that explains it.
    - Use the parent to work out where the user pasted ([Where the user pasted it](investigation.md#where-the-user-pasted-it)): `explorer.exe` is the Run dialog; a browser may be a file-upload window (FileFix); a shell or terminal with no suspicious arguments of its own, starting a downloader at T0, is a paste into an open window. An open-window paste leaves no command line for the pasted text, so its children and connections are all you have.
    - If a Windows binary name runs from a folder other than its usual Windows folder, or it is a renamed copy of a Windows binary (`ProcessVersionInfoOriginalFileName` differs from `FileName`): escalate. Contain (step 8) if not done. Treat the copy as a payload and preserve it (step 11).
    - If a binary is unsigned or untrusted, or a signed EXE runs from a user-writable folder: treat it as a payload. Contain and preserve it (steps 8 to 11).
    - If a script, EXE, DLL, MSI or HTA that the pasted command fetched or wrote ran (second-stage payload ran): escalate. Contain (step 8) if not done.
    - If a scheduled task or service started anything in the chain: record it for step 17.

13. **Look for the paste in `RunMRU`** ([Confirm the paste](investigation.md#confirm-the-paste)). Search from T0 − 24h and record every row in the ticket.
    - Expect: a value set by `explorer.exe` at T0 whose data matches the command from step 2.
    - If other values hold a LOLBin, a URL, a lure comment or an encoded string: each is another paste. Decode it (step 6), add it to step 12, and move T0 if it is earlier.
    - If there is no value: this doesn't clear the device. A command that failed leaves no value, and a paste anywhere else never touches the key.

14. **Ask the user, through the customer contact:** what page were you on, how did you get there, what did it tell you to do, where did you paste, how many times, what happened next, and did anyone tell you to do this? Ask them not to reopen the page and not to sign in on this device.
    - Expect: the answers in the ticket. Step 22 uses them.
    - If they saw a "verify you're human" check, a CAPTCHA, or a "fix this error" prompt before pasting: escalate (user reports a verification or fix-an-error prompt before pasting). This is the lure; never a false positive.
    - If someone told them to paste, by phone, chat or remote session: ask the customer contact, not the user, for the helpdesk ticket. Attackers pose as IT support. If the customer's helpdesk can't confirm it: escalate (user was told to paste by someone the helpdesk can't confirm).
    - If they typed a password into the page or a prompt: treat that password as known to the attacker. Step 20 covers that account.
    - If you can't reach them: record it and continue. Don't hold any other step for this one.

15. **List what the chain did:** network connections, files written, registry changes and DLLs loaded, for each process from step 12. Run the callout query for each domain from step 6 ([Network callouts](investigation.md#network-callouts)) and the file query ([Dropped payloads and persistence](investigation.md#dropped-payloads-and-persistence)).
    - Expect: nothing beyond what a named purpose explains.
    - Record every external IP, domain and URL, and every file path and SHA1. Steps 21, 24, 25 and 26 use them.
    - A connection that network protection blocked can still show as `ConnectionSuccess`. Check the alerts queue for the block.
    - If the chain reached the staging or C2 URL (network callout confirmed to the staging or C2 URL): escalate; a payload was likely delivered. Contain (step 8) if not done.
    - If the chain wrote or ran an unknown EXE or DLL, or one with a stealer detection (infostealer or unknown payload executed, or one can't be ruled out): escalate and preserve it (step 11). Use step 11 of the [malware alert playbook](../01-malware-alert/playbook.md) to name it. Step 19 covers the credentials.

16. **Check whether anything is still running or connecting.** Use the package's Processes and Network connections folders, then Live Response `processes` and `connections` for the current state.
    - Expect: nothing from the chain running; no connections to the IPs or domains from steps 6 and 15.
    - If C2 looks live (connections to an IOC from steps 6 or 15 still happening): escalate now.
    - Record what is still running and its PID; step 24 needs it.

17. **Check persistence** with the [persistence playbook](../04-persistence-detected/playbook.md): run keys, scheduled tasks, services, startup folders and WMI. Compare with the package's Autoruns, Scheduled tasks and Services.
    - Expect: nothing the attacker added.
    - If found: escalate (persistence established after the paste). Record each item. Don't remove anything yet; that is step 26.
    - Mark any item that is a changed legitimate entry, not a new one (for example Winlogon `Userinit`, `Shell` or `Notify`, or an existing service's `ImagePath`). Steps 24 and 26 treat it differently.

18. **Check identity on the device:** lsass access, credential-tool keywords, new accounts and lateral movement. Use step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md).
    - Expect: no hits.
    - If any hit: escalate, and follow the 06 playbook from step 2 for this device.

---

## 4. Contain the accounts

A stolen session stays valid until it is revoked, so do this before you scope the estate. If you don't hold the rights for a step here (disable, revoke, reset), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

19. **Decide whether the credentials on this device are exposed.** Microsoft calls an infostealer the most prolific ClickFix final payload. A stealer reads the browser, so the lsass check in step 18 doesn't cover this. The credentials count as not exposed only if all of these hold:
    - The pasted command is known and fully decoded (step 6).
    - Step 15 shows no connection from the chain, or only connections an alert shows as blocked.
    - The chain wrote and ran nothing beyond the pasted command (steps 12 and 15).
    - Nothing from the chain is running (step 16).
    - No browser credential theft signal ([Identity and browser credentials](investigation.md#identity-and-browser-credentials)).
    - Expect: the decision and the reason in the ticket.
    - Anything else, or you can't tell: an infostealer can't be ruled out. Escalate (infostealer or unknown payload executed, or one can't be ruled out) and do step 20. Don't wait for proof of a stealer: it can run in memory and leave no file.
    - If a browser credential theft signal appears: also escalate (browser credential theft signal).

20. **Contain every exposed account.** Do this when step 19 can't rule out a stealer, and for any account whose password was typed into the page (step 14). Otherwise go to step 21. There is one threshold: don't wait for a suspicious sign-in.
    - List the users: the user who pasted first, then every user who logged on to the device (step 8 of the [credential compromise playbook](../06-credential-compromise/playbook.md)). Their browser-saved passwords and signed-in web sessions are exposed.
    - For each user, in the 06 playbook: do steps 9 and 11, then steps 13 to 20 in order. That captures evidence, disables, revokes sessions, removes what the attacker added, resets the password from a clean device and re-enables. Its step 14 stops you on privileged and service accounts, and when many accounts are exposed at once.
    - Also run the sign-in query ([Identity and browser credentials](investigation.md#identity-and-browser-credentials)) for each user, and rerun it with a later T0 until the sessions are revoked. A stolen session can be used days after the paste.
    - If a sign-in comes from an IP, country or device the user doesn't recognise, or Entra ID Protection has a detection: escalate (suspicious sign-in for an exposed account since T0).
    - If an account logged on to a device it has no documented reason to use: escalate (exposed account logged on to a device it has no documented reason to use), and run this playbook from step 2 for that device.
    - Password reset doesn't replace revoking sessions. Revoking doesn't reach sites outside Entra or apps that issue their own session tokens. Tell the customer which users need resets for other sites saved in the browser, and which apps need their sessions ended.
    - Expect: each exposed user listed in the ticket with what was done.

---

## 5. Scope

21. **Search the estate** ([Scope across the estate](investigation.md#scope-across-the-estate)): the tenant-wide hunt with every domain from steps 6 and 15, the shape of the command in process events, `RunMRU` for the lure comment, and the hash sweep with the SHA1 of each non-Windows file from steps 11 and 15. Never hash-sweep the LOLBin.
    - Expect: only this device.
    - If other devices: escalate (same lure, domain or command pattern on more than one device). Run steps 2 to 20 for each device where a command ran. A network hit alone shows a visit, not a paste: check that device's process chain around the hit first.
    - Zero rows doesn't prove no spread: domains rotate, and URL-click data covers only Safe Links clicks from email, Teams and Office apps. Many devices is a reason to scope wider, never to close.

22. **Find how the user got to the page** ([How the user got to the page](investigation.md#how-the-user-got-to-the-page)): the user's answer from step 14, then the browser's connections before T0.
    - Expect: the vector recorded: search result, advert, compromised site or phishing link, with the lure domain and the staging domain.
    - If a phishing email: use the [phishing email playbook](../12-phishing-email/playbook.md) for the other recipients.
    - If none is found: record the vector as unknown.

23. **Check for EtherHiding** ([Special case: EtherHiding](investigation.md#special-case-etherhiding)) if the lure sat on a compromised legitimate site, or if any process in steps 15 or 22 reached a blockchain RPC host. Otherwise go to step 24. Look at browser connections to RPC hosts just before T0, then run the EtherHiding query for non-browser processes.
    - Expect: nothing. Record the incident as a standard domain-based lure.
    - If a non-browser process reached an RPC host, or a browser reached one just before the lure and the customer has no web3 use: escalate (EtherHiding variant confirmed: flag for TI; standard domain blocklists won't catch it). Record the RPC host. The contract address comes from TI or the IR lead; don't visit the page to find it.
    - An empty query doesn't rule it out: it excludes browsers and its host list is illustrative.

---

## 6. Stop, block, remove

Only after step 10 is done (or recorded as failed) and step 11 is done on every device in scope. If you don't hold the rights for a step here, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

24. **Stop what is still running** (step 16).
    - Nothing from the chain running: go to step 25.
    - If a changed legitimate entry recorded in step 17 (for example Winlogon `Userinit`, or an existing service's `ImagePath`) points to the file: don't run Stop and Quarantine File yourself. Microsoft doesn't say which registry data it deletes. Ask the IR lead first.
    - A payload not signed by Microsoft or a trusted non-Microsoft publisher (an EXE or DLL from steps 11 and 15, or a script if its file page offers the action): file page → Stop and Quarantine File. It stops its running processes, quarantines the file and deletes persistent data such as registry keys, on every device where it was seen in the last 30 days.
      - Expect: the Action center shows Success for each device.
      - If Failed: record the reason. If Pending: the device is offline; the action times out after three days.
      - If Defender warns that the file is widely used in the organization: cancel and escalate. It may be a business application.
      - A quarantined file can be restored if it turns out to be clean.
    - A LOLBin still running, or another running file signed by Microsoft or a trusted publisher (for example `powershell.exe`, `mshta.exe`, `rundll32.exe`, or a remote management agent): Stop and Quarantine File can't be used on it. Don't use Live Response `remediate` on the process either: on a process it stops the process and deletes the image file. Escalate; the IR lead decides how to stop it. The device stays isolated meanwhile. The script, HTA or DLL it ran: Stop and Quarantine File as above if the file page offers it; otherwise it is removed in step 26.

25. **Block the IOCs** with Defender for Endpoint indicators (Settings → Endpoints → Indicators). Block the SHA1 of each malicious non-Windows file from steps 11 and 15, and the external IPs, URLs and domains from steps 6, 15 and 22 (the lure and staging domains).
    - Never add a block indicator for the hash of a Windows binary or another legitimate signed tool. A file indicator stops the file being read, written or executed on every device in its scope.
    - File hashes: PE files only (`.exe`, `.dll`), and Defender Antivirus must be in active mode. A script can't be blocked by hash; block the URL it came from. Blocks typically apply within 15 minutes, 30 on average, and can take over 2 hours.
    - IPs and URLs: external IPs only, one address per indicator (no ranges). Outside Microsoft Edge, blocking needs Network Protection in block mode. An HTTPS full URL path can be blocked only in Edge; other browsers block by domain, and only with QUIC and Encrypted Client Hello disabled. Blocks can take up to 48 hours; most apply within 2 hours.
    - Don't block a domain the customer uses for business (for example a cloud storage or code-hosting site, or a compromised site they rely on). Block the full URL (Edge only) or escalate.
    - EtherHiding: block an RPC host only if the customer confirms it has no web3 use; it is shared infrastructure. If they do, or can't say, treat it as a domain the customer uses for business. A contract address can't be blocked at the network layer; record it as an IOC.
    - Submit the lure domain, staging URL and, for EtherHiding, the RPC host and contract address to the TI watchlist.
    - Expect: each indicator listed with its expiry.
    - A blocked connection can still appear as `ConnectionSuccess` in network events. Check the alerts queue for the block, not the connection log.

26. **Remove persistence and remaining files** found in steps 15 and 17, using the [persistence playbook](../04-persistence-detected/playbook.md). A script or other payload that Stop and Quarantine didn't cover: Live Response `remediate file` with its full path deletes it. Do this only once step 11 holds a copy.
    - Expect: each item removed and recorded.
    - Never point `remediate` at a Windows binary.
    - If the persistence is a changed legitimate entry, not a new one (for example Winlogon `Userinit`, `Shell` or `Notify`, or an existing service's `ImagePath`): don't delete the value or the key. Escalate; the IR lead restores the original data.
    - Accounts the attacker created: disable them; delete only with the IR lead's agreement.

27. **Confirm every action in the Action center** (History tab): isolation, package, quarantine, Live Response actions.
    - Expect: every action Success.
    - If an action failed or an item from steps 15 and 17 has no action: do it from the device or file page, or with Live Response `remediate` (not on Windows binaries). Record each.
    - If it still fails: escalate. Don't release the device.

28. **Run a full antivirus scan** (device page → Run antivirus scan → Full). From 1 September 2026 Microsoft no longer runs automated investigation (AIR) as a separate experience for Defender for Endpoint alerts; for on-demand investigations it says to run a full antivirus scan.
    - Expect: the scan completes with no new detections.
    - If it finds anything: escalate, treat each detection as a new alert, and go back to step 12 for it.

---

## 7. Clean or reimage, then release

If you don't hold the rights to release the device, request it from the customer's IT contact once the IR lead or the criteria in step 30 allow it.

29. **Decide clean or reimage.** Reimage when attacker code ran and you can't account for all of it: an unknown or stealer payload ran, step 19 couldn't rule a stealer out, someone had hands-on access (for example a burst of discovery commands such as `whoami`, `net group` or `nltest` in the chain), or you can't account for every item the chain created. Don't try to clean a device that ran an unknown payload with unknown persistence. For High and above, the IR lead decides.
    - Reimaging destroys what is left on the disk. Do it only after steps 10 and 11 are done or recorded as failed, and after the IR lead says no further collection (for example a disk image) is needed.
    - Expect: the decision and who made it in the ticket.

30. **Release only when all of these hold:**
    - Steps 24 to 28 done, every action Success.
    - Credentials handled (steps 18 to 20).
    - Indicators in place (step 25).
    - No new alerts and no connections to the IOCs while isolated, for the period the IR lead sets.
    - For High and above, the IR lead approves the release.
    - If isolation will auto-lift (step 9) before these hold: escalate before that date.
    - Then: device page → Release from isolation. Tell the customer the outcome.

---

## 8. Close out

- [ ] Classification set: True positive, Informational expected activity (authorised test), or False positive (only per Closing as a false positive)
- [ ] Full delivery chain documented (for example search result → compromised site → fake CAPTCHA → user pasted into Run → PowerShell → payload)
- [ ] Decoded command (step 6), `RunMRU` rows (step 13) and the user's answers (step 14) in the ticket
- [ ] Credential decision (step 19), and every exposed user with what was done (step 20)
- [ ] Whether this was a standard domain-based lure or an EtherHiding variant (step 23)
- [ ] Other affected users and devices documented
- [ ] IOCs documented (SHA1, IPs, domains, URLs, RPC host, contract address) and which were blocked
- [ ] Findings written up: how the user got there, what ran, what it did, persistence, spread, credentials, remediation, clean or reimage
- [ ] Escalated if any trigger below was hit

---

## Closing as a false positive

Close only with a named, verifiable benign cause, and record it. "Nothing else found", "the user says it was fine", "it's a Microsoft-signed binary", low volume, or "seen on many devices" is never enough; spread means scope wider. A remote session isn't enough either: attackers pose as IT support and use legitimate remote-access tools. All of these must hold:

- The customer's helpdesk confirms, through the customer contact and not through the user, a ticket opened before T0 that names the technician and the command. The remote session, if there was one, is theirs.
- The command, decoded if it was encoded (step 6), is fully readable and matches a documented internal script or a vendor's published repair command word for word: name the script, the vendor page or the change record.
- Every host it contacts is the customer's own or the vendor's own, as named in that script, page or record. Looking like a vendor's domain isn't enough.
- The user reports no verification check, CAPTCHA or "fix this error" prompt before pasting (step 14).
- Every non-Windows binary in the chain shows the vendor as `Signer`, with `IsTrusted` true, in `DeviceFileCertificateInfo` for its SHA1.
- Steps 12 to 15 found nothing else: no unexplained child processes, no connections to hosts the script or page doesn't name, and no unexplained files or registry changes.
- No item in Escalate if appears anywhere in the process tree.

An authorised test that was detected correctly (with a ticket): classify as Informational, expected activity, not False positive.

Never close these yourself, even if a test, an admin or a support session is mentioned: any item in Escalate if below. Escalate; the IR lead confirms any authorised test.

If any condition can't be confirmed: don't close. Escalate.

---

## Escalate if

See also [escalation triggers](../../reference/escalation-triggers.md).

```
Shadow copy deletion: vssadmin delete shadows, wmic shadowcopy delete, or Win32_ShadowCopy removed through PowerShell
bcdedit ... recoveryenabled No
rundll32.exe with comsvcs.dll in the command line, whatever follows it
Mimikatz, sekurlsa:: or other credential-tool keywords in a command line
Event logs cleared (wevtutil cl)
PsExec, psexesvc or WMI execution to or from another host
Defender or EDR tampered with or stopped
Any hit in step 2 of the credential compromise playbook (step 18)
Privileged user, server or jump host
macOS device
Command, decoded if it was encoded, downloads or runs code from an external host, or loads an assembly from memory, and no ticket from the customer's helpdesk names that exact command
Encoded content that can't be decoded to readable text
User reports a verification or fix-an-error prompt before pasting
User was told to paste by someone the helpdesk can't confirm
Windows binary name running from a folder other than its usual Windows folder, or a renamed copy of a Windows binary
Second-stage payload ran (a script, EXE, DLL, MSI or HTA that the pasted command fetched or wrote)
Network callout confirmed to the staging or C2 URL: payload likely delivered
Infostealer or unknown payload executed, or one can't be ruled out
Browser credential theft signal
Suspicious sign-in for an exposed account since T0
Exposed account logged on to a device it has no documented reason to use
C2 looks live (connections to an IOC from steps 6 or 15 still happening)
Same lure, domain or command pattern on more than one device
EtherHiding variant confirmed: flag for TI; standard domain blocklists won't catch it
Persistence established after the paste
Persistence is a changed legitimate entry, not a new one (for example Winlogon Userinit, Shell or Notify, or an existing service's ImagePath)
Device can't be isolated (pending, offline, domain controller, other Tier 0 server, Hyper-V host)
Stop and Quarantine File can't be used on a running process (Microsoft or trusted-publisher signed), or Defender warns the file is widely used
A domain to block is one the customer uses for business
Remediation failed and can't be completed
Full antivirus scan after removal finds new detections
Isolation will auto-lift before the release criteria hold
```

---

## Actions — Defender XDR quick reference

| Action | Where |
|--------|-------|
| Isolate device | Device page → Actions → Isolate device |
| Collect investigation package | Device page → Actions → Collect investigation package |
| Live Response (`processes`, `connections`, `getfile`, `remediate`) | Device page → Actions → Initiate Live Response session |
| Collect file | File page → Collect file |
| Stop and quarantine file | File page → Stop and Quarantine File |
| Add indicator | Settings → Endpoints → Indicators |
| Revoke sessions | Entra admin center → user → Revoke sessions |
| Run AV scan | Device page → Actions → Run antivirus scan |
| Check actions | Defender XDR → Action center (History) |
| Release isolation | Device page → Actions → Release from isolation |
