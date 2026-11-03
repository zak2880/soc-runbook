# Suspicious process — playbook

Work top to bottom. Each step is one action, what you should see, and what to do if you don't. Capture evidence before you stop, quarantine, remove or delete anything. Queries and background are in the [investigation](investigation.md).

T0 = the first malicious event in the chain (the document opened, the command pasted, or the first suspicious process), in UTC. It is not the alert time. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

---

## 1. Triage

1. **Record the incident:** severity, title, how many alerts are grouped. Run [All alerts for this device](../01-malware-alert/investigation.md#all-alerts-for-this-device).
   - Expect: alerts that all belong to this process chain.
   - If other categories appear (credential access, lateral movement, C2): record them and treat this as a multi-stage incident. Check them against Escalate if before you continue.

2. **Record the device and the process.** Device FQDN and OS; the user's SAM name and UPN; for the suspicious process: name, full path, SHA1, full command line, PID and creation time; the parent's name and command line; the grandparent's name. Take them from the alert's process tree or the Device timeline.
   - Expect: all known.
   - If the PID or creation time is missing: identify the process in the Device timeline. Don't match on the process name alone; PIDs are reused.

3. **Set T0** from the Device timeline: the earliest event in the chain.
   - Expect: T0 at or before the alert time.
   - If you can't find it: use the suspicious process's creation time and mark T0 as an estimate.

4. **Check whether it was blocked** ([Was it blocked?](investigation.md#was-it-blocked)): the alert's detection status, then the device's ASR events from T0.
   - Expect: Prevented or Blocked, and an ASR event ending in `Blocked` if a rule was involved.
   - If Detected, or an ASR event ends in `Audited`: the action ran. Do steps 5 and 6, then go to step 8.
   - Blocked covers that one action. Processes earlier in the chain may have run; step 7 checks them.

5. **Check the whole process tree for an immediate trigger.** Read every command line in the tree for:
   - Shadow copy deletion: `vssadmin delete shadows`, `wmic shadowcopy delete`, or `Win32_ShadowCopy` removed through PowerShell
   - `bcdedit` ... `recoveryenabled No`
   - `rundll32.exe` with `comsvcs.dll` in the command line, whatever follows it
   - Mimikatz, `sekurlsa::` or other credential-tool keywords in a command line
   - Event logs cleared (`wevtutil cl`)
   - PsExec, `psexesvc` or WMI execution to or from another host
   - Defender or EDR tampered with or stopped
   - Expect: none.
   - If any: escalate now and go to step 8. For a credential item, also run step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md) for this device.
   - WMI to another host includes `wmic /node:` and `-ComputerName` on `Invoke-CimMethod` or `Invoke-WmiMethod`. Defender tampering includes `Set-MpPreference` changes and new exclusions.

6. **Decode any encoded content** ([Decode before you judge](investigation.md#decode-before-you-judge)): `-e`, `-ec`, `-enc`, `-EncodedCommand`, `FromBase64String`, `certutil -decode` input, script arguments to `mshta`. Decode PowerShell as UTF-16LE on your analysis machine. Never run the result.
   - Expect: readable text whose action you can name. Record every URL, IP, domain and file name it contains.
   - If it contains a step 5 item: escalate now and go to step 8.
   - If the decoded command downloads or runs code from an external host, or loads an assembly from memory, and its parent is not the customer's confirmed management agent: escalate and go to step 8.
   - If the encoded content can't be decoded to readable text: escalate and go to step 8.
   - The switches alone (`-nop`, `-w h`, `-enc`) are not a verdict. Management tools use them too.

7. **Decide the path.**
   - It looks like sanctioned activity (a named management tool or a documented script): do steps 12 to 14. Close only if every condition in Closing as a false positive holds; otherwise go to step 8.
   - Detection status Prevented or Blocked, no ASR event ends in `Audited`, and the Device timeline shows nothing else from the chain ran after T0 (no other child processes, connections or file writes): do steps 12 to 14, then steps 18 and 19, without containing. If they find anything, come back to step 8.
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

9. **Isolate the device** (device page → Isolate device). Isolation keeps the device connected to the Defender service.
   - Expect: the Action center shows the isolation as completed.
   - If not (pending or offline): Defender retries for up to three days. Escalate and report the device as not isolated.
   - Microsoft states isolation is lifted automatically after seven days (VERIFY (tenant)). Put the date in the ticket and re-check it.

10. **Collect the investigation package** (device page → Collect investigation package). It records autoruns, running processes, network connections, prefetch, scheduled tasks, services and the Security event log.
    - Expect: the package is downloadable from the Action center.
    - If not: collection can fail on low battery or a metered connection. Retry once, then record the failure and continue.
    - Don't stop a process, run an antivirus scan, Stop and Quarantine File, or Live Response `remediate` until this step is done or recorded as failed. Those actions remove the processes, files and registry entries the package would have recorded.

11. **Preserve the payload:** every file the chain ran or wrote that is not a Windows binary, for example the script (`.ps1`, `.js`, `.vbs`, `.hta`), DLL or EXE named in steps 2 and 6. On the file page, select Collect file if it is shown; Download file instead means Defender already holds a copy. If the file page doesn't offer either, use Live Response `getfile` with the full path.
    - Expect: each payload held by Defender or downloaded, with its path and SHA1 in the ticket.
    - If Collect file is disabled: the file hasn't been seen in the past 30 days, or you lack the permission. Record which, and try `getfile`.
    - Don't download an lsass dump file; follow step 7 of the [credential compromise playbook](../06-credential-compromise/playbook.md). Don't open or run any payload on your own workstation.

---

## 3. Investigate

12. **Trace the whole chain** in the alert's process tree and the Device timeline from T0: grandparent, parent, process, children and grandchildren. Link each child to its parent on PID plus creation time ([Follow the process](investigation.md#follow-the-process)).
    - Expect: every process recorded with path, SHA1 and command line, and a parent that explains it.
    - If an Office app or `WmiPrvSE.exe` started PowerShell, cmd, mshta or a script host, and ASR didn't block it: escalate.
    - If the parent is `WmiPrvSE.exe`: find what called WMI ([Hidden parents](investigation.md#hidden-parents)). A call from another device is WMI execution to or from another host (step 5): escalate. Use step 9 of the [credential compromise playbook](../06-credential-compromise/playbook.md) to scope it.
    - If the parent is `explorer.exe` and the command has a URL or encoded arguments: it may be a Run-dialog paste. Use the [ClickFix investigation](../13-clickfix/investigation.md) for scope, and continue here.
    - If an Office app is the parent: record the document it had open; it is the delivery file for step 19.
    - If a scheduled task or service started it: record it for step 16.

13. **Check each binary in the chain:** path, original file name and signer ([Process name spoofing](investigation.md#process-name-spoofing)).
    - Expect: Windows binaries run from their usual Windows folder with a matching original file name. Other binaries show `IsSigned` and `IsTrusted` true and a known vendor as `Signer` in `DeviceFileCertificateInfo`.
    - If a Windows binary name runs from a folder other than its usual Windows folder, or it is a renamed copy of a Windows binary (`ProcessVersionInfoOriginalFileName` differs from `FileName`): escalate. Contain (step 8) if not done.
    - If a signed EXE runs from a user-writable folder: check the DLLs it loaded from that folder. An unsigned or untrusted DLL there is the payload; preserve it (step 11).
    - If a binary is unsigned or untrusted and runs from a user-writable folder: treat it as a payload. Contain and preserve it (steps 8 to 11).

14. **List what the chain did:** network connections, files written, registry changes and DLLs loaded, for each process from step 12 ([Follow the process](investigation.md#follow-the-process)).
    - Expect: nothing beyond what a named purpose explains.
    - Record every external IP, domain and URL, and every file path and SHA1. Steps 18, 21 and 22 use them.
    - A connection that network protection blocked can still show as `ConnectionSuccess`. Check the alerts queue for the block.
    - If the chain wrote or ran an unknown EXE or DLL, or one with a stealer detection (infostealer or unknown payload executed): escalate, and run steps 11 and 17 of the [malware alert playbook](../01-malware-alert/playbook.md) for that file.

15. **Check whether anything is still running or connecting.** Use the package's Processes and Network connections folders, then Live Response `processes` and `connections` for the current state.
    - Expect: nothing from the chain running; no connections to the IPs or domains from steps 6 and 14.
    - If C2 looks live (connections to an IOC from steps 6 or 14 still happening): escalate now.
    - Record what is still running and its PID; step 20 needs it.

16. **Check persistence** with the [persistence playbook](../04-persistence-detected/playbook.md): run keys, scheduled tasks, services, startup folders and WMI. Compare with the package's Autoruns, Scheduled tasks and Services.
    - Expect: nothing the attacker added.
    - If found: record each item. Don't remove anything yet; that is step 22.

17. **Check identity:** lsass access, credential-tool keywords, new accounts and lateral movement. Use step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md).
    - Expect: no hits.
    - If any hit: escalate, and follow the 06 playbook from step 2 for this device.

---

## 4. Scope

18. **Search the estate** ([Scope across the estate](investigation.md#scope-across-the-estate)). For non-Windows files from steps 11 and 14: the hash sweep with their SHA1. For a LOLBin chain: the PowerShell, Office and LOLBin queries estate-wide with the same T0, and the domains and IPs from steps 6 and 14.
    - Expect: only this device.
    - If other devices: escalate (same malicious file or command pattern on more than one device). Run steps 2 to 17 for each device where it ran.
    - Zero rows doesn't prove no spread ([What the process data doesn't show](investigation.md#what-the-process-data-doesnt-show)).

19. **Find how it started.** Ask the user, through the customer contact, what they were doing at T0: did they open a file, paste a command, or follow someone's instructions? Then check the delivery:
    - A document (step 12) from email: use the [phishing email playbook](../12-phishing-email/playbook.md).
    - A Run-dialog paste: use the [ClickFix investigation](../13-clickfix/investigation.md).
    - A download: `FileOriginUrl` and `FileOriginReferrerUrl` on the file's creation event.
    - Another device (WMI, PsExec): that device is in scope; run this playbook for it.
    - Expect: the vector recorded. If none is found: record it as unknown.

---

## 5. Stop, block, remove

Only after step 10 is done (or recorded as failed) and step 11 is done on every device in scope. If you don't hold the rights for a step here, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

20. **Stop what is still running** (step 15).
    - Nothing from the chain running: go to step 21.
    - A payload not signed by Microsoft or a trusted non-Microsoft publisher (an EXE, DLL or script from steps 11 and 14): file page → Stop and Quarantine File. It stops its running processes, quarantines the file and deletes persistent data such as registry keys, on every device where it was seen in the last 30 days.
      - Expect: the Action center shows Success for each device.
      - If Failed: record the reason. If Pending: the device is offline; the action times out after three days.
      - If Defender warns that the file is widely used in the organization: cancel and escalate. It may be a business application.
      - A quarantined file can be restored if it turns out to be clean.
    - A Windows binary or another file signed by Microsoft or a trusted publisher (for example `powershell.exe`, `mshta.exe`, `rundll32.exe`, or a remote management agent): Stop and Quarantine File can't be used on it. Don't use Live Response `remediate` on the process either: on a process it stops the process and deletes the image file. Escalate; the IR lead decides how to stop it. The device stays isolated meanwhile. Quarantine the script, HTA or DLL it ran as above.

21. **Block the IOCs** with Defender for Endpoint indicators (Settings → Endpoints → Indicators). Block the SHA1 of each malicious non-Windows file from steps 11 and 14, and the external IPs, URLs and domains from steps 6 and 14.
    - Never add a block indicator for the hash of a Windows binary or another legitimate signed tool. A file indicator stops the file being read, written or executed on every device in its scope.
    - File hashes: PE files only (`.exe`, `.dll`), and Defender Antivirus must be in active mode. A script can't be blocked by hash; block the URL it came from. Blocks typically apply within 15 minutes, 30 on average, and can take over 2 hours.
    - IPs and URLs: external IPs only, one address per indicator (no ranges). Outside Microsoft Edge, blocking needs Network Protection in block mode. An HTTPS full URL path can be blocked only in Edge; other browsers block by domain, and only with QUIC and Encrypted Client Hello disabled. Blocks can take up to 48 hours; most apply within 2 hours.
    - Don't block a domain the customer uses for business (for example a cloud storage or code-hosting site). Block the full URL (Edge only) or escalate.
    - Expect: each indicator listed with its expiry.
    - A blocked connection can still appear as `ConnectionSuccess` in network events. Check the alerts queue for the block, not the connection log.

22. **Remove persistence and remaining files** found in steps 14 and 16, using the [persistence playbook](../04-persistence-detected/playbook.md). A script or other payload that Stop and Quarantine didn't cover: Live Response `remediate file` with its full path deletes it. Do this only once step 11 holds a copy.
    - Expect: each item removed and recorded.
    - Never point `remediate` at a Windows binary.
    - If the persistence is a changed Windows value (for example under Winlogon) rather than a new entry: don't delete it. Escalate; the IR lead restores the original value.
    - Accounts the attacker created: disable them; delete only with the IR lead's agreement.

23. **Confirm every action in the Action center** (History tab): isolation, package, quarantine, Live Response actions.
    - Expect: every action Success.
    - If an action failed or an item from steps 14 and 16 has no action: do it from the device or file page, or with Live Response `remediate` (not on Windows binaries). Record each.
    - If it still fails: escalate. Don't release the device.

24. **Run a full antivirus scan** (device page → Run antivirus scan → Full). From 1 September 2026 Microsoft no longer runs automated investigation (AIR) as a separate experience for Defender for Endpoint alerts; for on-demand investigations it says to run a full antivirus scan.
    - Expect: the scan completes with no new detections.
    - If it finds anything: escalate, treat each detection as a new alert, and go back to step 12 for it.

---

## 6. Clean or reimage, then release

If you don't hold the rights to release the device, request it from the customer's IT contact once the IR lead or the criteria in step 26 allow it.

25. **Decide clean or reimage.** Reimage when an unknown or stealer payload ran, someone had hands-on access (for example a burst of discovery commands such as `whoami`, `net group` or `nltest` in the chain), or you can't account for every item the chain created. For High and above, the IR lead decides.
    - Reimaging destroys what is left on the disk. Do it only after steps 10 and 11 are done or recorded as failed, and after the IR lead says no further collection (for example a disk image) is needed.
    - Expect: the decision and who made it in the ticket.

26. **Release only when all of these hold:**
    - Steps 20 to 24 done, every action Success.
    - Credentials handled (step 17).
    - Indicators in place (step 21).
    - No new alerts and no connections to the IOCs while isolated, for the period the IR lead sets.
    - For High and above, the IR lead approves the release.
    - If isolation will auto-lift (step 9) before these hold: escalate before that date.
    - Then: device page → Release from isolation. Tell the customer the outcome.

---

## 7. Close out

- [ ] Classification set: True positive, Informational expected activity (authorised test, sanctioned tool), or False positive (only per Closing as a false positive)
- [ ] Decoded command (step 6) and full process chain (step 12) in the ticket
- [ ] IOCs documented (SHA1, IPs, domains, URLs) and which were blocked
- [ ] Findings written up: how it started, what ran, what it did, persistence, spread, credentials, remediation, clean or reimage
- [ ] Escalated if any trigger below was hit

---

## Closing as a false positive

Close only with a named, verifiable benign cause, and record it. "Nothing else found", "expected for this user's role", low volume, or "seen on many devices" is never enough; spread means scope wider. A signed parent isn't enough either: a remote management tool an attacker installed is signed by its vendor too. All of these must hold:

- The command line, decoded if it was encoded (step 6), is fully readable and does a named, documented thing: name the script, product or change record.
- The parent is the customer's own management agent or application: name the product, and confirm with the customer's asset list or a change record that this installation is theirs.
- Every non-Windows binary in the chain shows the vendor as `Signer`, with `IsTrusted` true, in `DeviceFileCertificateInfo` for its SHA1.
- Steps 12 to 14 found nothing else: no unexplained child processes, no connections to hosts the product doesn't document, and no unexplained files or registry changes.
- No item in Escalate if appears anywhere in the process tree.

A sanctioned admin or test tool that was detected correctly (for example an authorised test with a ticket): classify as Informational, expected activity, not False positive.

Never close these yourself, even if a test or an admin is mentioned: any item in Escalate if below. Escalate; the IR lead confirms any authorised test.

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
Any hit in step 2 of the credential compromise playbook (step 17)
Office app or WmiPrvSE.exe started PowerShell, cmd, mshta or a script host, and ASR didn't block it
Decoded command downloads or runs code from an external host, or loads an assembly from memory, and its parent is not the customer's confirmed management agent
Encoded content that can't be decoded to readable text
Windows binary name running from a folder other than its usual Windows folder, or a renamed copy of a Windows binary
Infostealer or unknown payload executed
C2 looks live (connections to an IOC from steps 6 or 14 still happening)
Same malicious file or command pattern on more than one device
Device can't be isolated (pending, offline, domain controller, other Tier 0 server, Hyper-V host)
Stop and Quarantine File can't be used on a running process (Microsoft or trusted-publisher signed), or Defender warns the file is widely used
A domain to block is one the customer uses for business
Persistence is a changed Windows value (for example under Winlogon), not a new entry
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
| Run AV scan | Device page → Actions → Run antivirus scan |
| Check actions | Defender XDR → Action center (History) |
| Release isolation | Device page → Actions → Release from isolation |
