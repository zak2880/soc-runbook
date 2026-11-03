# LOLBin abuse — playbook

Work top to bottom. Each step is one action, what you should see, and what to do if you don't. Capture evidence before you stop, cancel, quarantine, remove or delete anything. Queries and background are in the [investigation](investigation.md).

The LOLBin is a Windows binary. Never quarantine, block, delete or `remediate` the binary itself; act on what it fetched, decoded, ran or wrote.

T0 = the first malicious event in the chain (the document opened, the command pasted, or the first suspicious process), in UTC. It is not the alert time. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

---

## 1. Triage

1. **Record the incident:** severity, title, how many alerts are grouped. Run [All alerts for this device](../01-malware-alert/investigation.md#all-alerts-for-this-device).
   - Expect: alerts that all belong to this process chain.
   - If other categories appear (credential access, lateral movement, C2): record them and treat this as a multi-stage incident. Check them against Escalate if before you continue.

2. **Record the device and the LOLBin.** Device FQDN and OS version (WMIC is removed on Windows 11 24H2 and later); the user's SAM name and UPN; for the LOLBin: name, full path, original file name, SHA1, full command line, PID and creation time; the parent's name and command line; the grandparent's name. Take them from the alert's process tree or the Device timeline.
   - Expect: all known.
   - If the PID or creation time is missing: identify the process in the Device timeline. Don't match on the process name alone; LOLBins run many times a day and PIDs are reused.

3. **Set T0** from the Device timeline: the earliest event in the chain.
   - Expect: T0 at or before the alert time.
   - If you can't find it: use the LOLBin's creation time and mark T0 as an estimate.

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
   - If any: escalate now and go to step 8. Do step 6 after step 12. For a credential item, also run step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md) for this device.
   - These hold even if ASR blocked the command: a blocked dump command was still run by someone.
   - WMI to another host includes `wmic /node:` and `-ComputerName` on `Invoke-CimMethod` or `Invoke-WmiMethod`. Defender tampering includes `Set-MpPreference` changes and new exclusions.

6. **Decode any encoded content** ([Decode before you judge](../02-suspicious-process/investigation.md#decode-before-you-judge)): `-e`, `-ec`, `-enc`, `-EncodedCommand`, `FromBase64String`, script arguments to `mshta`. Decode PowerShell as UTF-16LE on your analysis machine. Never run the result. For `certutil -decode` or `-decodehex`, find the input file instead; don't run certutil yourself.
   - Expect: readable text whose action you can name. Record every URL, IP, domain and file name it contains.
   - If it contains a step 5 item: escalate now and go to step 8.
   - If the decoded command downloads or runs code from an external host, or loads an assembly from memory, and its parent is not the customer's confirmed management agent: escalate and go to step 8. Confirmed means a named product that the customer's asset list or a change record shows is their own installation.
   - If the decoded command opens a connection to an external host (for example a TCP client object): it may be a reverse shell. Escalate and go to step 8.
   - If the encoded content can't be decoded to readable text: escalate and go to step 8.
   - The switches alone (`-nop`, `-w h`, `-enc`) are not a verdict. Management tools use them too.

7. **Decide the path.**
   - A LOLBin fetched a file or script from an external host, by IP or domain name (`certutil -urlcache`, `-verifyctl` or `-URL`; `bitsadmin /transfer` or `/addfile`; `Start-BitsTransfer`; `mshta` or `regsvr32` with a URL), and the caller is not the customer's confirmed management agent (step 6): escalate and go to step 8.
   - It looks like sanctioned activity (a named management tool or a documented script): do step 12 if BITS was involved, then steps 13 to 15. Close only if every condition in Closing as a false positive holds; otherwise go to step 8.
   - Detection status Prevented or Blocked, no ASR event ends in `Audited`, and the Device timeline shows nothing else from the chain ran after T0 (no other child processes, connections, file writes or registry changes): you don't need to isolate. Do steps 10 to 21. If any of them finds something, go to step 8. If not: do steps 22 to 26 for the file that started the chain (for example the document), and close out as a true positive.
   - Anything else, or you can't tell: go to step 8. Don't wait to see whether the LOLBin is still running: a certutil download finishes in seconds, and a BITS job keeps going after `bitsadmin.exe` exits.

---

## 2. Contain the device

If you don't hold the rights for a step here (isolation, investigation package, Live Response), or a step needs someone with administrator rights on the device, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

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

10. **Collect the investigation package** (device page → Collect investigation package). It records autoruns, running processes, network connections, prefetch, scheduled tasks, services and the Security event log.
    - Expect: the package is downloadable from the Action center.
    - If not: collection can fail on low battery or a metered connection. Retry once, then record the failure and continue.
    - Don't stop a process, cancel a BITS job, run an antivirus scan, Stop and Quarantine File, or Live Response `remediate` until this step is done or recorded as failed. Those actions remove the processes, files and registry entries the package would have recorded.

11. **Preserve the payload:** every file the chain fetched, decoded, ran or wrote that is not a Windows binary. For example the downloaded or decoded file, the DLL that `rundll32` or `regsvr32` ran, the `.hta`, `.sct` or `.ps1`, and the target files of any BITS job (step 12). Not the LOLBin itself. On the file page, select Collect file if it is shown; Download file instead means Defender already holds a copy. If the file page doesn't offer either, use Live Response `getfile` with the full path.
    - Expect: each payload held by Defender or downloaded, with its path and SHA1 in the ticket.
    - If Collect file is disabled: the file hasn't been seen in the past 30 days, or you lack the permission. Record which, and try `getfile`.
    - If a script or HTA was loaded from a URL and no file was written: record the full URL.
    - Don't download an lsass dump file; follow step 7 of the [credential compromise playbook](../06-credential-compromise/playbook.md). Don't open or run any payload on your own workstation.

12. **Record the BITS jobs** if `bitsadmin.exe`, `Start-BitsTransfer`, `-NotifyCmdLine` or a `svchost.exe -k netsvcs -s BITS` parent appears anywhere in the chain. Otherwise go to step 13. Ask the customer's IT contact to run `bitsadmin /list /allusers /verbose` as an administrator on the device and send you the output ([bitsadmin.exe](investigation.md#bitsadminexe)). On an isolated device that needs someone at the device, or a Live Response library script (`run`) if your team has an approved one.
    - Expect: every job in the ticket with its name, GUID, owner, state, URLs, local files and notify command.
    - Add each job's local files to step 11.
    - If a job has a notify command, or the customer can't name it: escalate (BITS job with a notify command, or one the customer can't name).
    - If nobody can list the jobs: record it, escalate (BITS jobs can't be listed or cancelled), and keep the device isolated.
    - Don't cancel any job yet; that is step 22. Cancelling deletes the job's temporary files.

---

## 3. Investigate

13. **Trace the whole chain** in the alert's process tree and the Device timeline from T0: grandparent, parent, LOLBin, children and grandchildren. Link each child to its parent on PID plus creation time ([Follow the LOLBin](investigation.md#follow-the-lolbin)).
    - Expect: every process recorded with path, SHA1 and command line, and a parent that explains it.
    - If an Office app or `WmiPrvSE.exe` started PowerShell, cmd, mshta, a script host or another LOLBin, ASR didn't block it, and the caller is not the customer's confirmed management agent or application (step 6): escalate.
    - If ASR blocked an Office child (`AsrOfficeChildProcessBlocked`): delivery was attempted. Record the document the Office app had open; it is the delivery file for step 21.
    - If the parent is `WmiPrvSE.exe`: find what called WMI ([Hidden parents for LOLBins](investigation.md#hidden-parents-for-lolbins)). A call from another device is WMI execution to or from another host (step 5): escalate. Use step 9 of the [credential compromise playbook](../06-credential-compromise/playbook.md) to scope it.
    - If the command ran WMI on another host (`wmic /node:` or `-ComputerName`): that is a step 5 item; escalate. The target device is in scope ([wmic.exe](investigation.md#wmicexe)): on it, look for processes whose parent is `WmiPrvSE.exe` around the time of the command, and run this playbook for it.
    - If the parent is `explorer.exe` and the command has a URL or encoded arguments: it may be a Run-dialog paste. Use the [ClickFix investigation](../13-clickfix/investigation.md) for scope, and continue here.
    - If the parent is `svchost.exe -k netsvcs -s BITS`: it is a BITS notify command. Do step 12 if not done.
    - If a scheduled task or service started it: record it for step 17.

14. **Check the LOLBin binary itself:** `FolderPath` and `ProcessVersionInfoOriginalFileName` ([Renamed and copied LOLBins](investigation.md#renamed-and-copied-lolbins)).
    - Expect: it ran from its usual Windows folder (`System32` or `SysWOW64`), and its original file name matches its name.
    - If it ran from another folder, or it is a renamed copy (`ProcessVersionInfoOriginalFileName` differs from `FileName`): escalate. Contain (step 8) if not done. The copy is not the Windows file: treat it as a payload and preserve it (step 11).
    - If it is `wmic.exe` on Windows 11 24H2 or later: WMIC is removed there. Record where the binary came from; a copy outside `System32` or `SysWOW64` is handled as above.

15. **List what the chain did:** network connections, files written, registry changes and DLLs loaded, for the LOLBin and each process from step 13 ([Follow the LOLBin](investigation.md#follow-the-lolbin)). Where BITS was involved, also check `svchost.exe` with `BITS` in its command line.
    - Expect: nothing beyond what a named purpose explains.
    - Record every external IP, domain and URL, and every file path and SHA1. Steps 19, 23 and 24 use them.
    - A connection that network protection blocked can still show as `ConnectionSuccess`. Check the alerts queue for the block.
    - If a LOLBin fetched a file or script from an external host (step 7 list) and the caller is not the customer's confirmed management agent: escalate, and preserve the file (step 11).
    - If the chain wrote or ran an unknown EXE or DLL, or one with a stealer detection (infostealer or unknown payload executed): escalate, and run steps 11 and 17 of the [malware alert playbook](../01-malware-alert/playbook.md) for that file.

16. **Check whether anything is still running or connecting.** Use the package's Processes and Network connections folders, then Live Response `processes` and `connections` for the current state.
    - Expect: nothing from the chain running; no connections to the IPs or domains from steps 6 and 15.
    - If C2 looks live (connections to an IOC from steps 6 or 15 still happening): escalate now.
    - Record what is still running and its PID; step 22 needs it.
    - `bitsadmin.exe` not running doesn't mean its job stopped; step 12 covers the jobs.

17. **Check persistence** with the [persistence playbook](../04-persistence-detected/playbook.md): run keys, scheduled tasks, services, startup folders and WMI. Compare with the package's Autoruns, Scheduled tasks and Services. BITS jobs are persistence too (step 12).
    - Expect: nothing the attacker added.
    - If found: record each item. Don't remove anything yet; that is step 24.

18. **Check identity:** lsass access, credential-tool keywords, new accounts and lateral movement. Use step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md).
    - Expect: no hits.
    - If any hit, including `rundll32.exe` with `comsvcs.dll`: escalate, and follow the 06 playbook from step 2 for this device. Every account with a session on the device is exposed (06 step 8).

---

## 4. Scope

19. **Search the estate** ([Scope across the estate](investigation.md#scope-across-the-estate)). For the LOLBin: the sweep estate-wide with the same T0, and the command-line pattern (URL or domain, output file name, switch set). For non-Windows files from steps 11 and 15: the hash sweep with their SHA1. Then the domains and IPs from steps 6 and 15.
    - Never run a hash sweep on, or block, the LOLBin's own hash: it is on every device.
    - Expect: only this device.
    - If other devices: escalate (same malicious file or command pattern on more than one device). Run steps 2 to 18 for each device where it ran.
    - Zero rows doesn't prove no spread: the sweep misses PowerShell WMI and BITS cmdlets, `-decodehex` without a URL and renamed copies ([KQL — master LOLBin sweep](investigation.md#kql--master-lolbin-sweep)).

20. **Check whether the pattern ran before T0** ([Baseline the pattern, not the binary](investigation.md#baseline-the-pattern-not-the-binary)): the same command-line shape, from the same parent, under the same account, on this device or others.
    - Expect: no earlier run, or earlier runs with a named, documented reason (a script, product or change record the customer shows you).
    - If earlier runs have no documented reason: move T0 to the earliest one and redo steps 19 and 21. This is scope, not a sign that the activity is benign.
    - "The LOLBin is used here every day" is not an answer to this step.

21. **Find how it started.** Ask the user, through the customer contact, what they were doing at T0: did they open a file, paste a command, or follow someone's instructions? Then check the delivery:
    - A document (step 13) from email: use the [phishing email playbook](../12-phishing-email/playbook.md).
    - A Run-dialog paste: use the [ClickFix investigation](../13-clickfix/investigation.md).
    - A download: `FileOriginUrl` and `FileOriginReferrerUrl` on the file's creation event. For a `certutil -decode` input file, check how that file arrived.
    - Another device (WMI, PsExec): that device is in scope; run this playbook for it.
    - Expect: the vector recorded. If none is found: record it as unknown.

---

## 5. Stop, block, remove

Only after step 10 is done (or recorded as failed), step 11 is done on every device in scope, and step 12 is done where BITS was involved. If you don't hold the rights for a step here, or it needs someone with administrator rights on the device, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

22. **Stop what is still running** (step 16) **and cancel the BITS jobs** (step 12).
    - Nothing from the chain running and no BITS job to cancel: go to step 23.
    - A payload not signed by Microsoft or a trusted non-Microsoft publisher (an EXE or DLL from steps 11 and 15, or a script if its file page offers the action): file page → Stop and Quarantine File. It stops its running processes, quarantines the file and deletes persistent data such as registry keys, on every device where it was seen in the last 30 days.
      - Expect: the Action center shows Success for each device.
      - If Failed: record the reason. If Pending: the device is offline; the action times out after three days.
      - If Defender warns that the file is widely used in the organization: cancel and escalate. It may be a business application.
      - A quarantined file can be restored if it turns out to be clean.
    - The LOLBin itself, or another file signed by Microsoft or a trusted publisher (for example `powershell.exe`, `certutil.exe`, `rundll32.exe`, `mshta.exe`): Stop and Quarantine File can't be used on it. Don't use Live Response `remediate` on the process either: on a process it stops the process and deletes the image file, which is the Windows binary. Escalate; the IR lead decides how to stop it. The device stays isolated meanwhile. The script, HTA or DLL it ran: Stop and Quarantine File as above if the file page offers it; otherwise it is removed in step 24.
    - A BITS job the customer can't name: ask the customer's IT contact to run `bitsadmin /cancel PASTE_JOB_ID_HERE` as an administrator on the device for each job, only once step 11 holds the job's files.
      - Expect: `bitsadmin /list /allusers` no longer shows the job.
      - If a job can't be cancelled: escalate (BITS jobs can't be listed or cancelled). The device stays isolated.

23. **Block the IOCs** with Defender for Endpoint indicators (Settings → Endpoints → Indicators). Block the SHA1 of each malicious non-Windows file from steps 11 and 15, and the external IPs, URLs and domains from steps 6 and 15.
    - Never add a block indicator for the hash of a LOLBin, another Windows binary or another legitimate signed tool. A file indicator stops the file being read, written or executed on every device in its scope. Block where it downloaded from instead.
    - File hashes: PE files only (`.exe`, `.dll`), and Defender Antivirus must be in active mode. A script, HTA or scriptlet can't be blocked by hash; block the URL it came from. Blocks typically apply within 15 minutes, 30 on average, and can take over 2 hours.
    - IPs and URLs: external IPs only, one address per indicator (no ranges). Outside Microsoft Edge, blocking needs Network Protection in block mode. An HTTPS full URL path can be blocked only in Edge; other browsers block by domain, and only with QUIC and Encrypted Client Hello disabled. Blocks can take up to 48 hours; most apply within 2 hours.
    - Don't block a domain the customer uses for business (for example a cloud storage or code-hosting site). Block the full URL (Edge only) or escalate.
    - Expect: each indicator listed with its expiry.
    - A blocked connection can still appear as `ConnectionSuccess` in network events. Check the alerts queue for the block, not the connection log.

24. **Remove persistence and remaining files** found in steps 15 and 17, using the [persistence playbook](../04-persistence-detected/playbook.md). A downloaded, decoded or dropped payload that Stop and Quarantine didn't cover: Live Response `remediate file` with its full path deletes it. Do this only once step 11 holds a copy.
    - Expect: each item removed and recorded.
    - Never point `remediate` at a Windows binary.
    - An lsass dump file: don't delete it yourself. Follow step 7 of the [credential compromise playbook](../06-credential-compromise/playbook.md); the IR lead decides when it is collected and removed.
    - If the persistence is a changed Windows value (for example under Winlogon) rather than a new entry: don't delete it. Escalate; the IR lead restores the original value.
    - Accounts the attacker created: disable them; delete only with the IR lead's agreement.

25. **Confirm every action in the Action center** (History tab): isolation, package, quarantine, Live Response actions. BITS cancellations are done on the device and won't appear there; record the customer's confirmation in the ticket.
    - Expect: every action Success.
    - If an action failed or an item from steps 15 and 17 has no action: do it from the device or file page, or with Live Response `remediate` (not on Windows binaries). Record each.
    - If it still fails: escalate. Don't release the device.

26. **Run a full antivirus scan** (device page → Run antivirus scan → Full). From 1 September 2026 Microsoft no longer runs automated investigation (AIR) as a separate experience for Defender for Endpoint alerts; for on-demand investigations it says to run a full antivirus scan.
    - Expect: the scan completes with no new detections.
    - If it finds anything: escalate, treat each detection as a new alert, and go back to step 13 for it.

---

## 6. Clean or reimage, then release

If you don't hold the rights to release the device, request it from the customer's IT contact once the IR lead or the criteria in step 28 allow it.

27. **Decide clean or reimage.** Reimage when an unknown or stealer payload ran, a credential dump ran, someone had hands-on access (for example a burst of discovery commands such as `whoami`, `net group` or `nltest` in the chain), or you can't account for every item the chain created. For High and above, the IR lead decides.
    - Reimaging destroys what is left on the disk. Do it only after steps 10, 11 and 12 are done or recorded as failed, and after the IR lead says no further collection (for example a disk image or the dump file) is needed.
    - Expect: the decision and who made it in the ticket.

28. **Release only when all of these hold:**
    - Steps 22 to 26 done, every action Success, and every BITS job from step 12 cancelled or named by the customer.
    - Credentials handled (step 18).
    - Indicators in place (step 23).
    - No new alerts and no connections to the IOCs while isolated, for the period the IR lead sets.
    - For High and above, the IR lead approves the release.
    - If isolation will auto-lift (step 9) before these hold: escalate before that date.
    - Then: device page → Release from isolation. Tell the customer the outcome.

---

## 7. Close out

- [ ] Classification set: True positive, Informational expected activity (authorised test, sanctioned tool), or False positive (only per Closing as a false positive)
- [ ] LOLBin technique documented with full command line, decoded command (step 6) and process chain (step 13)
- [ ] BITS job list (step 12) and what was cancelled, if BITS was involved
- [ ] IOCs documented (SHA1, IPs, domains, URLs) and which were blocked
- [ ] MITRE technique ID noted (mshta, regsvr32, rundll32: T1218.005 / .010 / .011 System Binary Proxy Execution; certutil: T1105 / T1140; wmic: T1047; bitsadmin: T1197; see [MITRE-mapping.md](../../../MITRE-mapping.md))
- [ ] Findings written up: how it started, what ran, what it did, persistence, spread, credentials, remediation, clean or reimage
- [ ] Escalated if any trigger below was hit

---

## Closing as a false positive

Close only with a named, verifiable benign cause, and record it. "Nothing else found", "this LOLBin is used here every day", "it's a Microsoft-signed binary", low volume, or "seen on many devices" is never enough; spread means scope wider. A signed parent isn't enough either: a remote management tool an attacker installed is signed by its vendor too. All of these must hold:

- The command line, decoded if it was encoded (step 6), is fully readable and does a named, documented thing: name the script, product or change record.
- The parent is the customer's own management agent or application: name the product, and confirm with the customer's asset list or a change record that this installation is theirs.
- No LOLBin fetched a file or script from an external host (step 7 list). A `certutil` `-urlcache`, `-verifyctl` or `-URL` with an external URL is never closed as a false positive.
- `certutil -decode` or `-decodehex`: both the input and the output path are in the named product's own folder, and the output is not an executable or a script.
- Any BITS job (step 12) is named by the customer and has no notify command the product doesn't document.
- Every non-Windows binary in the chain shows the vendor as `Signer`, with `IsTrusted` true, in `DeviceFileCertificateInfo` for its SHA1.
- Steps 13 to 15 found nothing else: no unexplained child processes, no connections to hosts the product doesn't document, and no unexplained files or registry changes.
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
Any hit in step 2 of the credential compromise playbook (step 18)
A LOLBin fetched a file or script from an external host (IP or domain name), and the caller is not the customer's confirmed management agent
Office app or WmiPrvSE.exe started PowerShell, cmd, mshta, a script host or another LOLBin, ASR didn't block it, and the caller is not the customer's confirmed management agent or application
Decoded command downloads or runs code from an external host, or loads an assembly from memory, and its parent is not the customer's confirmed management agent
Decoded command opens a connection to an external host (possible reverse shell)
Encoded content that can't be decoded to readable text
Windows binary name running from a folder other than its usual Windows folder, or a renamed copy of a Windows binary
BITS job with a notify command, or one the customer can't name
BITS jobs can't be listed or cancelled
Infostealer or unknown payload executed
C2 looks live (connections to an IOC from steps 6 or 15 still happening)
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
| Live Response (`processes`, `connections`, `getfile`, `run`, `remediate`) | Device page → Actions → Initiate Live Response session |
| Collect file | File page → Collect file |
| Stop and quarantine file | File page → Stop and Quarantine File |
| Add indicator | Settings → Endpoints → Indicators |
| Run AV scan | Device page → Actions → Run antivirus scan |
| Check actions | Defender XDR → Action center (History) |
| Release isolation | Device page → Actions → Release from isolation |
| List or cancel BITS jobs | On the device, as an administrator: `bitsadmin /list /allusers /verbose`, `bitsadmin /cancel PASTE_JOB_ID_HERE` (customer IT) |
