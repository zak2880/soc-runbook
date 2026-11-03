# Defence evasion — playbook

Work top to bottom. Each step is one action, what you should see, and what to do if you don't. Capture evidence before you restore, stop, quarantine, remove or delete anything. Queries and background are in the [investigation](investigation.md).

Two rules hold in every step. Never add a Defender exclusion, even to stop an alert repeating or to fix a false positive. Never turn protection back on yourself: record the state first; step 28 says who does it and when.

A query hit is an attempt, not proof that protection changed. An empty result is not a clean result. Step 4 reads the real state.

T0 = the first malicious event in the chain (the evasion event, or whatever ran before it), in UTC. It is not the alert time. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

---

## 1. Triage

1. **Record the incident:** severity, title, how many alerts are grouped. Run [All alerts for this device](../01-malware-alert/investigation.md#all-alerts-for-this-device).
   - Expect: alerts that all belong to this chain.
   - If other categories appear (credential access, lateral movement, C2): record them and treat this as a multi-stage incident. Check them against Escalate if before you continue.

2. **Record the device and the signal.** Device FQDN, OS version and role (workstation, server, domain controller); the user's SAM name and UPN; the alert title and detection status. For the process involved: name, full path, SHA1, full command line, PID, creation time and account; its parent's name and command line. Take them from the alert's process tree or the Device timeline.
   - Expect: all known.
   - If the PID or creation time is missing: identify the process in the Device timeline. Don't match on the process name alone; PIDs are reused.

3. **Set T0** from the Device timeline: the earliest event in the chain. Look before the evasion event; tampering usually follows something else that ran.
   - Expect: T0 at or before the alert time.
   - If you can't find it: use the process's creation time and mark T0 as an estimate.

4. **Record the protection state before anything changes** ([Check the real state first](investigation.md#check-the-real-state-first)). These are read-only. Put each reading and its time in the ticket: Sensor health state; the newest events in the Device timeline; the Device health status card (top message, Defender Antivirus mode); Effective settings (antivirus settings and every exclusion, with the source of each). Then Live Response `processes` (`MsMpEng.exe`, `MsSense.exe`) and `services` (`WinDefend`, `Sense`, `EventLog`). Use `Get-MpComputerStatus` and `Get-MpPreference` if your team has an approved library script.
   - Expect: sensor Active with events up to now; Defender in the mode the customer expects; `MsMpEng.exe` and `MsSense.exe` running; no exclusion you can't explain.
   - If Live Response or the script isn't available: record why, and ask the customer's IT contact for the output of `Get-MpComputerStatus` and `Get-MpPreference`. Don't wait for it; continue.
   - If the sensor is Inactive or Misconfigured, or the timeline stops while the device is on: escalate (sensor stopped reporting or lost health during the incident) and go to step 8. Active doesn't prove the sensor is working now: Microsoft marks a device Inactive only after more than seven days without signals.
   - A device that is simply switched off, or a timeline event showing the EDR client in Critical mode, is not this trigger. Confirm the first with the customer and record the gap.
   - Keep this record. Step 28 restores from it. Change nothing now.

5. **Check whether it was blocked** ([Was it blocked?](investigation.md#was-it-blocked)): the alert's detection status, then `TamperingAttempt` and ASR events for the device from T0.
   - Expect: Prevented or Blocked, an ASR event ending in `Blocked` if a rule was involved, and step 4 shows protection unchanged.
   - If Detected, or an ASR event ends in `Audited`, or step 4 shows protection changed: it took effect.
   - Blocked covers that one action. Earlier processes may have run, and step 6 still applies: something on the device tried it.

6. **Check for an immediate trigger.** Run the Defender, taskkill and event log queries with T0 ([Disabling security tools](investigation.md#disabling-security-tools), [Log and artefact clearing](investigation.md#log-and-artefact-clearing)). Read the alerts, step 4, and every command line in the process tree for:
   - Event logs cleared or deleted (`wevtutil cl`, `Clear-EventLog`, `Remove-EventLog`, Event Viewer, `.evtx` files deleted, or Security event 1102)
   - Audit policy or event logging turned off (`auditpol /clear`, `/remove` or `/set` with `disable`; `wevtutil sl` with `/e:false`; EventLog service stopped or disabled)
   - Defender or EDR tampered with or stopped: protection off or weakened with no change record, a tamper alert, a `TamperingAttempt` event, or a security service stopped or killed
   - Defender exclusion with no change record
   - Defender change from central policy with no change record (Group Policy, Intune, Configuration Manager)
   - Unknown or vulnerable driver written or loaded
   - Sensor stopped reporting or lost health during the incident
   - Firewall turned off, or a rule allowing inbound connections added, with no change record
   - AMSI bypass followed by any download, child process or persistence
   - Process injection: a Defender injection alert, or a legitimate process with an unexplained public connection
   - Expect: none.
   - If any: escalate now and go to step 8.
   - These hold even if the attempt was blocked.
   - No change record means the customer's contact can't name one now. No answer counts as no record. Don't wait for an answer before you contain.

7. **Decide the path.**
   - No trigger, and it looks like a named change or normal behaviour (a change record, a product the customer runs, `eventvwr.exe` starting `mmc.exe`): read the matching row in [Closing as a false positive](#closing-as-a-false-positive) and do the checks it names from steps 13 to 22, leaving out the parts that need the package or the logs from step 11. Close only if every condition holds; otherwise go to step 8.
   - Anything else, or you can't tell: go to step 8. Evasion means something already ran on the device. Prevented or Blocked doesn't change that.

---

## 2. Contain the device

If you don't hold the rights for a step here (isolation, investigation package, Live Response), or a step needs someone with administrator rights on the device, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

8. **Check the device type, network and sensor before isolating.**
   - Domain controller, other Tier 0 server, or Hyper-V host: don't isolate it yourself. Escalate now (device can't be isolated). Isolating a Hyper-V host blocks network traffic to every VM on it.
   - Production server: tell the customer contact you are isolating it, and record the time.
   - Full-tunnel VPN: Microsoft says the device can't reach the Defender service once isolated. Do step 10 first, then step 9.
   - Behind a web proxy (PAC, WPAD or static): use selective isolation. Microsoft warns such devices might not recover from full isolation.
   - Sensor unhealthy or tampered with (steps 4 and 6): don't rely on isolation alone. Microsoft doesn't say it works on a damaged sensor. Ask the customer's IT contact now to cut the device off at the switch, NAC, firewall or VPN, and record the time. Still do step 9.
   - Expect: an ordinary workstation or member server. Go to step 9.

9. **Isolate the device** (device page → Isolate device). Isolation disconnects the device from the network and keeps it connected to the Defender service.
   - Expect: the Action center shows the isolation as completed.
   - If not (pending or offline): Defender retries for up to three days. Escalate (device can't be isolated), report the device as not isolated, and ask for the network cut-off from step 8.
   - Microsoft states isolation is lifted automatically after seven days (VERIFY (tenant)). Put the date in the ticket and re-check it.

10. **Collect the investigation package** (device page → Collect investigation package). It records autoruns, running processes, network connections, prefetch, scheduled tasks, services and the Security event log. It holds no process memory.
    - Expect: the package is downloadable from the Action center.
    - If not: collection can fail on low battery or a metered connection, and a damaged sensor may not complete it. Retry once, then record the failure and continue.
    - Don't restart the device, run an antivirus scan, Stop and Quarantine File, Live Response `remediate`, or ask anyone to restore a setting until this step is done or recorded as failed. Those actions remove or change what the package would have recorded.

11. **Preserve the logs the package doesn't hold.** Live Response `getfile` with the full path in quotes, from `C:\Windows\System32\winevt\Logs\`: `System.evtx`, `Microsoft-Windows-Windows Defender%4Operational.evtx` and `Microsoft-Windows-PowerShell%4Operational.evtx`.
    - Expect: each file downloaded and listed in the ticket.
    - VERIFY (tenant) that `getfile` can read a log file the Event Log service has open. If it fails: ask the customer's IT contact to export the log as an administrator, for example `wevtutil epl System PASTE_FILE_PATH_HERE`, and send it to you.
    - Whoever signs in to the device exposes their credentials to it. They must not use a domain admin or other privileged domain account. If a credential dump ran, the IR lead decides how this is done.
    - If a log is empty or missing: record that. The IR lead decides on disk collection.

12. **Preserve the payload:** every file the chain dropped or ran that is not a Windows binary. For example tools, scripts, loaders, INF files and `.sys` drivers. On the file page, select Collect file if it is shown; Download file instead means Defender already holds a copy. If the file page offers neither, use Live Response `getfile` with the full path.
    - Expect: each file held by Defender or downloaded, with its path and SHA1 in the ticket.
    - If Collect file is disabled: the file hasn't been seen in the past 30 days, or you lack the permission. Record which, and try `getfile`.
    - If a file can't be preserved: record why, and escalate (a target file can't be preserved before removal). Don't remove it until the IR lead agrees.
    - If a script ran only in memory: record the command line and the decoded content.
    - If injection is suspected, or an attacker's process is still running: ask the IR lead now whether to capture memory. Stopping the process or restarting the device loses it.
    - Don't download an lsass dump file; follow step 7 of the [credential compromise playbook](../06-credential-compromise/playbook.md). Don't open or run any payload on your own workstation.

---

## 3. Investigate

If you don't hold the Live Response role, request it from the customer's IT contact, record the time of the request, and use the package meanwhile. Do steps 13 to 21 even after one finds something: attackers combine these techniques.

13. **Work out what changed in Defender** ([Defender settings and exclusions](investigation.md#defender-settings-and-exclusions)): the `defence-evasion-defender-disabled` query, a Device timeline search for `MpPreference`, Effective settings, and events 5001, 5007, 5010, 5012 and 5013 in the Defender log from step 11. Record each change: setting or exclusion, old and new value, time, account, initiating process and command line, and the source (a command on the device, or a policy).
    - Expect: no change, or a change that a named change record covers.
    - The query can miss `-ExclusionPath` and `-DisableRealtimeMonitoring`. An empty result isn't the answer; use the timeline search.
    - If an exclusion has no change record: escalate (Defender exclusion with no change record). A setting with none: escalate (Defender or EDR tampered with or stopped).
    - If the source is Group Policy, Intune or Configuration Manager and there is no change record: escalate (Defender change from central policy with no change record). The management system itself may be compromised.
    - If the timeline shows troubleshooting mode (`AntivirusTroubleshootModeEvent`) and the customer can't name who started it: escalate (Defender or EDR tampered with or stopped).
    - Change nothing yet; that is step 28.

14. **Check whether a security tool was stopped or a driver used** ([Security tools stopped or killed](investigation.md#security-tools-stopped-or-killed), [Vulnerable drivers](investigation.md#vulnerable-drivers)): the taskkill query; a Device timeline search for `sc.exe`, `net stop`, `Stop-Process` and `Set-Service` against `WinDefend`, `Sense` or the customer's other security products; `.sys` files written outside `C:\Windows\`; `AsrVulnerableSignedDriver` events.
    - Expect: nothing aimed at a security tool, no ASR driver event, and no `.sys` file outside `C:\Windows\` that a named product doesn't explain.
    - If a tool was stopped or attacked: compare with step 4 to record whether it took effect. Escalate (Defender or EDR tampered with or stopped).
    - If a driver was written or loaded and isn't one the customer can name: escalate (unknown or vulnerable driver written or loaded). Preserve it (step 12). Treat the device's telemetry after that time as unreliable.
    - Save Live Response `drivers` output in the ticket for the IR lead. It lists every driver on the device, so it isn't a check you can finish alone.

15. **Check for an AMSI bypass** ([AMSI bypass](investigation.md#amsi-bypass)): Defender alerts first, then the AMSI query. Decode anything encoded on your analysis machine ([Decode before you judge](../02-suspicious-process/investigation.md#decode-before-you-judge)). Never run the result.
    - Expect: nothing. `-ExecutionPolicy Bypass` on its own isn't an AMSI bypass.
    - If you find a bypass: check what that process did next, in step 22. Any download, child process or persistence: escalate (AMSI bypass followed by any download, child process or persistence).
    - If the encoded content can't be decoded to readable text: escalate (encoded content that can't be decoded to readable text).

16. **Check for a UAC bypass** ([UAC bypass](investigation.md#uac-bypass)): the UAC query, then the registry check.
    - Expect: no hijack key, and no child process other than `mmc.exe` from `eventvwr.exe`.
    - If you find a hijack key or an elevated child: record the user, key, value, data, child process, and what started the binary. Step 31 removes the key; leave it for now.
    - `cmstp.exe`: add the INF file to step 12.

17. **Check for log clearing and logging turned off** ([Log and artefact clearing](investigation.md#log-and-artefact-clearing)): the `event-log-clearing` query; Security event 1102 in the package; `.evtx` deletions; a Device timeline search for `auditpol`, `wevtutil sl`, `Remove-EventLog` and `EventLog`.
    - Expect: none.
    - If logs were cleared or deleted: escalate (event logs cleared or deleted). If logging was turned off: escalate (audit policy or event logging turned off).
    - Record the account, the time and which logs. Treat those logs as incomplete from then on. Change nothing yet; that is step 28.

18. **Check the host firewall** ([Firewall changes](investigation.md#firewall-changes)): a Device timeline search for `netsh advfirewall`, `Set-NetFirewallProfile` and `New-NetFirewallRule`.
    - Expect: no change, or one a named change record covers.
    - If it was turned off, or an inbound rule was added, with no change record: escalate (firewall turned off, or a rule allowing inbound connections added, with no change record). Record the rule, port, program and remote scope. Change nothing yet; that is step 28.

19. **Check for process injection** ([Process injection](investigation.md#process-injection)): Defender alerts, the injection query, and the Device timeline of any process that connected without a reason.
    - Expect: nothing.
    - If there is an injection alert, or a legitimate process has an unexplained public connection: escalate (process injection). Ask the IR lead about memory (step 12).
    - Never stop an injected process yourself; step 29 explains why.
    - Injection into `lsass.exe`: also treat it as a step 25 hit.

20. **Check for hidden data** ([Alternate data streams](investigation.md#alternate-data-streams), [Timestomping](investigation.md#timestomping)). Search `ProcessCommandLine` for a stream after a file name, as the investigation shows.
    - Expect: none, apart from `Zone.Identifier` and addresses with a port.
    - If you find a stream: add its file to step 12 and record the stream name. Microsoft doesn't say whether Collect file keeps the stream.
    - Timestomping can't be checked in Advanced Hunting. Write "not checked" in the ticket, and tell the IR lead if file dates matter to the timeline.

21. **Record any telemetry gap** ([Telemetry gaps and ETW tampering](investigation.md#telemetry-gaps-and-etw-tampering)): compare the device's events before and after each evasion event.
    - Expect: no gap, or one with a benign cause you can name (switched off, offline, EDR client in Critical mode).
    - If there is a gap with no benign cause: record its start and end, and escalate (sensor stopped reporting or lost health during the incident).

22. **Trace the whole chain:** what ran before the evasion and what ran after it ([process guide](../02-suspicious-process/investigation.md)). For each process: path, SHA1, command line, parent, network connections, files written and registry changes.
    - Expect: every process recorded, with a parent that explains it.
    - Record every external IP, domain and URL, and every file path and SHA1. Steps 26, 30 and 31 use them.
    - A connection that network protection blocked can still show as `ConnectionSuccess`. Check the alerts queue for the block.
    - Record whether the evasion came before the payload ran (preparing the ground) or after it (covering tracks).
    - If you see a burst of discovery commands (`whoami`, `net group`, `nltest`) or interactive timing: record it as hands-on access for step 34.
    - If the chain wrote or ran an unknown EXE or DLL, or one with a stealer detection: escalate (infostealer or unknown payload executed), and run steps 11 and 17 of the [malware alert playbook](../01-malware-alert/playbook.md) for that file.

23. **Check whether anything is still running or connecting.** Use the package's Processes and Network connections folders, then Live Response `processes` and `connections` for the current state.
    - Expect: nothing from the chain running; no connections to the IPs or domains from step 22.
    - If C2 looks live (connections to an IOC from step 22 still happening): escalate now.
    - Record what is still running and its PID; step 29 needs it.

24. **Check persistence** with the [persistence playbook](../04-persistence-detected/playbook.md): run keys, scheduled tasks, services, startup folders and WMI. Compare with the package's Autoruns, Scheduled tasks and Services.
    - Expect: nothing the attacker added.
    - If found: record each item. Don't remove anything yet; that is step 31.

25. **Check identity:** lsass access, credential-tool keywords, new accounts and lateral movement. Use step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md).
    - Expect: no hits.
    - If any hit: escalate (any hit in step 2 of the credential compromise playbook), and follow the 06 playbook from step 2 for this device. Every account with a session on the device is exposed (06 step 8).

---

## 4. Scope

26. **Search the estate** ([Scope across the estate](investigation.md#scope-across-the-estate)): the queries with the same T0, read past your device; the hash sweep with each non-Windows SHA1 from steps 12 and 22; then the domains and IPs from step 22.
    - Never run a hash sweep on a Windows binary: it is on every device.
    - Expect: only this device.
    - If other devices: escalate (same evasion technique or file on more than one device). Run steps 2 to 25 for each. If a policy set the value (step 13), every device under that policy is in scope.
    - Zero rows doesn't prove no spread.

27. **Find how it started.** Ask the user, through the customer contact, what they were doing at T0, then check the delivery:
    - A document or link from email: use the [phishing email playbook](../12-phishing-email/playbook.md).
    - A Run-dialog paste: use the [ClickFix investigation](../13-clickfix/investigation.md).
    - A download: `FileOriginUrl` and `FileOriginReferrerUrl` on the file's creation event.
    - Another device (remote execution): that device is in scope; run this playbook for it.
    - Expect: the vector recorded. If none is found: record it as unknown.

---

## 5. Stop, block, remove

Only after steps 10, 11 and 12 are done (or recorded as failed) on every device in scope, and steps 13 to 25 have recorded what changed. If you don't hold the rights for a step here, or it needs someone with administrator rights on the device, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

28. **Request that protection is restored.** You don't do this yourself. Send the customer's endpoint or security admin the records from steps 4, 13, 17 and 18. Ask them to put back each setting, remove each exclusion with no change record, turn tamper protection on, and undo the audit policy, event logging and firewall changes. Record the time of the request.
    - Why before step 29: Stop and Quarantine File needs Defender Antivirus at least in passive mode, file and network indicators need active mode, and a scan needs it running. An exclusion left in place overrides a block file indicator ([What Defender can't do while it is off](investigation.md#what-defender-cant-do-while-it-is-off)).
    - Why not sooner: once protection is back, Defender can act on files. Anything not yet collected may be gone. Do it with the device isolated (step 9). If it isn't isolated, the IR lead decides when.
    - If a changed legitimate entry recorded in step 24 points to a file: tell the IR lead before protection is restored. Defender may act on that file.
    - Who holds the right, by the source you recorded:
      - Group Policy: the customer's Group Policy admin. Audit policy and firewall settings set by policy are the same.
      - Intune or Defender security settings management: an Intune admin with Endpoint Security Manager rights or equivalent.
      - A command on the device, no policy: a local administrator on the device.
      - Tamper protection: the Intune policy; or the Defender portal's Advanced features toggle, which needs Core security settings (manage), held by Security Administrator or Security Operator. That toggle covers the whole organization, so it is the customer's decision. The Windows Security app works only on a device no security team manages.
      - A non-Microsoft security product: the admin of that product's console.
    - Fix it at the source. If a policy set the value and the policy stays as it is, the change comes back.
    - An isolated device may not receive policy from Intune or a domain controller (VERIFY (tenant)). Then it needs someone at the device or an approved Live Response library script. Whoever signs in must not use a domain admin or other privileged domain account. If a credential dump ran, the IR lead decides how.
    - Don't start troubleshooting mode yourself. It lets local administrators change protected settings for up to four hours. Only the IR lead decides to use it.
    - Expect: repeat step 4. Every reading matches the customer's expected state. Record who made each change and when. If tamper protection was never on at this customer, record that and recommend it.
    - If a value won't stay, or comes back changed: escalate (protection can't be restored, or it is turned off again). Something is still changing it. Keep the device isolated.
    - If protection can't be restored at all (for example a damaged sensor): escalate (protection can't be restored, or it is turned off again). Steps 29, 30 and 33 may not work. The IR lead decides; go to step 34.

29. **Stop what is still running** (step 23).
    - Nothing from the chain running: go to step 30.
    - If a changed legitimate entry recorded in step 24 (for example Winlogon `Userinit`, or an existing service's `ImagePath`) points to the file: don't run Stop and Quarantine File yourself. Microsoft doesn't say which registry data it deletes. Ask the IR lead first.
    - A payload not signed by Microsoft or a trusted non-Microsoft publisher: file page → Stop and Quarantine File. It stops its running processes, quarantines the file and deletes persistent data such as registry keys, on every device where it was seen in the last 30 days.
      - Expect: the Action center shows Success for each device.
      - If Failed: record the reason. If Pending: the device is offline; the action times out after three days.
      - If Defender warns that the file is widely used in the organization: cancel and escalate (Stop and Quarantine File can't be used, or Defender warns the file is widely used). It may be a business application.
      - A quarantined file can be restored if it turns out to be clean.
    - An injected process, a Windows binary, or another file signed by Microsoft or a trusted publisher: Stop and Quarantine File can't be used on it. Don't use Live Response `remediate` on the process either: on a process it stops the process and deletes the image file. Escalate (Stop and Quarantine File can't be used); the IR lead decides how to stop it. The device stays isolated meanwhile.

30. **Block the IOCs** with Defender for Endpoint indicators (Settings → Endpoints → Indicators): the SHA1 of each malicious non-Windows file from steps 12 and 22, and the external IPs, URLs and domains from step 22.
    - Do this after step 28. A file under an antivirus exclusion stays allowed despite a block indicator, and a process exclusion stops network protection for that process.
    - Never add a block indicator for the hash of a Windows binary or another legitimate signed tool. A file indicator stops the file being read, written or executed on every device in its scope. A vulnerable driver is legitimately signed: ask the IR lead first.
    - File hashes: PE files only (`.exe`, `.dll`), and Defender Antivirus must be in active mode. A script can't be blocked by hash; block its delivery URL. Blocks typically apply within 15 minutes, 30 on average, and can take over 2 hours.
    - IPs and URLs: external IPs only, one address per indicator (no ranges). Outside Microsoft Edge, blocking needs Defender Antivirus in active mode and Network Protection in block mode. An HTTPS full URL path can be blocked only in Edge; other browsers block by domain, and only with QUIC and Encrypted Client Hello disabled. Blocks can take up to 48 hours; most apply within 2 hours.
    - Don't block a domain the customer uses for business. Block the full URL (Edge only) or escalate (a domain to block is one the customer uses for business).
    - Expect: each indicator listed with its expiry. A blocked connection can still appear as `ConnectionSuccess` in network events; check the alerts queue for the block.

31. **Remove persistence and remaining files** found in steps 16, 22 and 24, using the [persistence playbook](../04-persistence-detected/playbook.md). A tool or script Stop and Quarantine didn't cover: Live Response `remediate file` with its full path deletes it. Do this only once step 12 holds a copy.
    - Expect: each item removed and recorded.
    - UAC hijack key (step 16): it sits in the user's hive, so the per-user rule in step 19 of the persistence playbook applies. Request removal of what step 16 recorded from the customer's IT contact.
    - Never point `remediate` at a Windows binary.
    - A driver file: don't delete it yourself. The IR lead decides.
    - An lsass dump file: don't delete it yourself. Follow step 7 of the [credential compromise playbook](../06-credential-compromise/playbook.md).
    - If the persistence is a changed legitimate entry, not a new one (for example Winlogon `Userinit`, `Shell` or `Notify`, or an existing service's `ImagePath`): don't delete the value or the key. Escalate; the IR lead restores the original data.
    - Accounts the attacker created: disable them; delete only with the IR lead's agreement.

32. **Confirm every action in the Action center** (History tab): isolation, package, quarantine, Live Response actions. Changes the customer's admin made in step 28 won't appear there; record their confirmation in the ticket.
    - Expect: every action Success.
    - If an action failed or an item from steps 16, 22 and 24 has no action: do it from the device or file page, or with Live Response `remediate` (not on Windows binaries). Record each.
    - If it still fails: escalate (remediation failed and can't be completed). Don't release the device.

33. **Run a full antivirus scan** (device page → Run antivirus scan → Full). It needs Defender Antivirus active or passive, and it doesn't look inside an exclusion, so step 28 comes first. From 1 September 2026 Microsoft no longer runs automated investigation (AIR) as a separate experience for Defender for Endpoint alerts; for on-demand investigations it says to run a full antivirus scan.
    - Expect: the scan completes with no new detections.
    - If it finds anything: escalate (full antivirus scan after removal finds new detections), treat each detection as a new alert, and go back to step 22 for it.

---

## 6. Clean or reimage, then release

If you don't hold the rights to release the device, request it from the customer's IT contact once the IR lead or the criteria in step 35 allow it.

34. **Decide clean or reimage.** Reimage is the default when protection really was off or weakened (step 5), a driver was used, logs were cleared or logging turned off, injection was found, an unknown or stealer payload ran, someone had hands-on access, or you can't account for every item the chain created. The device's own telemetry for that period can't be trusted. Clean only when the attempt was blocked, step 4 shows protection never changed, the payload is identified and every item it created is removed. For High and above, the IR lead decides.
    - Reimaging destroys what is left on the disk. Do it only after steps 10, 11 and 12 are done or recorded as failed, and after the IR lead says no further collection (for example memory or a disk image) is needed.
    - Expect: the decision and who made it in the ticket.

35. **Release only when all of these hold:**
    - Step 28 holds: a repeat of step 4 shows protection still on and matching the customer's expected state.
    - Steps 29 to 33 done, every action Success.
    - Credentials handled (step 25).
    - Indicators in place (step 30).
    - No new alerts and no connections to the IOCs while isolated, for the period the IR lead sets.
    - For High and above, the IR lead approves the release.
    - If isolation will auto-lift (step 9) before these hold: escalate (isolation will auto-lift before the release criteria hold) before that date.
    - Then: device page → Release from isolation. Tell the customer the outcome, and ask them to lift any network cut-off from step 8.

---

## 7. Close out

- [ ] Classification set: True positive, Informational expected activity (authorised test, sanctioned tool), or False positive (only per Closing as a false positive)
- [ ] Protection state before and after: step 4, the repeat in step 28, who restored what and when
- [ ] Each evasion technique documented: attempted or took effect, time, account, process, and whether it came before or after the payload ran
- [ ] Telemetry gaps noted with start and end times (step 21), logs cleared or incomplete (step 17), and "not checked" items (step 20)
- [ ] IOCs documented (SHA1, IPs, domains, URLs) and which were blocked
- [ ] MITRE technique IDs noted (tools, Defender and AMSI: T1685; audit policy and event logging: T1685.001; log clearing: T1685.005; host firewall: T1686.003; UAC bypass: T1548.002; injection: T1055; alternate data streams: T1564.004; timestomp: T1070.006; CMSTP: T1218.003; see [MITRE-mapping.md](../../../MITRE-mapping.md))
- [ ] Findings written up: how it started, what ran, what was tampered with, persistence, spread, credentials, remediation, clean or reimage
- [ ] Escalated if any trigger below was hit

---

## Closing as a false positive

Close only with a named, verifiable benign cause, and record it. "Nothing else found", "it was blocked", "an admin account did it", low volume, or "seen on many devices" is never enough; spread means scope wider. A signature or a `Program Files` path isn't enough either: a remote-access tool an attacker installed is signed by its vendor too.

Never add a Defender exclusion to close this, or to stop an alert repeating. Microsoft says an exclusion creates a protection gap. If legitimate activity keeps alerting, tell the customer's security contact; tuning is their decision.

Never close these yourself, even if a test or an admin is mentioned: any item in Escalate if below. Escalate; the IR lead decides. The items that say "with no change record" stop applying only when the matching row here is met in full.

| Signal | Close only if all of these hold |
|--------|---------------------------------|
| Defender setting changed, or exclusion added | A change record names this device, the exact setting or path, the account and the time, and the customer confirms it. The account is that admin, and the initiating process is their management tool or console. An exclusion doesn't cover a whole drive, a user-writable folder or a common extension, and nothing from the process chain sits inside it. A temporary change has been reversed as the record says (step 4). Steps 13 and 22 found nothing else |
| Troubleshooting mode | The Device timeline shows it starting and ending. A named customer admin confirms they started it, for a ticket they can quote. Settings returned to their previous values when it ended (step 4). Steps 13 and 22 found nothing else in that window |
| Defender in passive mode, or disabled | The asset list names a non-Microsoft antivirus as this device's primary product. The customer confirms the mode predates T0. Steps 13 and 14 found no command, tamper event or stopped service. The sensor is healthy |
| Firewall rule added | A change record names this device and rule. The rule is for a named product's file, and `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` with `IsTrusted` true. The creating process is that product's installer or the customer's management agent, and the customer confirms the job. Inbound scope is limited to what the product documents |
| `eventvwr.exe` started `mmc.exe` | No hijack key in step 16. No other child process from `eventvwr.exe`. A user or admin launching Event Viewer explains it |
| AMSI query hit on `Bypass` only | The only match is `-ExecutionPolicy Bypass`. The script is named and documented by the customer (a change record or asset list). Its full command line, decoded if encoded, does what the document says. No AMSI string or alert. Steps 15 and 22 found nothing else |
| Legitimate process with a public connection | The vendor documents that feature, the destination belongs to that vendor, and the customer's asset list shows the product. No injection alert. Steps 19 and 22 found nothing else in that process |

A sanctioned change, tool or authorised test that was detected correctly: classify as Informational, expected activity, not False positive.

If any condition can't be confirmed: don't close. Escalate.

---

## Escalate if

See also [escalation triggers](../../reference/escalation-triggers.md).

```
Event logs cleared or deleted (wevtutil cl, Clear-EventLog, Remove-EventLog, Event Viewer, .evtx files deleted, or Security event 1102)
Audit policy or event logging turned off (auditpol /clear, /remove or /set with disable; wevtutil sl with /e:false; EventLog service stopped or disabled)
Defender or EDR tampered with or stopped: protection off or weakened with no change record, a tamper alert, a TamperingAttempt event, or a security service stopped or killed
Defender exclusion with no change record
Defender change from central policy with no change record (Group Policy, Intune, Configuration Manager)
Unknown or vulnerable driver written or loaded
Sensor stopped reporting or lost health during the incident
Firewall turned off, or a rule allowing inbound connections added, with no change record
AMSI bypass followed by any download, child process or persistence
Process injection: a Defender injection alert, or a legitimate process with an unexplained public connection
Encoded content that can't be decoded to readable text
Infostealer or unknown payload executed
C2 looks live (connections to an IOC from step 22 still happening)
Any hit in step 2 of the credential compromise playbook
Same evasion technique or file on more than one device
Device can't be isolated (pending, offline, domain controller, other Tier 0 server, Hyper-V host)
A target file can't be preserved before removal
Protection can't be restored, or it is turned off again
Stop and Quarantine File can't be used, or Defender warns the file is widely used
A domain to block is one the customer uses for business
Persistence is a changed legitimate entry, not a new one (for example Winlogon Userinit, Shell or Notify, or an existing service's ImagePath)
Remediation failed and can't be completed
Full antivirus scan after removal finds new detections
Isolation will auto-lift before the release criteria hold
```

---

## Actions — Defender XDR quick reference

| Action | Where |
|--------|-------|
| Read the protection state | Device page: Sensor health state, Device health status card, Configuration management → Effective settings |
| Isolate device | Device page → Actions → Isolate device |
| Collect investigation package | Device page → Actions → Collect investigation package |
| Live Response (`processes`, `services`, `drivers`, `connections`, `registry`, `getfile`, `run`, `remediate`) | Device page → Actions → Initiate Live Response session |
| Collect file | File page → Collect file |
| Stop and quarantine file | File page → Stop and Quarantine File |
| Add indicator | Settings → Endpoints → Indicators |
| Run AV scan | Device page → Actions → Run antivirus scan |
| Check actions | Defender XDR → Action center (History) |
| Release isolation | Device page → Actions → Release from isolation |
| Restore settings, remove exclusions | The customer's endpoint or security admin (step 28). Never you, and never add an exclusion |
