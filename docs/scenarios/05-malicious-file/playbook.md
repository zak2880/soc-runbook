# Malicious file — playbook

Work top to bottom. Each step is one action, what you should see, and what to do if you don't. Capture evidence before you quarantine, remove or delete anything. Queries, and how to read them, are in the [investigation](investigation.md).

Use this playbook when the starting point is a file: a file-based alert, a hunting hit (executables in suspicious paths, mass renames, shadow-copy deletion) or a file a user reported. For a Defender Antivirus malware detection, use the [malware alert playbook](../01-malware-alert/playbook.md); it uses the file checks in the investigation.

T0 = first malicious event (the file's delivery, creation or first run), in UTC. It is not the alert time. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

---

## 1. Triage

If you came back here after containing the device (step 11 done), read each "go to step 7" below as "continue from step 12".

1. **Check for ransomware first.** Run the VSS deletion query (it runs estate-wide) and the mass file renames query for this device ([Ransomware signals](investigation.md#ransomware-signals)). If you don't have T0 yet, use the alert time. If the alert is more than 4 hours old, run the renames query again with T0 set to one hour ago.
   - Expect: no hits.
   - If shadow copies or the backup catalog were deleted, `bcdedit` turned off recovery, mass file renames, or ransom-note files created in many folders: escalate now (consider P1) and go to step 7. Don't finish triage first. After step 11, come back to step 2. Until you have a file, the file for steps 2 to 11 is the process doing the renames or deletions (`InitiatingProcessFileName`).
   - If the renames are on a file server and `RequestProtocol` is `SMB` (read it on one renamed file's event; the query doesn't show it): the device at `RequestSourceIP` is doing the encryption. Escalate, and contain that device (step 7). Don't isolate the file server yourself.
   - A `vssadmin` or `bcdedit` hit can be read-only (for example `vssadmin list shadows`): read the command line. A deletion that looks like backup software still goes to the IR lead; don't close it yourself.
   - No hits doesn't prove shadow copies are intact; some methods leave no command line.

2. **Record the device FQDN and OS, the logged-on user's SAM name and UPN, the alert name, the file name and full path, its SHA1, and the process that wrote it with its command line.** SHA256 is usually empty; take SHA1 from the file page.
   - Expect: all known.
   - If no SHA1: hashes are empty when the file is on remote storage, locked or compressed. Use the Device timeline, the file name and the path for the checks that need the hash.

3. **Set T0** from the Device timeline: the earliest of the file's delivery, its creation and its first run.
   - Expect: T0 at or before the alert time.
   - If you can't find it: use the file's creation time and mark T0 as an estimate. If it is earlier than the time you used in step 1, rerun step 1 with it.

4. **Check the alert's detection status** (alert page).
   - Expect: Prevented (the file wasn't written or run) or Blocked (it ran and was then stopped).
   - If Detected: the attack is possibly still active. Go to step 7 now. After step 11, come back to step 5.
   - If there is no alert (a hunting hit or a user report): nothing has stopped the file. Continue with step 5.

5. **Check whether the file ran** ([Did it run?](investigation.md#did-it-run)). Run the hash sweep and read `Tables` for this device, and check the execution status on the file page's Observed in organization tab.
   - Expect: only `DeviceFileEvents`, and no execution on the file page.
   - If `DeviceProcessEvents` or `DeviceImageLoadEvents`, or the file page shows it ran: it ran. Go to step 7.
   - If the hash is empty, or the file is a script, shortcut or document: check the Device timeline from T0 for a process whose command line contains the file name. Anything found = it ran. Go to step 7.

6. **Decide the path.** Read the file's creation event ([How did it arrive?](investigation.md#how-did-it-arrive)).
   - If `RequestProtocol` is `SMB` and `RequestSourceIP` is an internal device: the file arrived over SMB from another internal device. Escalate and go to step 7.
   - If it is a remote-access, remote-management or file-transfer tool: do step 14 now. Then go to step 7 unless the customer confirmed it.
   - If a script host, LOLBin or unknown binary wrote it: go to step 7.
   - Nothing ran, and a normal application (browser, mail client, archive tool) wrote it: containment isn't needed yet. Do steps 10 to 15, then steps 19 and 20, then steps 21 to 25 if the file is malicious. Close only per Closing or Closing as a false positive below; if anything else turns up, come back to step 7.
   - Anything else, or you can't tell: go to step 7.

---

## 2. Contain the device

If you don't hold the rights for a step here (isolation, investigation package, Collect file, Live Response), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do. For ransomware, say it is urgent and escalate at the same time.

7. **Check the device type and network before isolating.**
   - Domain controller, other Tier 0 server, or Hyper-V host: don't isolate it yourself. Escalate now. Isolating a Hyper-V host blocks network traffic to every VM on it.
   - File server whose files are being renamed over SMB (step 1): isolate the device at `RequestSourceIP`, not the server. Escalate.
   - Production server: tell the customer contact you are isolating it, and record the time.
   - Full-tunnel VPN: Microsoft says the device can't reach the Defender service once isolated. Do step 9 first, then step 8.
   - Behind a web proxy (PAC, WPAD or static): use selective isolation. Microsoft warns such devices might not recover from full isolation.
   - Expect: an ordinary workstation or member server. Go to step 8.

8. **Isolate the device** (device page → Isolate device). Isolation keeps the device connected to the Defender service.
   - Expect: the Action center shows the isolation as completed.
   - If not (pending or offline): Defender retries for up to three days. Escalate and report the device as not isolated.
   - Microsoft states isolation is lifted automatically after seven days (VERIFY (tenant)). Put the date in the ticket and re-check it.

9. **Collect the investigation package** (device page → Collect investigation package). It records autoruns, running processes, network connections, DNS cache, prefetch, scheduled tasks, services and the Security event log.
   - Expect: the package is downloadable from the Action center.
   - If not: collection can fail on low battery or a metered connection. Retry once, then record the failure and continue.
   - Don't run an antivirus scan, Stop and Quarantine File, or Live Response `remediate` until this step is done or recorded as failed. Those actions remove files, processes and registry entries the package would have recorded.

10. **Check whether the file is still on disk** ([Is it still on disk?](investigation.md#is-it-still-on-disk)). Live Response `fileinfo` with the full path; if it isn't there, `findfile` with the file name.
    - Expect: the file at the recorded path.
    - If it is at another path: record the new path and its SHA1, and use them from here on.
    - If it isn't on the device: check the Action center (History). Defender removed it = record that. No Defender action, and the Device timeline shows it was deleted after it ran ([Self-deleting droppers](investigation.md#self-deleting-droppers)) = the file deleted itself after running. Escalate.

11. **Preserve the sample.** On the file page, select Collect file if it is shown. If Download file is shown instead, Defender already holds a copy. If the file page offers neither and the file is still on disk (step 10), use Live Response `getfile` with the full path (3 GB limit).
    - Expect: the sample held by Defender or downloaded, with its path and SHA1 in the ticket.
    - If Collect file is disabled: the file hasn't been seen in the past 30 days, or you lack the permission. For a script or document, Collect file and Download file need Security Administrator or advanced Live Response rights (or the file collection permission in unified RBAC). Record which, and try `getfile`.
    - Don't open or run the file on your own workstation. A document may hold customer data; handle it as confidential.
    - Do the same for every file you find in step 15 before step 23 removes it.

---

## 3. Investigate

12. **Enrich the hash on the file page** ([Hash enrichment](investigation.md#hash-enrichment)): Defender Antivirus detection, VirusTotal ratio, devices in the organization (last 30 days), prevalence outside the organization.
    - Expect: the values recorded in the ticket.
    - The device count follows your access scope. If you can't see every device group, record that the count may be low.
    - To check VirusTotal directly, search the SHA1 only. Never upload the file: VirusTotal may share submitted files with its premium customers. Upload only with the IR lead's approval.
    - 0 detections or no VirusTotal report is not evidence that the file is benign.
    - If the detection or VirusTotal names a known credential dumper (for example Mimikatz): escalate, and do step 18 whether or not it ran.

13. **Get the file's behaviour.** PE file (`.exe`, `.dll`) that Defender holds (step 11): file page → Deep analysis → Submit. The report lists behaviours and observables, including contacted IPs and files created on disk. It takes several minutes.
    - Expect: behaviours, IPs, domains and dropped files recorded for steps 15 and 22.
    - If Submit isn't available: the sample isn't in Defender's sample collection yet; Microsoft notes up to 10 minutes' latency between a file's submission and Deep analysis being available. Try again after that, then record it and continue.
    - Script, shortcut or document: Deep analysis doesn't support it. Read its content only on an analysis machine your team approves, or ask the IR lead. Don't submit it to a public sandbox.

14. **Check whether it is a legitimate tool.** Look up its SHA1 in `DeviceFileCertificateInfo` (`Signer`, `IsTrusted`). Version information (company name) is not a signature.
    - Expect: the signer and `IsTrusted` recorded, or the file recorded as unsigned.
    - If it is a remote-access, remote-management or file-transfer tool (for example AnyDesk, ScreenConnect, rclone): ask the customer for the change record or approved-software entry. None = a remote-access or admin tool installed with no change record or approved-software entry. Escalate, and contain (step 7) if not done.
    - Signed, widely seen and 0 VirusTotal detections doesn't change this. An attacker-installed remote-access tool passes all three.

15. **Trace who wrote it and what it did** in the alert's process tree and the Device timeline from T0 ([process guide](../02-suspicious-process/investigation.md)). Record the writer's chain, every file the file wrote (Device timeline, Deep analysis observables, File content tab), its network connections, and any disguised name ([Double extensions and disguised names](investigation.md#double-extensions-and-disguised-names)).
    - Expect: a normal application wrote it and nothing ran from it.
    - If a script host, LOLBin or unknown binary wrote it, or it started other processes: they are in scope. Record each one and its SHA1, and preserve each file (step 11). A quarantined file is no evidence that its writer was stopped.
    - If it is an unknown payload or has a stealer detection (`PWS`, `TrojanSpy`) and it ran: infostealer or unknown payload executed. Escalate, and run steps 11 and 17 of the [malware alert playbook](../01-malware-alert/playbook.md) for it.

16. **Check whether anything is still running or connecting.** Use the package's Processes and Network connections folders, then Live Response `processes` and `connections` for the current state.
    - Expect: nothing from the chain running; no connections to the IPs or domains from steps 13 and 15.
    - If C2 looks live (connections to those IPs or domains still happening): escalate now.
    - A blocked connection can still show as `ConnectionSuccess`. Check the alerts queue for the block.

17. **If it ran: check persistence** with the [persistence playbook](../04-persistence-detected/playbook.md): run keys, scheduled tasks, services, startup folders and WMI. Compare with the package's Autoruns, Scheduled tasks and Services.
    - Expect: nothing the attacker added.
    - If found: record each item. Don't remove anything yet; that is step 23.

18. **If it ran, or it is a credential dumper (step 12): check identity:** lsass access, credential-tool keywords, new accounts, lateral movement. Use step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md).
    - Expect: no hits.
    - If the file is a known credential dumper (for example Mimikatz), or step 2 of the credential compromise playbook has any hit: escalate, and follow that playbook from step 2 for this device.

---

## 4. Scope

19. **Search for the file across the estate** ([hash sweep](investigation.md#hash-across-estate)) with the SHA1 of the file and of each file from step 15.
    - Expect: only this device.
    - If other devices: escalate (same malicious file on more than one device). Run steps 1 to 18 for each device where `Tables` shows it ran, and steps 4 to 6 for the rest. The earliest `FirstSeen` is the patient-zero candidate; if it is before T0, move T0 and rerun steps 19 and 20.
    - Zero rows doesn't prove no spread: the hash can be empty, and a per-device variant has a different hash. Check the file page's Observed in organization tab, and run the executables query without the device filter for the same file name or folder pattern.

20. **Find how it arrived** ([How did it arrive?](investigation.md#how-did-it-arrive)): `FileOriginUrl` and `FileOriginReferrerUrl` on the file's creation event (web), `RequestSourceIP`, `RequestAccountName` and `ShareName` (network share), Explorer in Defender for Office 365 (email).
    - Expect: the delivery vector recorded, with the URL, sender or source device.
    - If `RequestSourceIP` is an internal device: the file arrived over SMB from another internal device. Escalate. That device is in scope; run this playbook for it, and check the `RequestAccountName` account with step 9 of the [credential compromise playbook](../06-credential-compromise/playbook.md).
    - If email reached other users: use the [phishing email playbook](../12-phishing-email/playbook.md).
    - If none is found: record the vector as unknown.

---

## 5. Stop, block, remove

Only after step 9 is done (or recorded as failed) on every device where the file ran, and step 11 is done for every file you will remove. If you don't hold the rights for a step here (Stop and Quarantine File, indicators, Live Response `remediate`), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

21. **Stop and quarantine the file** (file page → Stop and Quarantine File). This stops its running processes, quarantines the file and deletes persistent data such as registry keys, on every device where it was seen in the last 30 days. For a script or other non-PE file, use it if the file page offers the action; otherwise step 23 removes it.
    - If a changed legitimate entry recorded in step 17 (for example Winlogon `Userinit`, or an existing service's `ImagePath`) points to the file: don't run Stop and Quarantine File yourself. Microsoft doesn't say which registry data it deletes. Ask the IR lead first.
    - Expect: the Action center shows Success for each device.
    - If Failed: record the reason. If Pending: the device is offline; the action times out after three days.
    - If Defender warns that the file is widely used in the organization: cancel and escalate. It may be a business application.
    - It can't be used on a file signed by Microsoft or by a trusted non-Microsoft publisher (for example a signed remote-access tool from step 14). Don't use Live Response `remediate` on its running process either: on a process it stops the process and deletes the image file. Escalate; the IR lead decides how to stop it. The device stays isolated meanwhile.
    - The action reaches at most 1,000 devices. If more devices have the file: escalate, and rely on the file indicator (step 22).
    - A quarantined file can be restored if it turns out to be clean.

22. **Block the IOCs** with Defender for Endpoint indicators (Settings → Endpoints → Indicators). Block the SHA1 of the file and of each malicious file from steps 13 and 15, and the external IPs, URLs and domains from steps 13, 15 and 20.
    - Never add a block indicator for the hash of a Windows binary. A file indicator stops the file being read, written or executed on every device in its scope.
    - File hashes: PE files only (`.exe`, `.dll`), and Defender Antivirus must be in active mode. A script, shortcut or document can't be blocked by hash; block its delivery URL. Blocks typically apply within 15 minutes, 30 on average, and can take over 2 hours. Microsoft recommends an indicator to keep a file blocked after Stop and Quarantine times out or completes.
    - IPs and URLs: external IPs only, one address per indicator (no ranges). Outside Microsoft Edge, blocking needs Network Protection in block mode. An HTTPS full URL path can be blocked only in Edge; other browsers block by domain, and only with QUIC and Encrypted Client Hello disabled. Blocks can take up to 48 hours; most apply within 2 hours.
    - Don't block the hash of software the customer uses elsewhere (for example a remote-access tool their IT team also runs), or a domain the customer uses for business (for example a cloud storage or code-hosting site). Escalate; for a domain, you can block the full URL (Edge only).
    - Expect: each indicator listed with its expiry.
    - A blocked connection can still appear as `ConnectionSuccess` in network events. Check the alerts queue for the block, not the connection log.

23. **Remove persistence and remaining files** found in steps 15 and 17, using the [persistence playbook](../04-persistence-detected/playbook.md). A script or other file Stop and Quarantine didn't cover, a copy at another path (step 10), or a copy on a device where the file was last seen more than 30 days ago: Live Response `remediate file` with its full path deletes it. Do this only once step 11 holds a copy or records why it couldn't.
    - Expect: each item removed and recorded.
    - Never point `remediate` at a Windows binary.
    - If the persistence is a changed legitimate entry, not a new one (for example Winlogon `Userinit`, `Shell` or `Notify`, or an existing service's `ImagePath`): don't delete the value or the key. Escalate; the IR lead restores the original data.
    - Accounts the attacker created: disable them; delete only with the IR lead's agreement.

24. **Confirm every action in the Action center** (History tab): isolation, package, quarantine, antivirus remediation, Live Response actions, on every device from step 19.
    - Expect: every action Success, and none Pending.
    - If an action failed or an item from steps 15 and 17 has no action: do it from the device or file page, or with Live Response `remediate` (not on Windows binaries). Record each.
    - If a device stayed offline past the three-day timeout: it never received Stop and Quarantine. Run step 23 on it when it is back; the indicator (step 22) covers it meanwhile for PE files.
    - If it still fails: escalate. Don't release the device.

25. **Run a full antivirus scan** (device page → Run antivirus scan → Full). From 1 September 2026 Microsoft no longer runs automated investigation (AIR) as a separate experience for Defender for Endpoint alerts; for on-demand investigations it says to run a full antivirus scan.
    - Expect: the scan completes with no new detections.
    - If it finds anything: escalate, treat each detection as a new alert, and go back to step 12 for it.

---

## 6. Clean or reimage, then release

If you don't hold the rights to release the device or to reimage it, request it from the customer's IT contact once the IR lead or the criteria in step 27 allow it.

26. **Decide clean or reimage.** Reimage when ransomware, an unknown payload or a stealer ran, someone had hands-on access, or you can't account for every item the file created. For High and above, the IR lead decides.
    - Reimaging destroys what is left on the disk. Do it only after steps 9 and 11 are done or recorded as failed, and after the IR lead says no further collection (for example a disk image) is needed.
    - Expect: the decision and who made it in the ticket.

27. **Release only when all of these hold:**
    - Steps 21 to 25 done, every action Success.
    - Credentials handled (step 18, and step 17 of the malware alert playbook if step 15 found a stealer or unknown payload).
    - Indicators in place (step 22).
    - No new alerts and no connections to the IOCs while isolated, for the period the IR lead sets.
    - For High and above, the IR lead approves the release.
    - If isolation will auto-lift (step 8) before these hold: escalate before that date.
    - Then: device page → Release from isolation. Tell the customer the outcome.

---

## 7. Close out

- [ ] Classification set: True positive, Informational expected activity (authorised test, sanctioned tool), or False positive (only per Closing as a false positive)
- [ ] SHA1 (and SHA256 if known), file path, detection name or family, and delivery vector documented
- [ ] IOCs documented (SHA1, IPs, domains, URLs), which were blocked, and which couldn't be blocked by hash
- [ ] Every device from step 19 confirmed in the Action center (step 24)
- [ ] Findings written up: vector, execution, spread, persistence, credentials, remediation, clean or reimage
- [ ] Escalated if any trigger below was hit

---

## Closing

A file that never ran and needed no containment (step 6) can be closed at Low only if all of these hold. Record each check in the ticket.

- Every condition in the malware alert playbook's [Closing at Low](../01-malware-alert/playbook.md#closing-at-low) holds. A hunting hit or a user report has no detection status: instead, steps 21 to 24 show the file quarantined or removed on every device from step 19.
- It didn't arrive over SMB from another internal device, and it isn't a remote-access or admin tool (step 6).
- No item in Escalate if applies.

If any condition fails or can't be confirmed: contain (step 7).

## Closing as a false positive

Close only with a named, verifiable benign cause, and record it. "Nothing else found", low volume, "seen on many devices", a trusted signature, high prevalence or 0 VirusTotal detections is never enough on its own; spread means scope wider. All of these must hold:

- The file is software the customer deployed on purpose: name the product and the asset list, approved-software entry or change record.
- `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` with `IsTrusted` true. For an unsigned script, the change record names the script and its owner, and its content matches (step 13).
- The process that wrote it is the product's installer or the customer's deployment tool, and nothing else in the chain is suspicious (step 15).

A sanctioned admin or test tool that was detected correctly (with a ticket): classify as Informational, expected activity, not False positive.

Never close these yourself, even if a test, a backup job or an admin is mentioned: any item in Escalate if. Escalate; the IR lead confirms any authorised activity.

If any condition can't be confirmed: don't close. Escalate.

---

## Escalate if

See also [escalation triggers](../../reference/escalation-triggers.md).

```
Shadow copies or the backup catalog deleted, or bcdedit turned off recovery
Mass file renames
Ransom-note files created in many folders
The file arrived over SMB from another internal device
A remote-access or admin tool installed with no change record or approved-software entry
A known credential dumper (for example Mimikatz), or any hit in step 2 of the credential compromise playbook
Infostealer or unknown payload executed
The file deleted itself after running
Same malicious file on more than one device
C2 looks live (connections to an IOC still happening)
Device can't be isolated (pending, offline, domain controller, other Tier 0 server, Hyper-V host)
Stop and Quarantine File can't be used (file signed by Microsoft or a trusted publisher), or Defender warns the file is widely used
More than 1,000 devices have the file
A hash or domain to block is software or a site the customer uses for business
Persistence is a changed legitimate entry, not a new one (for example Winlogon Userinit, Shell or Notify, or an existing service's ImagePath)
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
| Live Response (`fileinfo`, `findfile`, `getfile`, `processes`, `connections`, `remediate`) | Device page → Actions → Initiate Live Response session |
| Collect file / Download file / Deep analysis | File page → Collect file / Download file / Deep analysis |
| Stop and quarantine file | File page → Stop and Quarantine File |
| Add indicator | Settings → Endpoints → Indicators |
| Run AV scan | Device page → Actions → Run antivirus scan |
| Check actions | Defender XDR → Action center |
| Release isolation | Device page → Actions → Release from isolation |
