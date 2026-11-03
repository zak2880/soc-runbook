# C2 beaconing — playbook

Work top to bottom. Each step is one action, what you should see, and what to do if you don't. Capture evidence before you stop, quarantine, remove or delete anything. Queries and background are in the [investigation](investigation.md).

T0 = the first connection from the device to the C2 destination, or the earliest malicious event before it, in UTC. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

Don't wait for proof of an interactive session before you contain. Beaconing from a process that isn't a named, sanctioned product is enough. Isolation keeps the device connected to the Defender service, so the investigation continues.

---

## 1. Triage

1. **Record the incident:** severity, title, how many alerts are grouped. Run [All alerts for this device](../01-malware-alert/investigation.md#all-alerts-for-this-device).
   - Expect: only network or C2 alerts for this device.
   - If other categories appear (credential access, lateral movement, malware execution): record them and treat this as a multi-stage incident. Check them against Escalate if before you continue.

2. **Record the beacon:** device FQDN and OS; the logged-on user's SAM name and UPN; the destination IP, domain and port; and the process that made the connections: file name, folder path, SHA1, PID, start time, parent and account. Take them from the alert evidence or the network events in the Device timeline (`InitiatingProcessFolderPath`, `InitiatingProcessSHA1`, `InitiatingProcessId`, `InitiatingProcessCreationTime`). SHA256 is usually empty; use SHA1.
   - Expect: all known.
   - If the process is unknown: record the destination and use the Device timeline from the alert time backwards to find it.

3. **Set T0.** Search the destination domain in the Defender portal and take this device's first event time from the URL/domain page (Devices tab). If you only have an IP: search the Device timeline for the IP and take the earliest event. The IP page's first-seen time is for the whole organization, so use it as a lower bound only.
   - Expect: T0 at or before the alert time.
   - If the first event sits at the start of the time range: widen the range (the domain page goes back up to six months; Advanced Hunting holds 30 days). If you still can't find the start, mark T0 as an estimate.

4. **Check the process.** Look up its SHA1 in `DeviceFileCertificateInfo` (`Signer`, `IsTrusted`) and note its folder path. Check what it started: `DeviceProcessEvents` on this device where `InitiatingProcessId` is the beacon PID and `InitiatingProcessCreationTime` is its start time. Check the alert evidence and the Device timeline for named pipes (the hunting `ActionType` for pipe events is VERIFY (tenant)).
   - Expect: a signed product (`IsTrusted` true, `Signer` = the product's vendor) running from its install folder, that started nothing unexpected.
   - If any of the following: this is beaconing confirmed from a process that isn't a named, sanctioned product. Go to step 7 now and escalate. Don't do steps 5 and 6 first.
     - The process isn't signed, `IsTrusted` is false, or the signer isn't the vendor of the product it claims to be.
     - It runs from a user-writable folder (`AppData`, `Temp`, `Downloads`, `C:\Users\Public`).
     - It is a Windows binary that loads DLLs (`rundll32.exe`, `dllhost.exe`, `regsvr32.exe`) and makes the connections itself.
     - An RMM tool that isn't on the customer's approved list, or was installed outside a change record. If you can't check the record now, treat it as not approved.
     - Shells or recon commands started by the beaconing process (`cmd.exe`, `powershell.exe`, `whoami`, `net`, `nltest`).
     - A Cobalt Strike default named pipe (`msagent_*`, `status_*`, `postex_*`, `MSSE-*`).
     - A reverse shell (outbound connection from `cmd.exe` or `powershell.exe`).
     - An alert on the device that names Cobalt Strike or another C2 framework.

5. **Check the destination.** On the Defender IP or URL/domain page, read the Microsoft verdict and the related alerts. Find the vendor's documentation of the domains or IPs the product uses.
   - Expect: no malicious verdict, no related alerts, and the destination is in the vendor's documentation for this product.
   - If not, or you can't tell: this is beaconing confirmed from a process that isn't a named, sanctioned product. Go to step 7 and escalate.

6. **Decide the path.**
   - Every condition in [Closing as a false positive](#closing-as-a-false-positive) holds: close per that section. Containment isn't needed.
   - Anything else, or you can't tell: this is beaconing confirmed from a process that isn't a named, sanctioned product. Go to step 7 and escalate.

---

## 2. Contain the device

If you don't hold the rights for a step here, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

7. **Check the device type and network before isolating.**
   - Domain controller, other Tier 0 server, or Hyper-V host: don't isolate it yourself. Escalate now (device can't be isolated). Isolating a Hyper-V host blocks network traffic to every VM on it.
   - Production server: tell the customer contact you are isolating it, and record the time.
   - Full-tunnel VPN: Microsoft says the device can't reach the Defender service once isolated. Do step 9 first, then step 8.
   - Behind a web proxy (PAC, WPAD or static): use selective isolation. Microsoft warns such devices might not recover from full isolation.
   - Expect: an ordinary workstation or member server. Go to step 8.

8. **Isolate the device** (device page → Isolate device). Isolation cuts the C2 channel and keeps the device connected to the Defender service.
   - Expect: the Action center shows the isolation as completed.
   - If not (pending or offline): Defender retries for up to three days. Escalate (device can't be isolated) and report the device as not isolated.
   - Microsoft states isolation is lifted automatically after seven days (VERIFY (tenant)). Put the date in the ticket and re-check it.

9. **Collect the investigation package** (device page → Collect investigation package). It records autoruns, running processes, network connections, DNS cache, prefetch, scheduled tasks, services and the Security event log.
   - Expect: the package is downloadable from the Action center.
   - If not: collection can fail on low battery or a metered connection. Retry once, then record the failure and continue.
   - Don't run an antivirus scan, Stop and Quarantine File, or Live Response `remediate` until this step is done or recorded as failed. Those actions remove files, processes and registry entries the package would have recorded.

10. **Record the live state and preserve the implant.** In Live Response, run `processes` and `connections`; record the beacon PID and its connections. On the implant's file page, select Collect file if it is shown. If Download file is shown instead, Defender already holds a copy.
    - Expect: the outputs attached to the ticket and the sample held by Defender.
    - If Live Response isn't available (not enabled, no role, session fails): record why and use the package's Processes and Network connections folders.
    - If Collect file is disabled: the file hasn't been seen in the past 30 days, or you lack the permission. Record which.
    - If the beacon runs inside a signed program, the implant is the DLL found in step 13; collect it there.
    - Don't open or run the file on your own workstation.

---

## 3. Investigate

11. **Trace the process chain and how the implant arrived** in the Attack story and the Device timeline ([process guide](../02-suspicious-process/investigation.md)). Check the implant file's creation event for `FileOriginUrl` ([how did it arrive](../01-malware-alert/investigation.md#step-4--check-for-spread)). For an RMM tool, record when and by which account it was installed.
    - Expect: the delivery vector recorded, and each process in the chain recorded with its SHA1.
    - If a script host, LOLBin or unknown binary is in the chain: it is in scope. Record it and its SHA1.
    - If an RMM tool was installed outside a change record: escalate (an RMM tool that isn't on the customer's approved list, or was installed outside a change record).

12. **Check for hands-on activity since T0.** Repeat the child-process check from step 4 for the whole period since T0, and look for a sudden rise in connections to the destination ([investigation: Is someone driving it?](investigation.md#3-is-someone-driving-it)).
    - Expect: no shells or recon commands, no reverse shell, no Cobalt Strike default named pipe.
    - If any: escalate (shells or recon commands started by the beaconing process, a reverse shell, or a Cobalt Strike default named pipe). List every account exposed on the device with step 8 of the [credential compromise playbook](../06-credential-compromise/playbook.md) and give the list to the IR lead, who decides on session revocation and password resets (06 playbook steps 13 to 18).

13. **Check for a beacon inside a signed program.** Only if the beaconing process is signed (a vendor app or a Windows binary): check `DeviceImageLoadEvents` for that process on this device since T0, and the device's alerts for process injection.
    - Expect: every DLL it loaded is signed by the vendor or Microsoft (`DeviceFileCertificateInfo`), and no injection alert.
    - If not: escalate (a beacon inside a signed or Microsoft process). Record the DLL path and SHA1, and collect it as in step 10.

14. **Check persistence** with the [persistence playbook](../04-persistence-detected/playbook.md): run keys, scheduled tasks, services, startup folders and WMI. Compare with the package's Autoruns, Scheduled tasks and Services, or Live Response `persistence`.
    - Expect: nothing the attacker added.
    - If found: record each item. Don't remove anything yet; that is step 21.

15. **Check identity:** lsass access, credential-tool keywords, new accounts, lateral movement. Use step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md).
    - Expect: no hits.
    - If any hit: escalate (credential access or lateral movement on the device). Follow the 06 playbook from step 2 for this device.

16. **Enrich the destination** with the [threat intel enrichment guide](../../reference/threat-intel-enrichment.md). Look the IP and domain up; don't upload the implant or submit internal URLs to public services.
    - Expect: reputation, domain age and hosting recorded. A clean result doesn't clear the destination.
    - If the C2 runs over a cloud or web service: use the [LOTS & cloud C2 playbook](../09-lots-cloud-c2/playbook.md) as well.

---

## 4. Scope

17. **Find other devices that reached the destination:** the IP page (IP prevalence and IP activity observed in the organization) and the URL/domain page (Devices tab). Also run the [high connection count](investigation.md#high-connection-count) query and look for the same `RemoteIP` or `RemoteUrl`.
    - Expect: only this device.
    - If other devices: escalate (same destination or implant SHA1 on more than one device). Run steps 2 to 16 for each. The earliest first event is the patient-zero candidate; if it is before T0, move T0 and rerun steps 17 and 18.
    - The IP page lists up to 100 devices, and the query only shows pairs above 30 connections. Many devices is a reason to scope wider, never to close.

18. **Search for the implant across the estate** with the [hash sweep](../01-malware-alert/investigation.md#step-4--check-for-spread). Use the implant's SHA1, and the SHA1 of any DLL from step 13.
    - Expect: only this device.
    - If other devices: escalate (same destination or implant SHA1 on more than one device). Run steps 2 to 16 for each.
    - Zero rows doesn't prove no spread.

---

## 5. Stop, block, remove

Only after step 9 is done (or recorded as failed) and step 10 is done, on every device in scope. If you don't hold the rights for a step here, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

19. **Stop and quarantine the implant** (file page → Stop and Quarantine File). This stops its running processes, quarantines the file and deletes persistent data such as registry keys, on every device where it was seen in the last 30 days.
    - If a changed legitimate entry recorded in step 14 (for example Winlogon `Userinit`, or an existing service's `ImagePath`) points to the file: don't run Stop and Quarantine File yourself. Microsoft doesn't say which registry data it deletes. Ask the IR lead first.
    - Expect: the Action center shows Success for each device.
    - If Failed: record the reason. If Pending: the device is offline; the action times out after three days.
    - If Defender warns that the file is widely used in the organization: cancel and escalate (Stop and Quarantine File can't be used, or Defender warns the file is widely used). It may be a business application.
    - If the beacon runs inside a signed or Microsoft process (step 13), or the file is signed by Microsoft or a trusted publisher: Stop and Quarantine File can't be used on it. Don't use Live Response `remediate` on that process either: it stops the process and deletes the image file. Escalate (Stop and Quarantine File can't be used); the IR lead decides how to stop it. The device stays isolated meanwhile.
    - A quarantined file can be restored if it turns out to be clean.

20. **Block the IOCs** with Defender for Endpoint indicators (Settings → Endpoints → Indicators). Block every external IP and domain the beacon used (steps 2, 10, 16 and 17), and the SHA1 of each malicious file (steps 11 and 13).
    - IPs: external IPs only, one address per indicator (no ranges). C2 that rotates across several IPs or a CDN isn't covered by one IP indicator; block the domain too.
    - Domains and URLs: outside Microsoft Edge, blocking needs Network Protection in block mode. For HTTPS, Network Protection reads the host name from the TLS handshake, so the connection must use TCP (not QUIC) with an unencrypted ClientHello. A full URL path can be blocked only in Edge. Blocks can take up to 48 hours; most apply within 2 hours.
    - File hashes: PE files only (`.exe`, `.dll`), and Defender Antivirus must be in active mode. Blocks typically apply within 15 minutes, 30 on average, and can take over 2 hours.
    - If the destination is a cloud or business service the customer uses: don't block it. Escalate (destination is a cloud or business service the customer uses).
    - Expect: each indicator listed with its expiry.
    - Check that blocks work in the alerts queue and in `DeviceEvents` with `ActionType` `ExploitGuardNetworkProtectionBlocked`. A blocked connection can still appear as `ConnectionSuccess` in network events. Any other device in those block events is still trying to reach the destination: escalate (same destination or implant SHA1 on more than one device) and run steps 2 to 16 for it.

21. **Remove persistence and remaining files** found in steps 11, 13 and 14, using the [persistence playbook](../04-persistence-detected/playbook.md).
    - Expect: each item removed and recorded.
    - If the persistence is a changed legitimate entry, not a new one (for example Winlogon `Userinit`, `Shell` or `Notify`, or an existing service's `ImagePath`): don't delete the value or the key. Escalate; the IR lead restores the original data.
    - Accounts the attacker created: disable them; delete only with the IR lead's agreement.

22. **Confirm every action in the Action center** (History tab): isolation, package, quarantine, antivirus remediation, Live Response actions.
    - Expect: every action Success.
    - If an action failed or an item from steps 11, 13 and 14 has no action: do it from the device or file page, or with Live Response `remediate` (not on Windows binaries or signed programs). Record each.
    - If it still fails: escalate (remediation failed and can't be completed). Don't release the device.

23. **Run a full antivirus scan** (device page → Run antivirus scan → Full). Since 1 September 2026, automated investigation (AIR) no longer runs as a separate investigation in Defender for Endpoint and can't be triggered manually; Microsoft says to run a full antivirus scan for on-demand investigations.
    - Expect: the scan completes with no new detections.
    - If it finds anything: treat each detection as a new alert and go back to step 11 for it.

---

## 6. Clean or reimage, then release

24. **Decide clean or reimage.** Reimage when step 12 found hands-on activity, step 13 found a beacon inside a signed program, the implant is unknown, or you can't account for every item it created. For High and above, the IR lead decides.
    - Reimaging destroys what is left on the disk. Do it only after steps 9 and 10 are done or recorded as failed, and after the IR lead says no further collection (for example a disk image) is needed.
    - Expect: the decision and who made it in the ticket.

25. **Release only when all of these hold:**
    - Steps 19 to 23 done, every action Success.
    - Credentials handled (steps 12 and 15).
    - Indicators in place (step 20).
    - No new alerts, and no network events from the implant or to the destination in the Device timeline after step 21, for the period the IR lead sets.
    - For High and above, the IR lead approves the release.
    - If isolation will auto-lift (step 8) before these hold: escalate (isolation will auto-lift before the release criteria hold) before that date.
    - Then: device page → Release from isolation. Tell the customer the outcome.

---

## 7. Close out

- [ ] Classification set: True positive, Informational expected activity (authorised test, sanctioned tool), or False positive (only per Closing as a false positive)
- [ ] Destination IPs, domains and ports documented, with T0, and which were blocked
- [ ] Implant path and SHA1 documented, and how it arrived
- [ ] Hands-on activity found or not; exposed accounts and what was done for each
- [ ] Devices in scope documented
- [ ] MITRE techniques shown on each alert recorded
- [ ] Findings written up: vector, implant, persistence, spread, credentials, remediation, clean or reimage
- [ ] Escalated if any trigger below was hit

---

## Closing as a false positive

Close only with a named, verifiable benign cause, and record it. A known app name, a standard install path, a long-established domain, a fixed interval, low volume, or "seen on many devices" is never enough: attacker-installed RMM tools, beacons injected into or side-loaded by signed programs, and C2 over cloud services or aged domains all pass those tests. Spread means scope wider. All of these must hold:

- The product is named, and the customer's asset list, approved-software list or a change record covers it on this device. For an RMM tool, its install time and installing account match that record.
- `DeviceFileCertificateInfo` for the beaconing process's SHA1 shows the vendor as `Signer` with `IsTrusted` true, and the process runs from the vendor's install folder.
- The process started no shells or recon commands. `DeviceImageLoadEvents` for it shows no DLL that isn't signed by the vendor or Microsoft. The device has no other alerts since T0.
- The destination is infrastructure the vendor documents for that product, and the Defender IP or URL/domain page shows no malicious verdict and no related alerts.

An authorised red team exercise or test with a ticket: classify as Informational, expected activity, not False positive. The IR lead confirms it.

Never close these yourself, even if a test is mentioned: shells or recon commands started by the beaconing process; a Cobalt Strike default named pipe; a reverse shell; a beacon inside a signed or Microsoft process; an RMM tool that isn't on the customer's approved list, or was installed outside a change record; credential access or lateral movement on the device. Escalate; the IR lead confirms any authorised test.

Don't add a suppression or exclusion to stop the alert. Request tuning from whoever owns the detection, with the evidence above.

If any condition can't be confirmed: don't close. Treat it as beaconing confirmed from a process that isn't a named, sanctioned product: contain (step 7) and escalate.

---

## Escalate if

See also [escalation triggers](../../reference/escalation-triggers.md).

```
Beaconing confirmed from a process that isn't a named, sanctioned product
Shells or recon commands started by the beaconing process
A Cobalt Strike default named pipe (msagent_*, status_*, postex_*, MSSE-*)
A reverse shell (outbound connection from cmd.exe or powershell.exe)
A beacon inside a signed or Microsoft process
An RMM tool that isn't on the customer's approved list, or was installed outside a change record
Credential access or lateral movement on the device
Same destination or implant SHA1 on more than one device
Device can't be isolated (pending, offline, domain controller, Tier 0 server, Hyper-V host)
Stop and Quarantine File can't be used, or Defender warns the file is widely used
Destination is a cloud or business service the customer uses
Persistence is a changed legitimate entry, not a new one (for example Winlogon Userinit, Shell or Notify, or an existing service's ImagePath)
Remediation failed and can't be completed
Isolation will auto-lift before the release criteria hold
```

---

## Actions — Defender XDR quick reference

| Action | Where |
|--------|-------|
| Isolate device | Device page → Actions → Isolate device |
| Collect investigation package | Device page → Actions → Collect investigation package |
| Live Response | Device page → Actions → Initiate Live Response session |
| Collect file | File page → Collect file |
| Stop and quarantine file | File page → Stop and Quarantine File |
| IP or domain prevalence | Portal search → IP page / URL or domain page |
| Add indicator | Settings → Endpoints → Indicators |
| Run AV scan | Device page → Actions → Run antivirus scan |
| Check remediation | Defender XDR → Action center |
| Release isolation | Device page → Actions → Release from isolation |
