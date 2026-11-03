# Suspicious network activity — playbook

Work top to bottom. Each step is one action, what you should see, and what to do if you don't. Capture evidence before you stop, quarantine, block, remove or delete anything. Queries and background are in the [investigation](investigation.md).

T0 = the first suspicious network event from the device, or the earliest malicious event before it, in UTC. It is not the alert time. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

Don't wait for proof of a live or interactive session before you contain. Network activity from a process that isn't a named, sanctioned product, a documented script or an approved scanner is enough. Isolation keeps the device connected to the Defender service, so the investigation continues.

Never browse to, download from or submit a URL from this incident to a public scanner.

---

## 1. Triage

1. **Record the incident:** severity, title, how many alerts are grouped. Run [All alerts for this device](../01-malware-alert/investigation.md#all-alerts-for-this-device).
   - Expect: only network alerts for this device.
   - If other categories appear (malware execution, credential access, lateral movement): record them and treat this as a multi-stage incident. Check them against Escalate if before you continue.

2. **Record the connection:** device FQDN and OS; the logged-on user's SAM name and UPN; the destination IP, domain and port, and whether it is internal or external (`RemoteIPType`); and the process that made the connection: file name, folder path, SHA1, command line, PID, start time, parent and account (`InitiatingProcessFolderPath`, `InitiatingProcessSHA1`, `InitiatingProcessCommandLine`, `InitiatingProcessId`, `InitiatingProcessCreationTime`, `InitiatingProcessParentFileName`, `InitiatingProcessAccountName`). SHA256 is usually empty; use SHA1.
   - Expect: all known.
   - If the process is unknown: record the destination and use the Device timeline from the alert time backwards to find it.
   - For HTTPS, `RemoteUrl` holds the host at most. The command line often has the full URL.
   - If the network event names `svchost.exe` for a download: it may be a BITS transfer. Find the `bitsadmin.exe` or `Start-BitsTransfer` command in the Device timeline ([investigation: Download cradles](investigation.md#download-cradles)).
   - If the alert is for connections into this device from another internal device: that device is the source. Work on it as well, with this playbook from step 2.

3. **Set T0.** External destination: search the domain in the Defender portal and take this device's first event time from the URL/domain page (Devices tab). If you only have an IP, or the destination is internal: take the earliest event to it in the Device timeline. The IP page's first-seen time is for the whole organization, so use it as a lower bound only.
   - Expect: T0 at or before the alert time.
   - If the first event sits at the start of the time range: widen the range (the domain page goes back up to six months; Advanced Hunting holds 30 days). If you still can't find the start, mark T0 as an estimate.

4. **Check whether the connection was blocked:** the alerts queue, and `DeviceEvents` with `ExploitGuardNetworkProtectionBlocked` or `ExploitGuardNetworkProtectionAudited` for this device and destination ([investigation: What MDE can and can't show you](investigation.md#what-mde-can-and-cant-show-you)).
   - Expect: the result recorded (blocked, audited, or no network protection event).
   - A `ConnectionSuccess` row in `DeviceNetworkEvents` doesn't prove the connection worked; a blocked site can still log one. Audited means it was allowed.
   - Blocked doesn't clear the device: the process still ran. Continue.

5. **Classify the activity** ([investigation: What you're looking for](investigation.md#what-youre-looking-for)). Take the first line that fits.
   - A. Beaconing: repeated connections from one process to one external destination, on any port. Use the [C2 beaconing playbook](../08-c2-beaconing/playbook.md) from its step 4. Steps 1 to 3 here cover its steps 1 to 3.
   - B. A cloud, paste, webhook or code-hosting service (OneDrive, SharePoint, Microsoft Graph, GitHub, Discord, Telegram, paste sites, Dropbox, Google Drive, object storage), including downloads from one. Use the [LOTS & cloud C2 playbook](../09-lots-cloud-c2/playbook.md) from its step 5. Steps 1 to 4 here cover its steps 1 to 4.
   - C. Download: a downloader or script host fetching from any other internet host (`certutil.exe`, `curl.exe`, `powershell.exe`, `pwsh.exe`, `mshta.exe`, `bitsadmin.exe` or BITS, `finger.exe`). Continue here.
   - D. Internal: connections from this device to other internal devices on admin ports (445, 139, 135, 3389, 5985, 5986, 22). Continue here.
   - E. Anything else: an unusual port, a reverse shell, DNS with long, changing labels. Continue here.
   - Expect: one class recorded.
   - If D fits as well as A or B: continue here; step 20 tells you what to add.

6. **Check the process and decide the path.** Look up its SHA1 in `DeviceFileCertificateInfo` (`Signer`, `IsTrusted`), note its folder path and command line, and check what it started: `DeviceProcessEvents` on this device where `InitiatingProcessId` is its PID and `InitiatingProcessCreationTime` is its start time. These checks only read; change nothing on the device.
   - As soon as you see any of the following, go to step 7 and escalate; don't finish the other checks first. For the first six items the Escalate if line is "network activity from a process that isn't a named, sanctioned product, a documented script or an approved scanner"; the others are their own lines.
     - The process isn't signed, `IsTrusted` is false, or the signer isn't the vendor of the product it claims to be.
     - It runs from a user-writable folder (`AppData`, `Temp`, `Downloads`, `C:\Users\Public`).
     - It is a Windows binary that loads DLLs (`rundll32.exe`, `dllhost.exe`, `regsvr32.exe`) and makes the connections itself.
     - Class C, and the customer hasn't documented the script or job (named script path, change record or scheduled job). If you can't check now, treat it as not documented.
     - Class D, and the device isn't an approved scanner or management server, or the connections go beyond what its role explains (for a workstation: beyond its usual file servers, print servers and domain controllers).
     - An alert on the device that names Cobalt Strike or another C2 framework.
     - An RMM tool that isn't on the customer's approved list, or was installed outside a change record. If you can't check the record now, treat it as not approved.
     - Shells or recon commands started by the connecting process (`cmd.exe`, `powershell.exe`, `whoami`, `net`, `nltest`).
     - A reverse shell (`cmd.exe` or `powershell.exe` making the outbound connection).
     - A downloaded file that ran, outside a documented script or job.
     - A DNS tunnelling pattern ([investigation: DNS beaconing](investigation.md#dns-beaconing)).
   - Expect: a named, sanctioned product (signed by its vendor, in the vendor's install folder, and covered by the customer's asset list, approved-software list or a change record), a documented script or job, or an approved scanner, that started nothing unexpected. Check [Closing as a false positive](#closing-as-a-false-positive) now. If every condition holds, close there.
   - Anything else, or you can't tell: go to step 7 and escalate (network activity from a process that isn't a named, sanctioned product, a documented script or an approved scanner).

---

## 2. Contain the device

If you don't hold the rights for a step here, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

7. **Check the device type and network before isolating.**
   - Domain controller, other Tier 0 server, or Hyper-V host: don't isolate it yourself. Escalate now (device can't be isolated). Isolating a Hyper-V host blocks network traffic to every VM on it.
   - Production server, or a management server or scanner other systems depend on: tell the customer contact you are isolating it, and record the time.
   - Full-tunnel VPN: Microsoft says the device can't reach the Defender service once isolated. Do step 9 first, then step 8.
   - Behind a web proxy (PAC, WPAD or static): use selective isolation. Microsoft warns such devices might not recover from full isolation.
   - If the activity also runs over Microsoft 365 or Microsoft Graph (step 5, B together with D): choose the isolation type with step 7 of the [LOTS & cloud C2 playbook](../09-lots-cloud-c2/playbook.md).
   - Expect: an ordinary workstation or member server. Go to step 8.

8. **Isolate the device** (device page → Isolate device). Isolation disconnects it from the network, which cuts C2, downloads and connections to other internal devices, and keeps it connected to the Defender service.
   - Expect: the Action center shows the isolation as completed.
   - If not (pending or offline): Defender retries for up to three days. Escalate (device can't be isolated) and report the device as not isolated.
   - Microsoft states isolation is lifted automatically after seven days (VERIFY (tenant)). Put the date in the ticket and re-check it.

9. **Collect the investigation package** (device page → Collect investigation package). It records autoruns, running processes, network connections (active connections, ARP cache, DNS cache), SMB sessions, prefetch, scheduled tasks, services and the Security event log.
   - Expect: the package is downloadable from the Action center.
   - If not: collection can fail on low battery or a metered connection. Retry once, then record the failure and continue.
   - Don't run an antivirus scan, Stop and Quarantine File, or Live Response `remediate` until this step is done or recorded as failed. Those actions remove files, processes and registry entries the package would have recorded.

10. **Record the live state and preserve the evidence.** In Live Response, run `processes` and `connections`; record the process and its connections. Copy the full command line of the process, and of its parent, into the ticket. Then, on the file page, select Collect file for each malicious file: an unsigned or unknown program, the script a script host ran (path from the command line), or a file a downloader wrote. Don't collect `powershell.exe`, `certutil.exe` or another Windows binary. If Download file is shown instead, Defender already holds a copy.
    - Expect: the outputs attached to the ticket and the samples held by Defender.
    - If Live Response isn't available (not enabled, no role, session fails): record why and use the package's Processes and Network connections folders.
    - If Collect file is disabled: the file hasn't been seen in the past 30 days, or you lack the permission. Record which.
    - If there is no file (the command ran inline or was passed with `-EncodedCommand`, `-ec` or `-e`): the command line in the ticket is the evidence. An encoded command is Base64 of UTF-16LE text: decode it as text, never run it, and record the URLs in it.
    - Don't open or run any file on your own workstation, and don't browse to the URLs.

---

## 3. Investigate

If you don't hold the rights for a step here (Collect file, Live Response), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

11. **Trace the process chain and how it arrived** in the Attack story and the Device timeline ([process guide](../02-suspicious-process/investigation.md)). Check the creation event of the first file in the chain for `FileOriginUrl` ([how did it arrive](../01-malware-alert/investigation.md#step-4--check-for-spread)). For an RMM tool, record when and by which account it was installed.
    - Expect: the delivery vector recorded, and each process in the chain recorded with its SHA1.
    - If a script host, LOLBin or unknown binary is in the chain: it is in scope. Record it and its SHA1.
    - If an RMM tool was installed outside a change record: escalate (an RMM tool that isn't on the customer's approved list, or was installed outside a change record).
    - If it arrived by email and the email reached other users: use the [phishing email playbook](../12-phishing-email/playbook.md).

12. **Find what was downloaded or written, and whether it ran** ([investigation: Download cradles](investigation.md#download-cradles)). Record the path and SHA1 of each file. Run the hash sweep for each SHA1 and read `Tables`. Collect file for each one you'll need (step 10 limits apply). Submit an unknown PE for Deep analysis on the file page.
    - Expect: nothing written, or only files that never ran (`Tables` shows only `DeviceFileEvents`, and the Device timeline shows nothing started by them).
    - For a script or document the hash sweep may be empty: check the Device timeline for processes it started.
    - If a downloaded file ran, outside a documented script or job: escalate (a downloaded file that ran, outside a documented script or job). Add its process to the chain from step 11.

13. **Check for hands-on activity since T0.** Repeat the child-process check from step 6 for the whole period since T0. Check the alert evidence and the Device timeline for a Cobalt Strike default named pipe (`msagent_*`, `status_*`, `postex_*`, `MSSE-*`), as in the [C2 beaconing investigation](../08-c2-beaconing/investigation.md#3-is-someone-driving-it).
    - Expect: no shells or recon commands, no reverse shell, no Cobalt Strike default named pipe.
    - If any: escalate (shells or recon commands started by the connecting process, a reverse shell, or a Cobalt Strike default named pipe). List every account exposed on the device with step 8 of the [credential compromise playbook](../06-credential-compromise/playbook.md) and give the list to the IR lead, who decides on session revocation and password resets (06 playbook steps 13 to 18).

14. **Check for connections from inside a signed program.** Only if the connecting process is signed and isn't a Windows downloader or script host from step 5: check `DeviceImageLoadEvents` for that process on this device since T0, and the device's alerts for process injection ([C2 beaconing investigation](../08-c2-beaconing/investigation.md#4-is-it-hiding-in-a-legitimate-program)).
    - Expect: every DLL it loaded is signed by the vendor or Microsoft (`DeviceFileCertificateInfo`), and no injection alert.
    - If not: escalate (connections from inside a signed or Microsoft process). Record the DLL path and SHA1, and collect it as in step 10.

15. **Check connections from the device to other internal devices** ([investigation: Lateral movement — network signals](investigation.md#lateral-movement--network-signals)). Run the internal lateral movement scanning query for this device; widen its window in your copy if the activity lasted longer than an hour either side of T0. For each internal target that accepted a connection, check its logons and remote execution ([remote execution tools](../06-credential-compromise/investigation.md#remote-execution-tools)).
    - Expect: only connections the device's role explains (its usual file servers, print servers, domain controllers and management servers), and no logon or remote execution on any other target.
    - If scanning: escalate (internal scanning not explained by the device's role or an approved scanner).
    - If a logon or remote execution on a target: escalate (lateral movement from the device). Each target is in scope: run this playbook from step 2 for it, and follow the [credential compromise playbook](../06-credential-compromise/playbook.md) from step 2 for this device.
    - If repeated connections go between this device and one internal device, or a process is listening on an unusual port (step 10 `connections`): treat it as possible internal C2. Run this playbook from step 2 for the other device.

16. **Check DNS for the device:** long, changing labels under one parent domain in `DnsConnectionInspected` events (if your tenant has them), the package's `DnsCache.txt`, and the customer's DNS logs ([investigation: DNS beaconing](investigation.md#dns-beaconing)).
    - Expect: no such pattern.
    - If found: escalate (a DNS tunnelling pattern). Record the parent domain as an IOC.
    - No DNS data doesn't clear the device: DNS over HTTPS hides lookups, and the query library's DNS query can't count changing labels.

17. **Check persistence** with the [persistence playbook](../04-persistence-detected/playbook.md): run keys, scheduled tasks, services, startup folders and WMI. Compare with the package's Autoruns, Scheduled tasks and Services, or Live Response `persistence`.
    - Expect: nothing the attacker added.
    - If found: record each item. Don't remove anything yet; that is step 25.

18. **Check identity:** lsass access, credential-tool keywords, new accounts. Use step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md).
    - Expect: no hits.
    - If any hit: escalate (credential access on the device). Follow the 06 playbook from step 2 for this device.

19. **Check what may have left the device** ([investigation: Data leaving the device](investigation.md#data-leaving-the-device)). MDE has no byte counts; ask the customer for proxy or firewall logs if volume matters.
    - Expect: no upload or sync tool started by an unexpected process or account, no archive staged before the connections, and no connection by a script host or unknown program to a webhook service, the Telegram Bot API, Microsoft Graph or a storage host outside the customer's tenant.
    - If any: escalate (possible exfiltration).
    - If a stealer or unknown payload ran (steps 11 and 12): escalate (a stealer or unknown payload ran). Treat the browser-saved passwords and signed-in web sessions of every user who logged on to the device (06 playbook step 8) as exposed. Follow 06 playbook steps 13 to 18 for each of those users (capture evidence, revoke sessions, reset passwords). Tell the customer which users need resets for other sites they saved in the browser.

20. **Enrich each external destination** with the [threat intel enrichment guide](../../reference/threat-intel-enrichment.md). Look the IP and domain up; don't upload samples or submit full URLs from this incident to public services.
    - Expect: reputation, domain age and hosting recorded. A clean result or an old domain doesn't clear the destination.
    - If the content behind a URL must be fetched to understand it: escalate (URL content must be fetched to understand it). The IR lead decides how.
    - If step 5 found D together with B: also do steps 11 and 12 of the [LOTS & cloud C2 playbook](../09-lots-cloud-c2/playbook.md) (full URL, dead-drop resolver). D together with A: steps 6 and 13 here cover the beacon checks.

---

## 4. Scope

21. **Find other devices that reached the destination:** for each external destination, the IP page and the URL/domain page (Devices tab), the [high connection count](investigation.md#high-connection-count) query, and `ExploitGuardNetworkProtectionBlocked` events for the destination ([investigation: Scope](investigation.md#scope)). For internal activity, run the lateral movement query without the device filter.
    - Expect: only this device.
    - If other devices: escalate (same destination or malicious SHA1 on more than one device). Run steps 2 to 20 for each. The earliest first event is the patient-zero candidate; if it is before T0, move T0 and rerun steps 21 and 22.
    - The IP page lists up to 100 devices, and the query only shows pairs above 30 connections. Many devices is a reason to scope wider, never to close.

22. **Search for each malicious file across the estate** with the [hash sweep](../01-malware-alert/investigation.md#step-4--check-for-spread): the SHA1 of the connecting process if it isn't a Windows binary, and of each file from steps 10, 11, 12 and 14.
    - Expect: only this device.
    - If other devices: escalate (same destination or malicious SHA1 on more than one device). Run steps 2 to 20 for each.
    - Zero rows doesn't prove no spread.

---

## 5. Stop, block, remove

Only after step 9 is done (or recorded as failed) and step 10 is done, on every device in scope. If you don't hold the rights for a step here, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

23. **Stop and quarantine each malicious non-Microsoft file** from steps 10, 11, 12 and 14 (file page → Stop and Quarantine File). This stops its running processes, quarantines the file and deletes persistent data such as registry keys, on every device where it was seen in the last 30 days.
    - If a changed legitimate entry recorded in step 17 (for example Winlogon `Userinit`, or an existing service's `ImagePath`) points to the file: don't run Stop and Quarantine File yourself. Microsoft doesn't say which registry data it deletes. Ask the IR lead first.
    - Expect: the Action center shows Success for each device.
    - If Failed: record the reason. If Pending: the device is offline; the action times out after three days.
    - If Defender warns that the file is widely used in the organization: cancel and escalate (Stop and Quarantine File can't be used or the process still runs, or Defender warns the file is widely used). It may be a business application.
    - It can't be used on a file signed by Microsoft or by a trusted non-Microsoft publisher. Check the signer in `DeviceFileCertificateInfo` first; expect this for Windows downloaders and script hosts (`certutil.exe`, `curl.exe`, `powershell.exe`, `mshta.exe`) and for a signed program hosting a malicious DLL. Quarantine the downloaded file, script or DLL instead. Don't use Live Response `remediate` on the Windows process: on a process it stops the process and deletes the image file. If the malicious file itself is signed by a trusted publisher: escalate (Stop and Quarantine File can't be used or the process still runs, or Defender warns the file is widely used); the IR lead decides.
    - A quarantined script or DLL is no evidence that the process running it stopped. Run Live Response `processes` again. If it still runs: escalate (Stop and Quarantine File can't be used or the process still runs, or Defender warns the file is widely used); the IR lead decides how to stop it. The device stays isolated meanwhile.
    - A quarantined file can be restored if it turns out to be clean.

24. **Block the IOCs** with Defender for Endpoint indicators (Settings → Endpoints → Indicators). Block every external IP and domain from steps 2, 10, 11, 12, 16 and 20, and the SHA1 of each malicious PE from steps 10, 11, 12 and 14.
    - IPs: external IPs only, one address per indicator (no ranges). Internal addresses can't be added; isolating each device in scope is the control. C2 that rotates across several IPs or a CDN isn't covered by one IP indicator; block the domain too.
    - Domains and URLs: outside Microsoft Edge, blocking needs Network Protection in block mode. For HTTPS, Network Protection reads the host name from the TLS handshake, so the connection must use TCP (not QUIC) with an unencrypted ClientHello. A full URL path can be blocked only in Edge. Blocks can take up to 48 hours; most apply within 2 hours.
    - A DNS tunnel's parent domain: Microsoft's indicator pages describe blocking connections, not DNS lookups, so don't rely on an indicator to stop the tunnel. Isolation (step 8) is the control.
    - File hashes: PE files only (`.exe`, `.dll`), and Defender Antivirus must be in active mode. A script can't be blocked by hash. Blocks typically apply within 15 minutes, 30 on average, and can take over 2 hours.
    - If the destination is a cloud or business service the customer uses: don't block it. Escalate (destination is a cloud or business service the customer uses).
    - Expect: each indicator listed with its expiry.
    - Check that blocks work in the alerts queue and in `DeviceEvents` with `ActionType` `ExploitGuardNetworkProtectionBlocked`. A blocked connection can still appear as `ConnectionSuccess` in network events. Any other device in those block events is still trying to reach the destination: escalate (same destination or malicious SHA1 on more than one device) and run steps 2 to 20 for it.

25. **Remove persistence and remaining files** found in steps 11, 12, 14 and 17, using the [persistence playbook](../04-persistence-detected/playbook.md).
    - Expect: each item removed and recorded.
    - If the persistence is a changed legitimate entry, not a new one (for example Winlogon `Userinit`, `Shell` or `Notify`, or an existing service's `ImagePath`): don't delete the value or the key. Escalate; the IR lead restores the original data.
    - Accounts the attacker created: disable them; delete only with the IR lead's agreement.

26. **Confirm every action in the Action center** (History tab): isolation, package, quarantine, antivirus remediation, Live Response actions.
    - Expect: every action Success.
    - If an action failed or an item from steps 11, 12, 14 and 17 has no action: do it from the device or file page, or with Live Response `remediate` (not on Windows binaries or signed programs). Record each.
    - If it still fails: escalate (remediation failed and can't be completed). Don't release the device.

27. **Run a full antivirus scan** (device page → Run antivirus scan → Full). Since 1 September 2026, automated investigation (AIR) no longer runs as a separate investigation in Defender for Endpoint and can't be triggered manually; Microsoft says to run a full antivirus scan for on-demand investigations.
    - Expect: the scan completes with no new detections.
    - If it finds anything: treat each detection as a new alert with the [malware alert playbook](../01-malware-alert/playbook.md).

---

## 6. Clean or reimage, then release

If you don't hold the rights for a step here (reimage, release from isolation), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

28. **Decide clean or reimage.** Reimage when a downloaded, unknown or stealer payload ran (step 12 or 19), step 13 found hands-on activity, step 14 found connections from inside a signed program, or you can't account for every item the activity created. For High and above, the IR lead decides.
    - Reimaging destroys what is left on the disk. Do it only after steps 9 and 10 are done or recorded as failed, and after the IR lead says no further collection (for example a disk image) is needed.
    - Expect: the decision and who made it in the ticket.

29. **Release only when all of these hold:**
    - Steps 23 to 27 done, every action Success.
    - Every internal target from step 15 checked, and every device in scope from steps 21 and 22 handled.
    - Credentials handled (steps 13, 15, 18 and 19).
    - Indicators in place (step 24), or the IR lead has accepted that a destination can't be blocked.
    - No new alerts, and no network events from the process or to the destination in the Device timeline after step 25, for the period the IR lead sets.
    - For High and above, the IR lead approves the release.
    - If isolation will auto-lift (step 8) before these hold: escalate (isolation will auto-lift before the release criteria hold) before that date.
    - Then: device page → Release from isolation. Tell the customer the outcome.

---

## 7. Close out

- [ ] Classification set: True positive, Informational expected activity (authorised test, sanctioned tool), or False positive (only per Closing as a false positive)
- [ ] Activity class (step 5), process (folder, signer, SHA1, command line) and destinations (IPs, domains, ports, internal targets) documented, with T0
- [ ] IOCs documented (SHA1, IPs, domains, URLs, DNS parent domains) and which were blocked; destinations not blocked and why
- [ ] What was downloaded and whether it ran; how the activity started
- [ ] Hands-on activity, internal movement and data leaving the device: found or not; exposed accounts and what was done for each
- [ ] Devices in scope documented
- [ ] MITRE techniques shown on each alert recorded
- [ ] Findings written up: vector, process, channel, persistence, spread, credentials, remediation, clean or reimage
- [ ] Escalated if any trigger below was hit

---

## Closing as a false positive

Close only with a named, verifiable benign cause, and record it. A known app name, a standard install path, a long-established domain, a CDN, a fixed interval, low volume, or "seen on many devices" is never enough: attacker-installed RMM tools, beacons inside signed programs, downloads by Windows binaries, and C2 over cloud services or aged domains all pass those tests. Spread means scope wider.

Beaconing (class A) and cloud services (class B) close only per their own playbooks: [C2 beaconing](../08-c2-beaconing/playbook.md#closing-as-a-false-positive) and [LOTS & cloud C2](../09-lots-cloud-c2/playbook.md#closing-as-a-false-positive).

| Activity | Close only if all of these hold |
|----------|---------------------------------|
| Named, sanctioned product reaching an external destination (unusual port, RMM) | The product is named, and the customer's asset list, approved-software list or a change record covers it on this device. For an RMM tool, its install time and installing account match that record. `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` with `IsTrusted` true, and it runs from the vendor's install folder. It started no shells or recon commands, and `DeviceImageLoadEvents` shows no DLL that isn't signed by the vendor or Microsoft. The destination is infrastructure the vendor documents for that product, and the Defender IP or URL/domain page shows no malicious verdict and no related alerts. The device has no other alerts since T0 |
| Documented script or download job (class C) | The customer names the script or job, its path and owner, with a change record or documented scheduled job. The command line matches that record. The download host belongs to the customer or a named vendor. Every downloaded file is identified (name, SHA1, what it is) and is what the record says. Not for paste sites, webhook services, Telegram or Discord. The device has no other alerts since T0 |
| Approved internal scanner or management server (class D) | The customer names the product and its source device, and confirms the scan or job window (ticket or schedule). The connections come from that device, inside that window, from that product's process (vendor `Signer`, `IsTrusted` true, vendor install folder). No logon or remote execution on any target beyond what the customer confirms the product does (for example authenticated scanning). The device has no other alerts since T0 |

An authorised red team exercise or test with a ticket: classify as Informational, expected activity, not False positive. The IR lead confirms it.

Never close these yourself, even if a test or a business tool is mentioned: shells or recon commands started by the connecting process; a Cobalt Strike default named pipe; a reverse shell; a downloaded file that ran, outside a documented script or job; a DNS tunnelling pattern; lateral movement from the device; connections from inside a signed or Microsoft process; an RMM tool that isn't on the customer's approved list, or was installed outside a change record; credential access on the device; possible exfiltration; a stealer or unknown payload ran. Escalate; the IR lead confirms any authorised test.

Don't add a suppression or exclusion to stop the alert. Request tuning from whoever owns the detection, with the evidence above.

If any condition can't be confirmed: don't close. Treat it as network activity from a process that isn't a named, sanctioned product, a documented script or an approved scanner: contain (step 7) and escalate.

---

## Escalate if

See also [escalation triggers](../../reference/escalation-triggers.md).

```
Network activity from a process that isn't a named, sanctioned product, a documented script or an approved scanner
Shells or recon commands started by the connecting process
A Cobalt Strike default named pipe (msagent_*, status_*, postex_*, MSSE-*)
A reverse shell (outbound connection from cmd.exe or powershell.exe)
A downloaded file that ran, outside a documented script or job
A DNS tunnelling pattern (long, changing labels under one parent domain)
Internal scanning not explained by the device's role or an approved scanner
Lateral movement from the device (a logon or remote execution on an internal target)
Connections from inside a signed or Microsoft process
An RMM tool that isn't on the customer's approved list, or was installed outside a change record
Credential access on the device (06 playbook step 2)
Possible exfiltration (upload or sync tool, staged archive, or a script host or unknown program reaching a webhook, the Telegram Bot API, Microsoft Graph or storage outside the customer's tenant)
A stealer or unknown payload ran
Same destination or malicious SHA1 on more than one device
Device can't be isolated (pending, offline, domain controller, Tier 0 server, Hyper-V host)
Stop and Quarantine File can't be used or the process still runs, or Defender warns the file is widely used
Destination is a cloud or business service the customer uses
URL content must be fetched to understand it
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
| Collect file / Deep analysis | File page → Collect file / Deep analysis |
| Stop and quarantine file | File page → Stop and Quarantine File |
| IP or domain prevalence | Portal search → IP page / URL or domain page |
| Add indicator | Settings → Endpoints → Indicators |
| Run AV scan | Device page → Actions → Run antivirus scan |
| Check remediation | Defender XDR → Action center |
| Release isolation | Device page → Actions → Release from isolation |
