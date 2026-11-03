# Initial access — playbook

Work top to bottom. Each step is one action, what you should see, and what to do if you don't. Capture evidence before you disable, stop, quarantine, remove, reset or close anything. Queries and background are in the [investigation](investigation.md).

T0 = the first malicious event on the device or account (delivery, first logon or first execution), in UTC. It is not the alert time. You usually start from a later alert, so T0 moves earlier as you trace back. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

If another playbook sent you here to find how the attacker got in (09 step 21): the device is already in hand there. Do steps 12 to 21, plus step 11 for any account you find, then go back to it. Don't repeat containment or removal here.

---

## 1. Triage

1. **Record the incident:** severity, title, how many alerts are grouped. Run [All alerts for this device](../01-malware-alert/investigation.md#all-alerts-for-this-device).
   - Expect: alerts that all belong to one chain.
   - If other categories appear (credential access, lateral movement, C2): record them and treat this as a multi-stage incident. Check them against Escalate if before you continue.
   - If the alert has no device (a cloud sign-in alert): use the [credential compromise playbook](../06-credential-compromise/playbook.md) from its step 1. It scopes and contains the account. Then do steps 16, 19 and 21 here to find how the account was reached, and close out.

2. **Record the device and the account.** Device FQDN, OS and role (workstation, server, domain controller, jump host); the logged-on user's SAM name and UPN; any account used in a logon; the earliest malicious event you can see.
   - Expect: all known.
   - If malicious activity is confirmed on a server, domain controller or jump host: escalate (initial access to a server, domain controller or jump host) and continue.
   - If it is confirmed with an admin or service account: escalate (privileged, admin or service account used for access) and continue.
   - Not confirmed yet: step 21 checks both again.

3. **Set T0** from the Device timeline: the earliest of the delivery, the first logon and the first execution you can see.
   - Expect: T0 at or before the alert time. It may move earlier in steps 12 to 20; rerun the queries when it does.
   - If you can't find it: use the earliest event you have and mark T0 as an estimate.
   - If T0 may be older than 30 days: record that in the ticket and use Sentinel retention and the Device timeline. Don't record "no delivery found" because a query came back empty.

4. **Check whether it was blocked** ([investigation, Step 1](investigation.md#step-1--find-the-earliest-malicious-event)): the alert's detection status, then the device's ASR events from T0.
   - Expect: Prevented or Blocked, and an ASR event ending in `Blocked` if a rule was involved.
   - If Detected, or an ASR event ends in `Audited`: the action ran.
   - Blocked covers that one action. Processes earlier in the chain may have run.

5. **Name the likely vector** ([Common vectors](investigation.md#common-vectors)): email, web download, container, macro, pasted command, remote-access tool, RDP or other remote logon, valid account, public-facing service, supplier, removable media.
   - Expect: a best guess in the ticket, or "unknown". Section 4 confirms it.
   - If RDP or another remote logon is possible: run the [RDP query](investigation.md#rdp-brute-force) now. Step 6 needs the result.
   - If a public-facing service or appliance was exploited (for example a service process started a shell): escalate now (public-facing service or appliance exploited) and go to step 7.
   - If the access came through a supplier's or service provider's account or tool: escalate now (access through a supplier's or service provider's account or tool) and go to step 7. Don't contact the supplier yourself.

6. **Decide the path.** Take the first line that matches.
   - Success from a public IP after failed attempts from that IP: escalate now (RDP exposed to the internet with a successful brute force) and go to step 7. Don't finish tracing first. An attacker with a session may already have other ways back in.
   - Success from a public IP with a documented reason (a named user and source in a ticket or customer documentation): check Closing as a false positive. Otherwise go to step 7.
   - Any other success from a public IP, or a session you can't explain: go to step 7.
   - Failed public-IP logons only, and nothing else on the Device timeline: you don't need to isolate. Do step 28. Tell the customer the host is exposed, and ask them to block the source IPs and close the port or restrict it (step 32). Close out as a true positive.
   - It looks like sanctioned activity (a named product or a documented change): do steps 12 to 20. Close only if every condition in Closing as a false positive holds; otherwise go to step 7.
   - Detection status Prevented or Blocked, no ASR event ends in `Audited`, and the Device timeline shows nothing else from the chain ran after T0 (no other child processes, connections, file writes or registry changes): you don't need to isolate. Do steps 9, 10 and 12 to 29. If any of them finds something, go to step 7. If not: do steps 30 to 36 for the file that started the chain, and close out as a true positive.
   - Anything else, or you can't tell: go to step 7.

---

## 2. Contain the device

If you don't hold the rights for a step here (isolation, investigation package, Live Response), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

7. **Check the device type and network before isolating.**
   - Domain controller, other Tier 0 server, or Hyper-V host: don't isolate it yourself. Escalate now (device can't be isolated), then go to step 9. Isolating a Hyper-V host blocks network traffic to every VM on it.
   - An attacker session may be live on a device you can't isolate: also ask the customer's IT contact now to log the session off and block the source IP on their firewall. Live Response has no built-in command to end a session.
   - Production server: tell the customer contact you are isolating it, and record the time. They lose remote access to it too.
   - Full-tunnel VPN: Microsoft says the device can't reach the Defender service once isolated. Do step 9 first, then step 8.
   - Behind a web proxy (PAC, WPAD or static): use selective isolation. Microsoft warns such devices might not recover from full isolation.
   - Expect: an ordinary workstation or member server. Go to step 8.

8. **Isolate the device** (device page → Isolate device). Isolation keeps the device connected to the Defender service.
   - Expect: the Action center shows the isolation as completed, and Live Response `connections` shows no connection from the source IP.
   - If not (pending or offline): Defender retries for up to three days. Escalate (device can't be isolated) and report the device as not isolated.
   - If a connection from the source IP remains (for example through a selective isolation exclusion): do the same, and ask the customer's IT contact to log the session off.
   - Microsoft states isolation is lifted automatically after seven days (VERIFY (tenant)). Put the date in the ticket and re-check it.

9. **Collect the investigation package** (device page → Collect investigation package). It records autoruns, running processes, network connections, prefetch, scheduled tasks, services, users and groups, and the Security event log.
   - Expect: the package is downloadable from the Action center.
   - If not: collection can fail on low battery or a metered connection. Retry once, then record the failure and continue.
   - Don't restart the device, run an antivirus scan, Stop and Quarantine File, or Live Response `remediate` until this step is done or recorded as failed. Those actions remove the processes, files and registry entries the package would have recorded.

10. **Preserve the delivery file and the payload:** every file the chain ran or wrote that is not a Windows binary, for example the document, ISO, LNK, script, HTML file, DLL or EXE. On the file page, select Collect file if it is shown; Download file instead means Defender already holds a copy. If the file page doesn't offer either, use Live Response `getfile` with the full path.
    - Expect: each file held by Defender or downloaded, with its path and SHA1 in the ticket.
    - If Collect file is disabled: the file hasn't been seen in the past 30 days, or you lack the permission. Record which, and try `getfile`.
    - If there is no file (a remote logon with nothing dropped yet): record that. The package from step 9 is the evidence.
    - Don't open or run any file on your own workstation.

---

## 3. Contain the account

Do step 11 when an account was used to get in (RDP, VPN, a sign-in the user doesn't recognise). Otherwise go to step 12. If you don't hold the rights, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

11. **Contain each account used to get in.** Run steps 13 to 16 of the [credential compromise playbook](../06-credential-compromise/playbook.md): capture evidence, stop on privileged or service accounts, disable, revoke sessions.
    - Expect: exports in the ticket; each account disabled, and its Entra sessions revoked if it has a cloud identity.
    - If 06 step 14 stops you (privileged or service account): escalate (privileged, admin or service account used for access). The IR lead decides.
    - Local account on the device: 06 steps 15 and 16 don't cover it, but its step 14 stop still applies. Record its groups (package, Users and Groups folder), then ask the customer's IT contact to disable it. Don't delete it.
    - Don't reset any password yet. Disabling stops new logons and can be undone. Resets come in step 34, after persistence is recorded.

---

## 4. Find the way in

Do every step whose vector is still possible, and change nothing yet. A proven vector rules out the rest: a confirmed RDP brute force needs only steps 12, 18, 19 and 21, so you reach the persistence check (step 23) quickly. If you don't hold the rights for a step here (Explorer, Entra sign-in logs), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

12. **Trace back to T0** ([investigation, Steps 1 and 2](investigation.md#tracing-back-to-t0)): the Device timeline from the alert backwards, and the files query.
    - Expect: each event from the first one to the alert recorded, with path, SHA1 and command line.
    - If a command line is encoded (`-enc`): decode it with step 6 of the [suspicious process playbook](../02-suspicious-process/playbook.md). If it can't be decoded to readable text: escalate (encoded content that can't be decoded to readable text).
    - If you find an earlier event: move T0, record it, and rerun the query.

13. **Ask the user, through the customer contact,** what they did around T0: what they opened, clicked, pasted or approved, and whether anyone phoned or messaged them first.
    - Expect: the answer in the ticket, or a note that you couldn't reach them. Continue either way.
    - If they took a call or installed something at someone's request: step 20 applies.

14. **Check where the file came from** ([investigation, Step 3](investigation.md#step-3--check-where-the-file-came-from)): `FileOriginUrl`, `FileOriginReferrerUrl` and `FileOriginIP` on the delivery file. Add them to your copy of the query.
    - Expect: the download URL and the page that linked to it recorded.
    - If the columns are empty: record that. It doesn't prove the file was local.
    - Don't browse to the URLs.

15. **Check for a container** ([ISO / IMG containers](investigation.md#iso--img-containers)): run the query, then look for the `.iso`, `.img` or `.vhd` file itself.
    - Expect: no hit, or a hit with the container file and its origin recorded.
    - A hit alone is a lead: mapped drives and USB volumes use the same drive letters. Ask the customer what the drive is.

16. **Check for an email** ([Email delivery](investigation.md#email-delivery)): find the message by recipient, time, attachment name or URL domain.
    - Expect: the message found, or "no delivering email found" recorded.
    - If found: run the [phishing email playbook](../12-phishing-email/playbook.md) for the message and every other recipient, then come back to step 17. It uses its own T0 (delivery of the first message in the campaign); if that is earlier than yours, move yours. It preserves the message before removing it, so don't remove anything from here.
    - This device stays in this playbook, or in the one that sent you here. Where 12 sends it to the malware playbook, still escalate as 12 says, but skip the hand-off. Any other device goes to the [malware playbook](../01-malware-alert/playbook.md) from its step 7.

17. **Check for a macro** ([Macros](investigation.md#macros)) if an Office file is in the chain: run Office spawning shells with T0.
    - Expect: no shell or script host from Office, or an ASR event ending in `Blocked`.
    - If an Office app or `WmiPrvSE.exe` started PowerShell, cmd, mshta or a script host, ASR didn't block it, and the caller is not the customer's confirmed management agent or application: escalate.
    - Record how the macro got past Office's internet-macro block, or "unknown". Don't ask whether the user enabled it: for a file with Mark of the Web there is no Enable content button.

18. **Check remote logons** ([RDP brute force](investigation.md#rdp-brute-force)): the RDP query from step 5 (rerun it if T0 moved), then whether the device is internet-facing.
    - Expect: no success from a public IP.
    - If success after failed attempts from the same IP: escalate (RDP exposed to the internet with a successful brute force). Do steps 7 to 11 if they aren't done.
    - If success with few or no failures: treat the account as stolen until shown otherwise. Do step 19, and steps 7 to 11 if they aren't done.
    - If a logon succeeded: list what ran in the session (`ProcessRemoteSessionIP`) and record it for step 22.
    - An empty result isn't clean. Read the limits in the investigation. No "internet facing" tag doesn't prove the device isn't exposed; ask the customer whether RDP should be reachable from the internet.

19. **Check the account** ([Valid accounts](investigation.md#valid-accounts-and-remote-services)): Entra sign-ins since T0 − 14 days, device logons, and the VPN or gateway logs from the customer.
    - Expect: no successful sign-in from an unfamiliar IP or country.
    - If there is one: ask the user through the customer contact. Unless they confirm travel or VPN, escalate (valid account used from a new country or unfamiliar IP: possible credential compromise) and do step 11 for that account. Write "possible" in the ticket until it is confirmed.

20. **Check the other vectors.**
    - Pasted command (a browser or `explorer.exe` starting a shell with a URL or encoded arguments): use the [ClickFix investigation](../13-clickfix/investigation.md) for scope, and continue here.
    - [Remote-access tool](investigation.md#remote-access-tools): ask the customer whether it is on their approved list and was installed under a change record. If not, or no answer: escalate (remote-access (RMM) tool not on the customer's approved list, or installed outside a change record). A vendor signature is not evidence it is benign.
    - Removable media: ask the customer what the drive is and who used it.
    - Public-facing service or supplier (escalated in step 5): ask the customer's IT contact for the appliance, application or supplier logs from T0 − 14 days.
    - Expect: each one ruled out or recorded.

21. **Record the vector:** T0, delivery method, and the full chain (for example email → ISO → LNK → PowerShell).
    - Expect: all in the ticket.
    - If none is found: record the vector as unknown. If attacker code ran or an account was used: escalate (delivery vector can't be found, and attacker code ran or an account was used). The way in may still be open.
    - Check step 2 again: if the activity is now confirmed on a server, domain controller or jump host, or with an admin or service account, escalate as it says.

---

## 5. Check what the attacker did

If you don't hold the Live Response role, request it from the customer's IT contact, record the time of the request, and use the package meanwhile.

22. **Check whether anything is still running or connecting.** Use the package's Processes and Network connections folders, then Live Response `processes` and `connections` for the current state.
    - Expect: nothing from the chain running; no connections to the IPs or domains from steps 12 and 14.
    - If C2 looks live (connections to an IOC still happening): escalate now.
    - Record what is still running and its PID; step 30 needs it.

23. **Check persistence** with the [persistence playbook](../04-persistence-detected/playbook.md): run keys, scheduled tasks, services, startup folders and WMI. Compare with the package's Autoruns, Scheduled tasks and Services.
    - Expect: nothing the attacker added.
    - If found: record each item. Don't remove anything yet; that is step 33. If the device isn't isolated: go to step 7 first.

24. **Check identity:** lsass access, credential-tool keywords, new accounts and lateral movement. Use step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md), and its step 12 for accounts the attacker created.
    - Expect: no hits.
    - If any hit: escalate (any hit in step 2 of the credential compromise playbook), and follow the 06 playbook from step 2 for this device.
    - New local accounts: record them. Don't remove anything yet; that is step 33.

25. **If an unknown payload or stealer ran:** escalate (infostealer or unknown payload executed), and run steps 11 and 17 of the [malware alert playbook](../01-malware-alert/playbook.md) for it.

---

## 6. Scope

Spread is a reason to scope wider, never a reason to close. Queries are in [Spread](investigation.md#spread).

26. **Search for the payload** (hash sweep), with the SHA1 of each file from steps 10 and 12.
    - Expect: only this device.
    - If other devices, or more than one user ran it: escalate (same malicious hash or delivery URL on more than one device, or more than one user ran the same payload). Run steps 2 to 25 for each device where it ran.
    - Zero rows doesn't prove no spread. Check the file page's "Observed in organization" tab.

27. **Search for the delivery source:** the domain from step 14, across `FileOriginUrl` and `FileOriginReferrerUrl`.
    - Expect: only this device.
    - If other devices: escalate (same malicious hash or delivery URL on more than one device). Check each file with steps 4 to 6.

28. **Search for the source IP** from step 18 across the estate.
    - Expect: only this device.
    - If `Succeeded` on another device: escalate (same source IP logged on to more than one device), add it to scope and run steps 2 to 25 for it.
    - If failures only on other devices: record them. Those hosts are exposed; tell the customer.

29. **Check the accounts** from steps 11 and 19 on other devices. Use step 9 of the [credential compromise playbook](../06-credential-compromise/playbook.md).
    - Expect: only devices the account has a documented reason to use.
    - If not: lateral movement. Escalate (account logged on to a device it has no documented reason to use), and run steps 2 to 25 for each new device.

---

## 7. Stop, block, remove

Only after step 9 is done (or recorded as failed) and step 10 is done on every device in scope. If you don't hold the rights for a step here, request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

30. **Stop what is still running** (step 22).
    - Nothing from the chain running: go to step 31.
    - If a changed legitimate entry recorded in step 23 (for example Winlogon `Userinit`, or an existing service's `ImagePath`) points to the file: don't run Stop and Quarantine File yourself. Microsoft doesn't say which registry data it deletes. Ask the IR lead first.
    - A payload not signed by Microsoft or a trusted non-Microsoft publisher: file page → Stop and Quarantine File. It stops its running processes, quarantines the file and deletes persistent data such as registry keys, on every device where it was seen in the last 30 days.
      - Expect: the Action center shows Success for each device.
      - If Failed: record the reason. If Pending: the device is offline; the action times out after three days.
      - If Defender warns that the file is widely used in the organization: cancel and escalate (Stop and Quarantine File can't be used on a running process (Microsoft or trusted-publisher signed), or Defender warns the file is widely used). It may be a business application.
      - A quarantined file can be restored if it turns out to be clean.
    - A Windows binary or another file signed by Microsoft or a trusted publisher (for example `powershell.exe`, or a remote management agent): Stop and Quarantine File can't be used on it. Don't use Live Response `remediate` on the process either: on a process it stops the process and deletes the image file. Escalate (Stop and Quarantine File can't be used on a running process); the IR lead decides how to stop it. The device stays isolated meanwhile.

31. **Block the IOCs** with Defender for Endpoint indicators (Settings → Endpoints → Indicators): the delivery URL and domain and the page that linked to it (step 14), the external IPs, URLs and domains from steps 12 and 22, and the SHA1 of each malicious PE file. Mail blocks are in the phishing email playbook.
    - Never add a block indicator for the hash of a Windows binary or another legitimate signed tool. A file indicator stops the file being read, written or executed on every device in its scope.
    - File hashes: PE files only (`.exe`, `.dll`), and Defender Antivirus must be in active mode. An ISO, LNK, Office document, script or HTML file can't be blocked by hash; block its delivery URL or domain. Blocks typically apply within 15 minutes, 30 on average, and can take over 2 hours.
    - IPs and URLs: external IPs only, one address per indicator (no ranges). Outside Microsoft Edge, blocking needs Network Protection in block mode. An HTTPS full URL path can be blocked only in Edge; other browsers block by domain, and only with QUIC and Encrypted Client Hello disabled. Blocks can take up to 48 hours; most apply within 2 hours.
    - Don't count an IP indicator as blocking inbound RDP. Microsoft describes Network Protection as preventing connections to malicious sites, and doesn't say it stops inbound connections. That block is step 32.
    - Don't block a domain the customer uses for business (for example a cloud storage or code-hosting site). Block the full URL (Edge only) or escalate (a domain to block is one the customer uses for business).
    - Expect: each indicator listed with its expiry.
    - A blocked connection can still appear as `ConnectionSuccess` in network events. Check the alerts queue for the block, not the connection log.

32. **Get the way in closed.** If the attacker got in, do this only after steps 9 and 23: closing a port doesn't remove what they already left, and it tells them you've seen them.
    - RDP or other remote access: ask the customer's IT contact to block the source IPs on their firewall, and to close the port or restrict it to known IPs.
    - Email: confirm the phishing email playbook's blocks and removal are done.
    - Web download: step 31 covers it. Tell the customer if Network Protection isn't in block mode.
    - Public-facing service or supplier access: the IR lead decides.
    - Expect: a change reference in the ticket, or the reason it can't be done.

33. **Remove persistence and remaining files** found in steps 10, 12 and 23, using the [persistence playbook](../04-persistence-detected/playbook.md). A script or other payload that Stop and Quarantine didn't cover: Live Response `remediate file` with its full path deletes it. Do this only once step 10 holds a copy.
    - Expect: each item removed and recorded.
    - Never point `remediate` at a Windows binary.
    - If the persistence is a changed legitimate entry, not a new one (for example Winlogon `Userinit`, `Shell` or `Notify`, or an existing service's `ImagePath`): don't delete the value or the key. Escalate; the IR lead restores the original data.
    - Accounts the attacker created: disable them; delete only with the IR lead's agreement.

34. **Finish the accounts from step 11.** Run steps 17 to 20 of the [credential compromise playbook](../06-credential-compromise/playbook.md): remove what the attacker added, reset from a clean device, block legacy auth if it was used, re-enable. Re-enabling is step 20: you do it, or the customer's IT contact if you don't hold the right, once that step's conditions hold.
    - Local account: ask the customer's IT contact to reset it from a clean device, and to leave it disabled if nobody needs it.
    - Expect: every account from steps 11, 19 and 24 reset or recorded as not yet reset, with the reason.

35. **Confirm every action in the Action center** (History tab): isolation, package, quarantine, Live Response actions.
    - Expect: every action Success.
    - If an action failed or an item from steps 10, 12 and 23 has no action: do it from the device or file page, or with Live Response `remediate` (not on Windows binaries). Record each.
    - If it still fails: escalate (remediation failed and can't be completed). Don't release the device.

36. **Run a full antivirus scan** (device page → Run antivirus scan → Full). From 1 September 2026 Microsoft no longer runs automated investigation (AIR) as a separate experience for Defender for Endpoint alerts; for on-demand investigations it says to run a full antivirus scan.
    - Expect: the scan completes with no new detections.
    - If it finds anything: escalate (full antivirus scan after removal finds new detections), treat each detection as a new alert, and go back to step 12 for it.

---

## 8. Clean or reimage, then release

If you don't hold the rights to release the device, request it from the customer's IT contact once the IR lead or the criteria in step 38 allow it.

37. **Decide clean or reimage.** Reimage when an unknown or stealer payload ran, someone had hands-on access (any attacker RDP session counts), or you can't account for every item the attacker created. For High and above, the IR lead decides.
    - Reimaging destroys what is left on the disk. Do it only after steps 9 and 10 are done or recorded as failed, and after the IR lead says no further collection (for example a disk image) is needed.
    - Expect: the decision and who made it in the ticket.

38. **Release only when all of these hold:**
    - Steps 30 to 36 done, every action Success.
    - Credentials handled (steps 11, 24, 25 and 34).
    - Indicators in place (step 31), and the way in closed (step 32).
    - No new alerts and no connections to the IOCs while isolated, for the period the IR lead sets.
    - For High and above, the IR lead approves the release.
    - If isolation will auto-lift (step 8) before these hold: escalate (isolation will auto-lift before the release criteria hold) before that date.
    - Then: device page → Release from isolation. Tell the customer the outcome.

---

## 9. Close out

- [ ] Classification set: True positive, Informational expected activity (authorised test, sanctioned tool), or False positive (only per Closing as a false positive)
- [ ] T0 and delivery method documented, or recorded as unknown with the reason
- [ ] Full delivery chain documented (for example email → user opened ISO → LNK → PowerShell)
- [ ] Other affected users, accounts and devices documented
- [ ] IOCs documented (SHA1, IPs, domains, URLs) and which were blocked
- [ ] How the way in was closed, or why it wasn't, and what the customer was told
- [ ] Findings written up: vector, what ran, persistence, spread, credentials, remediation, clean or reimage
- [ ] Escalated if any trigger below was hit

---

## Closing as a false positive

Close only with a named, verifiable benign cause, and record it. "Nothing else found", low volume, or "seen on many devices" is never enough; spread means scope wider. A vendor signature isn't enough either: a remote-access tool an attacker installed is signed by its vendor too.

Never close these yourself, even if a test or an admin is mentioned: any item in Escalate if below. Escalate; the IR lead confirms any authorised test.

| Signal | Close only if all of these hold |
|--------|---------------------------------|
| Logon from a public IP | The customer names the user and the source (office, partner or home IP) in a ticket or documentation. The user confirms the logon at that time. No failed attempts from that IP before the success. Everything that ran in the session is explained |
| Sign-in from a new country | The user confirms travel through the customer contact, or one location is a documented corporate VPN or proxy egress (customer documentation or a named location in Entra). No Entra ID Protection detection for the account |
| Process from a drive D: to Z: | The customer names the drive (mapped share or USB). The file is software they deployed on purpose (asset list or change record). `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` with `IsTrusted` true. No `.iso`, `.img` or `.vhd` file arrived before it |
| Downloaded file | The file is software the customer deployed on purpose: name the product and the asset list or change record. `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` with `IsTrusted` true. Nothing else in the chain is suspicious (step 12) |
| Remote-access tool | The product is on the customer's approved list. A change record or ticket explains this install, its time and its installer. The user confirms nobody unknown asked them to install it or join a session |

Sanctioned software or an authorised test that was detected correctly: classify as Informational, expected activity, not False positive.

If any condition can't be confirmed: don't close. Escalate.

---

## Escalate if

See also [escalation triggers](../../reference/escalation-triggers.md).

```
RDP exposed to the internet with a successful brute force
Valid account used from a new country or unfamiliar IP: possible credential compromise, unless the user confirms travel or VPN
Initial access to a server, domain controller or jump host
Privileged, admin or service account used for access
Public-facing service or appliance exploited
Access through a supplier's or service provider's account or tool
Remote-access (RMM) tool not on the customer's approved list, or installed outside a change record
Same malicious hash or delivery URL on more than one device, or more than one user ran the same payload
Same source IP logged on to more than one device
Account logged on to a device it has no documented reason to use
Any hit in step 2 of the credential compromise playbook
Office app or WmiPrvSE.exe started PowerShell, cmd, mshta or a script host, ASR didn't block it, and the caller is not the customer's confirmed management agent or application
Encoded content that can't be decoded to readable text
Infostealer or unknown payload executed
C2 looks live (connections to an IOC still happening)
Delivery vector can't be found, and attacker code ran or an account was used
Device can't be isolated (pending, offline, domain controller, other Tier 0 server, Hyper-V host)
Stop and Quarantine File can't be used on a running process (Microsoft or trusted-publisher signed), or Defender warns the file is widely used
A domain to block is one the customer uses for business
Persistence is a changed legitimate entry, not a new one (for example Winlogon Userinit, Shell or Notify, or an existing service's ImagePath)
Remediation failed and can't be completed
Full antivirus scan after removal finds new detections
Isolation will auto-lift before the release criteria hold
Any escalation trigger in a playbook this one hands you to (04, 06, 12)
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
