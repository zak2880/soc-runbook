# Persistence detected — playbook

Work top to bottom. Each step is one action, what you should see, and what to do if you don't. Record every persistence item before you stop, quarantine, remove or delete anything. Queries and background are in the [investigation](investigation.md).

T0 = the first malicious event: the creation of the persistence item, the first run of its target, or the start of the process that created it, whichever is earliest, in UTC. It is not the alert time. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention or the device itself.

**Arriving from another playbook:**
- **From a "Check persistence" step** (01 step 14, 02 step 16, 08 step 14, 09 step 16): the device is already isolated, the investigation package collected, the sample preserved and T0 set. Don't repeat steps 1 to 7. Do steps 8 to 13, escalating where they say, then go back to your playbook (it does the identity and scope checks). Don't remove anything; your playbook's removal step sends you back here.
- **From a "Remove persistence" step** (01 step 23, 02 step 22, 08 step 21, 09 step 24): Stop and Quarantine File and the indicators are done there. Start at step 19, then do steps 20 and 21 and go back to your playbook for the scan, reimage and release. Every item must already be recorded and classified as in steps 10 and 11. If one isn't, do steps 10 and 11 for it first.
- **From the credential compromise playbook** (06 step 22): the device may not be isolated or packaged. Start at step 1.

---

## 1. Triage

1. **Record the incident and the item.** Device FQDN and OS; the logged-on user's SAM name and UPN; the alert. For the persistence item: mechanism (Run key, Winlogon, scheduled task, service, startup folder, WMI), full location (key and value name, task path, service name, file path, or WMI object names), data or command line, target file path and SHA1, creation time, creating process and its account. Take them from the alert, the Device timeline or the query row.
   - Expect: all known.
   - If the creating process or account is missing: find them in the Device timeline at the creation time.

2. **Set T0** from the Device timeline: the earliest of the item's creation, the target's first run, and the start of the process that created it.
   - Expect: T0 at or before the alert time. Persistence can be created weeks before the alert. The queries search T0 − 14 days to T0 + 2 days, so take T0 from the item, not the alert ([What the queries don't show](investigation.md#what-the-queries-dont-show)).
   - If you can't find it: use the item's creation time and mark T0 as an estimate.

3. **Check the item for an immediate escalation.**
   - WMI event subscription found (any)
   - Hidden scheduled task (task key with no `SD` value, or a task in telemetry or `C:\Windows\System32\Tasks\` that the task list doesn't show)
   - Persistence is a changed legitimate entry, not a new one (for example Winlogon `Userinit`, `Shell` or `Notify`, or an existing service's `ImagePath`)
   - Persistence created from another device (for example `psexesvc`, or `schtasks` with `/s`)
   - Persistence on a domain controller or other Tier 0 server
   - Expect: none.
   - If any: escalate now and go to step 5. Don't remove or change the item.

4. **Decide the path.**
   - Every condition in [Closing as a false positive](#closing-as-a-false-positive) holds: close per that section.
   - Anything else, or you can't tell: go to step 5. Persistence the attacker added means attacker code already ran on the device.

---

## 2. Contain the device

If you don't hold the rights for a step here (isolation, investigation package, Live Response), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

5. **Check the device type and network before isolating.**
   - Domain controller, other Tier 0 server, or Hyper-V host: don't isolate it yourself. Escalate now (device can't be isolated). Isolating a Hyper-V host blocks network traffic to every VM on it.
   - Production server: tell the customer contact you are isolating it, and record the time.
   - Full-tunnel VPN: Microsoft says the device can't reach the Defender service once isolated. Do step 7 first, then step 6.
   - Behind a web proxy (PAC, WPAD or static): use selective isolation. Microsoft warns such devices might not recover from full isolation.
   - Expect: an ordinary workstation or member server. Go to step 6.

6. **Isolate the device** (device page → Isolate device). Isolation keeps the device connected to the Defender service. It doesn't stop a task or subscription from firing on the device.
   - Expect: the Action center shows the isolation as completed.
   - If not (pending or offline): Defender retries for up to three days. Escalate (device can't be isolated) and report the device as not isolated.
   - Microsoft states isolation is lifted automatically after seven days (VERIFY (tenant)). Put the date in the ticket and re-check it.

7. **Collect the investigation package** (device page → Collect investigation package). It records the autostart registry entries (Autoruns folder), scheduled tasks, services, running processes, network connections and the Security event log.
   - Expect: the package is downloadable from the Action center.
   - If not: collection can fail on low battery or a metered connection. Retry once, then record the failure and continue.
   - Don't restart the device, run an antivirus scan, Stop and Quarantine File, or Live Response `remediate` until this step is done or recorded as failed. Those actions remove the processes, files and registry entries the package would have recorded.

---

## 3. Find and record every item

If you don't hold the Live Response role, request it from the customer's IT contact, record the time of the request, and use the package meanwhile.

8. **Read what is configured on the device.** The package's Autoruns, Scheduled tasks and Services; then Live Response `persistence`, `scheduledtasks`, `services` and `startupfolders` ([Read the device first](investigation.md#read-the-device-first)). These are read-only and cover more locations than the queries.
   - Expect: the alert item (if the alert named one), and nothing else you can't explain.
   - If Live Response isn't available (not enabled, no role, session fails): record why and use the package.
   - Any other unexplained entry: add it to the list and record it in step 10.

9. **Run the queries with T0** ([KQL queries](investigation.md#kql-queries)); replace `PASTE_TIME_UTC` and `HOSTNAME` in each. Run keys, scheduled tasks, services, WMI and startup folders. Then check the other autostart keys and the three Winlogon values ([Registry Run keys](investigation.md#registry-run-keys), [Winlogon](investigation.md#winlogon)).
   - Expect: only items already on your list.
   - An empty result is not a clean result ([What the queries don't show](investigation.md#what-the-queries-dont-show)). If the services query has no rows: run the check in its VERIFY note, and record "services not covered by telemetry" if this device has none in 30 days.
   - New items: add them and record them in step 10.

10. **Record each item before anything is removed.** For every item: mechanism; full location; current data (Live Response `registry <key>\\<value>`); the data before a change (`PreviousRegistryValueData`); target path and SHA1 (`fileinfo`); creation or change time; creating process, its command line and account ([Record before you remove](investigation.md#record-before-you-remove)).
    - Preserve: each target file that isn't a Windows binary (file page → Collect file, or Live Response `getfile` with the full path); each scheduled task's XML file from `C:\Windows\System32\Tasks\` (`getfile`); for a shortcut, the shortcut and the file it starts.
    - If a command line is encoded (`-enc`): decode it with step 6 of the [suspicious process playbook](../02-suspicious-process/playbook.md). If it can't be decoded to readable text: escalate (encoded content that can't be decoded to readable text).
    - Expect: each item in the ticket, with its files held by Defender or downloaded.
    - If a file can't be preserved (Collect file disabled, `getfile` fails): record why. Don't remove that item until the IR lead agrees; escalate (a target file can't be preserved before removal).

11. **Classify each item.**
    - New entry the attacker added (a new Run value, task, service or startup file): removed in step 19.
    - Changed legitimate entry (Winlogon `Userinit`, `Shell` or `Notify`; an existing service's `ImagePath`; an existing task's action; any value whose `PreviousRegistryValueData` was legitimate): escalate (persistence is a changed legitimate entry, not a new one). Don't delete the value or the key. The IR lead restores the original data from step 10.
    - WMI subscription: escalate (WMI event subscription found). Removal needs a script; the IR lead does it.
    - Scheduled task: check its `TaskCache\Tree` key with Live Response `registry` for an `SD` value ([Scheduled tasks](investigation.md#scheduled-tasks)). No `SD` value: escalate (hidden scheduled task).
    - Remote-access (RMM) tool: ask the customer whether it is on their approved list and was installed under a change record. If not, or no answer: escalate (remote-access (RMM) tool not on the customer's approved list, or installed outside a change record).
    - Task or service that runs as SYSTEM (read the run-as account in the task XML, the package CSVs or the Live Response output; for a service, LocalSystem): if its target is unsigned or in a user-writable folder, escalate (SYSTEM-context task or service whose target is unsigned or in a user-writable folder).
    - New service whose image file is a Windows binary (for example `cmd.exe` or `svchost.exe`): escalate (new service whose image file is a Windows binary). Step 19 can't remove it safely: `remediate` on a service deletes its image file.
    - Created from another device (the creating process in step 10 is `psexesvc`, or the other device ran `schtasks` with `/s`): escalate (persistence created from another device). Step 16 scopes it.
    - Target is a Windows binary (`powershell.exe`, `rundll32.exe`, `mshta.exe`): the payload is its script, DLL, URL or encoded argument. Record that file; never the Windows binary.
    - Expect: a class for each item in the ticket.

12. **Check whether it is running or firing** ([Is it running?](investigation.md#is-it-running)): the package's Processes and Network connections, then Live Response `processes` and `connections`, then the target's process events since T0.
    - Expect: the target not running, and no connections to the IPs or domains from steps 10 and 13.
    - Record what is running and its PID; step 17 needs it.
    - If C2 looks live (connections to an IOC still happening): escalate now.

13. **Identify the target.** Read the detection name and enrich the SHA1 with the [threat intel enrichment guide](../../reference/threat-intel-enrichment.md). Look up hashes, IPs and domains; don't upload the file to public services.
    - Expect: a payload type recorded as known, or unknown.
    - If it is a credential dumper, C2 stager, infostealer or unknown payload: escalate (persistence target is a credential dumper, C2 stager, infostealer or unknown payload). Run steps 11 and 17 of the [malware alert playbook](../01-malware-alert/playbook.md) for it.

14. **Check identity:** lsass access, credential-tool keywords, new accounts, lateral movement. Use step 2 of the [credential compromise playbook](../06-credential-compromise/playbook.md), and its step 12 for accounts the attacker created.
    - Expect: no hits.
    - If any hit: escalate (any hit in step 2 of the credential compromise playbook), and follow the 06 playbook from step 2 for this device.

---

## 4. Scope

15. **Search for the same persistence on other devices** ([Scope across the estate](investigation.md#scope-across-the-estate)): rerun each query that found an item without its `DeviceName` line, on the value name, task name, service name or command-line fragment; and the hash sweep with each target SHA1.
    - Expect: only this device.
    - If other devices: escalate (same persistence on more than one device). Run steps 1 to 14 for each.
    - Zero rows don't prove no spread.

16. **Find what created it.** Trace the creating process from step 10 in the Device timeline ([process guide](../02-suspicious-process/investigation.md)).
    - Expect: the process chain and the delivery vector recorded, or the vector recorded as unknown.
    - If it was created from another device (for example `psexesvc`, or `schtasks` with `/s` on the other device): escalate (persistence created from another device). That device is in scope; run this playbook for it.
    - If a downloaded or emailed file started the chain: use step 20 of the [malware alert playbook](../01-malware-alert/playbook.md) to find how it arrived.

---

## 5. Stop, block, remove

Only after step 7 is done (or recorded as failed) and steps 10 and 11 are done for every item, on every device in scope. If you don't hold the rights for a step here (Stop and Quarantine File, indicators, Live Response advanced commands such as `remediate`), request it from the customer's IT contact, record the time of the request, and continue with the steps you can do.

17. **Stop what is still running** (step 12).
    - Nothing running: go to step 18.
    - If a changed legitimate entry from step 11 (for example Winlogon `Userinit`) points to the target: don't run Stop and Quarantine File yourself. Microsoft doesn't say which registry data it deletes. Ask the IR lead first.
    - A target not signed by Microsoft or a trusted non-Microsoft publisher: file page → Stop and Quarantine File. It stops its running processes, quarantines the file and deletes persistent data such as registry keys, on every device where it was seen in the last 30 days. Step 10 must be done first; afterwards, record which items it removed.
      - Expect: the Action center shows Success for each device.
      - If Failed: record the reason. If Pending: the device is offline; the action times out after three days.
      - If Defender warns that the file is widely used in the organization: cancel and escalate (Stop and Quarantine File can't be used, or Defender warns the file is widely used). It may be a business application.
      - A quarantined file can be restored if it turns out to be clean.
    - A Windows binary or another file signed by Microsoft or a trusted publisher (`powershell.exe`, `rundll32.exe`, a remote management agent): Stop and Quarantine File can't be used on it. Don't use Live Response `remediate` on the process either: on a process it stops the process and deletes the image file. Escalate (Stop and Quarantine File can't be used); the IR lead decides how to stop it. The device stays isolated meanwhile.
    - A removed scheduled task keeps running on its triggers until the device restarts or the `svchost.exe` process running it ends. Removing the item doesn't replace this step.

18. **Block the IOCs** with Defender for Endpoint indicators (Settings → Endpoints → Indicators): the SHA1 of each malicious target from step 10, and the external IPs, URLs and domains from steps 12 and 13.
    - Never block the hash of a Windows binary or another legitimate signed tool. A file indicator stops the file being read, written or executed on every device in its scope.
    - File hashes: PE files only (`.exe`, `.dll`), and Defender Antivirus must be in active mode. A script can't be blocked by hash. Blocks typically apply within 15 minutes, 30 on average, and can take over 2 hours.
    - IPs and URLs: external IPs only, one address per indicator (no ranges). Outside Microsoft Edge, blocking needs Network Protection in block mode. An HTTPS full URL path can be blocked only in Edge; other browsers block by domain, and only with QUIC and Encrypted Client Hello disabled. Blocks can take up to 48 hours; most apply within 2 hours.
    - Don't block a domain the customer uses for business. Block the full URL (Edge only) or escalate (a domain to block is one the customer uses for business).
    - Expect: each indicator listed with its expiry. A blocked connection can still appear as `ConnectionSuccess` in network events; check the alerts queue for the block.

19. **Remove each new entry** classed in step 11. Only items recorded as in step 10, with their files preserved.
    - First check whether Stop and Quarantine File already removed it (Action center, then Live Response `registry`, `scheduledtasks`, `services` or `startupfolders`). If it is gone: record that and move to the next item.
    - Run key value: remove the value only, never the key; other programs' entries share it. Use Live Response `remediate` on the registry entry (`help remediate` shows the syntax). VERIFY (tenant) on a test device that it removes only the named value before you use it on a Run key. A per-user (HKCU) value: Microsoft lists the `HKEY_USERS` hive as not supported by `remediate`, and whether a Live Response session sees the user's HKCU is VERIFY (tenant). Request removal of that one value from the customer's IT contact.
    - Scheduled task: Live Response `remediate` on the task removes it. Then check step 12 again: a running instance doesn't stop with the task. If it still runs, go back to step 17.
    - New service: Live Response `remediate` on the service stops it and deletes its image file. Use it only when the image file is the attacker's file from step 10 (step 11 escalates a Windows binary image). Microsoft doesn't say it deletes the service entry; check `services` afterwards, and if the entry remains, request its deletion from the customer's IT contact.
    - Startup folder item: Live Response `remediate` on it deletes the file. Remove the file a shortcut started too.
    - Each target file not already quarantined (script, DLL, EXE): Live Response `remediate file` with its full path deletes it. Never point `remediate` at a Windows binary.
    - Never remove these yourself: a changed legitimate entry, a WMI subscription, a hidden task, an unapproved RMM tool. Step 11 escalated them; the IR lead restores or removes them. Never delete a Winlogon or service value or key.
    - Accounts the attacker created: disable them; delete only with the IR lead's agreement.
    - Removed the wrong item: Live Response `undo` restores a remediated registry entry, scheduled task or file.
    - Expect: each item removed, with the command and time in the ticket.

20. **Confirm every action in the Action center** (History tab): isolation, package, quarantine, indicators, Live Response commands.
    - Expect: every action Success.
    - If an action failed or an item from step 19 has no action: do it again or request it from the customer's IT contact. Record each.
    - If it still fails: escalate (remediation failed and can't be completed). Don't release the device.

21. **Confirm it stays gone.** At the end of the period the IR lead sets, rerun the queries from step 9 with T0 set to the removal time and read only rows after it. Then repeat Live Response `persistence` and `scheduledtasks`, and the `SD` check for each task from step 11.
    - Expect: no new write event for any removed item, and nothing new in the on-device lists. A RunOnce value deletes itself when it runs, so absence alone proves nothing; look for a new write.
    - Restart the device only with the IR lead's agreement and after step 7; a restart ends running processes. Repeat this step after it.
    - If anything comes back: escalate (persistence comes back after removal). Something you haven't found is re-creating it.

22. **Run a full antivirus scan** (device page → Run antivirus scan → Full). From 1 September 2026 Microsoft no longer runs automated investigation (AIR) as a separate experience for Defender for Endpoint alerts; for on-demand investigations it says to run a full antivirus scan.
    - Expect: the scan completes with no new detections.
    - If it finds anything: escalate (full antivirus scan after removal finds new detections), treat each detection as a new alert with the [malware alert playbook](../01-malware-alert/playbook.md).

---

## 6. Clean or reimage, then release

If you don't hold the rights to release the device, request it from the customer's IT contact once the IR lead or the criteria in step 24 allow it.

23. **Decide clean or reimage.** Reimage when the target was a credential dumper, C2 stager, infostealer or unknown payload; more than one mechanism was found; step 11 escalated a changed legitimate entry, WMI subscription or hidden task; someone had hands-on access; or you can't account for every item. Clean only when the payload is identified and every item it created is removed. For High and above, the IR lead decides.
    - Reimaging destroys what is left on the disk. Do it only after steps 7 and 10 are done or recorded as failed, and after the IR lead says no further collection (for example a disk image) is needed.
    - Expect: the decision and who made it in the ticket.

24. **Release only when all of these hold:**
    - Steps 17 to 22 done, every action Success.
    - Credentials handled (step 14).
    - Indicators in place (step 18).
    - Step 21 shows nothing came back, for the period the IR lead sets.
    - For High and above, the IR lead approves the release.
    - If isolation will auto-lift (step 6) before these hold: escalate (isolation will auto-lift before the release criteria hold) before that date.
    - Then: device page → Release from isolation. Tell the customer the outcome.

---

## 7. Close out

- [ ] Classification set: True positive, Informational expected activity (sanctioned software or authorised test), or False positive (only per Closing as a false positive)
- [ ] Every item documented: mechanism, location, data before and after, target and SHA1, creator, class (step 10, 11)
- [ ] What was removed, by which command, and what the IR lead restored (step 19)
- [ ] Step 21 result recorded
- [ ] IOCs documented (SHA1, IPs, domains, URLs) and which were blocked
- [ ] Findings written up: how it got there, what it ran, spread, credentials, remediation, clean or reimage
- [ ] Escalated if any trigger below was hit

---

## Closing as a false positive

Close only with a named, verifiable benign cause, and record it. "Nothing else found", low volume, or "seen on many devices" is never enough; spread means scope wider. A signature or a `Program Files` path isn't enough either: a remote-access tool an attacker installed is signed by its vendor too. All of these must hold:

- The entry belongs to software the customer deployed on purpose: name the product, and the asset list or change record that covers this device.
- The creating process is that product's installer or the customer's management agent, and the customer confirms the installation or deployment job. An installer or agent process name alone (`msiexec.exe`, `ccmexec.exe`, `IntuneManagementExtension.exe`) isn't evidence; confirm the package or job with the customer.
- The full command line or data, decoded if encoded, runs a file in the product's install folder. No script, DLL, URL or encoded argument in a user-writable folder.
- `DeviceFileCertificateInfo` for the target's SHA1 shows the vendor as `Signer` with `IsTrusted` true.
- A remote-access tool is on the customer's approved list and was installed under a change record.
- No item in Escalate if applies.

Sanctioned software or an authorised test that was detected correctly: classify as Informational, expected activity, not False positive.

Never close these yourself, even if a tool or a test is mentioned: any item in Escalate if below. Escalate; the IR lead decides.

If any condition can't be confirmed: don't close. Escalate.

---

## Escalate if

See also [escalation triggers](../../reference/escalation-triggers.md).

```
WMI event subscription found (any)
Hidden scheduled task (task key with no SD value, or a task in telemetry or C:\Windows\System32\Tasks\ that the task list doesn't show)
Persistence is a changed legitimate entry, not a new one (for example Winlogon Userinit, Shell or Notify, or an existing service's ImagePath)
Persistence created from another device (for example psexesvc, or schtasks with /s)
Persistence on a domain controller or other Tier 0 server
Remote-access (RMM) tool not on the customer's approved list, or installed outside a change record
SYSTEM-context task or service whose target is unsigned or in a user-writable folder
New service whose image file is a Windows binary
Persistence target is a credential dumper, C2 stager, infostealer or unknown payload
Encoded content that can't be decoded to readable text
A target file can't be preserved before removal
C2 looks live (connections to an IOC still happening)
Any hit in step 2 of the credential compromise playbook
Same persistence on more than one device
Device can't be isolated (pending, offline, domain controller, other Tier 0 server, Hyper-V host)
Stop and Quarantine File can't be used, or Defender warns the file is widely used
A domain to block is one the customer uses for business
Remediation failed and can't be completed
Persistence comes back after removal
Full antivirus scan after removal finds new detections
Isolation will auto-lift before the release criteria hold
```

---

## Actions — Defender XDR quick reference

| Action | Where |
|--------|-------|
| Isolate device | Device page → Actions → Isolate device |
| Collect investigation package | Device page → Actions → Collect investigation package |
| Live Response (`persistence`, `scheduledtasks`, `services`, `startupfolders`, `registry`, `fileinfo`, `getfile`, `processes`, `connections`, `remediate`, `undo`) | Device page → Actions → Initiate Live Response session |
| Collect file | File page → Collect file |
| Stop and quarantine file | File page → Stop and Quarantine File |
| Add indicator | Settings → Endpoints → Indicators |
| Run AV scan | Device page → Actions → Run antivirus scan |
| Check actions | Defender XDR → Action center (History) |
| Release isolation | Device page → Actions → Release from isolation |
