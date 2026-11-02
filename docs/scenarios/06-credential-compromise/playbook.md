# Credential compromise — playbook

Work top to bottom. Each step is one action, what you should see, and what to do if you don't. Capture evidence before you disable, remove or reset anything. Queries are in the [investigation](investigation.md).

T0 = first malicious activity, in UTC. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

---

## 1. Triage

1. **Record T0, the device FQDN, and the alert account's SAM name and UPN.**
   - Expect: all four known.
   - If not: take T0 from the earliest related alert or process event and mark it as an estimate.
   - If the alert has no device (a cloud sign-in alert): go to step 3, then step 9.

2. **Check the device for lsass access or a dump.** Run the lsass access query, the credential sweep and the lolbin sweep (it covers comsvcs `MiniDump`).
   - Rule: any process opening `lsass.exe` that is not a verified security product, any lsass dump command or tool, or an lsass dump file = go to step 4 now and escalate. A verified security product runs from the vendor's install folder and shows the vendor as `Signer`, with `IsTrusted` true, in `DeviceFileCertificateInfo`.
   - Expect: no hits, or every lsass opener is a verified security product.
   - If not: go to step 4. Don't finish triage first.
   - An empty lsass query result doesn't clear the device; run the check query in its VERIFY note. An ASR `AsrLsassCredentialTheftBlocked` event doesn't clear it either.

3. **Check Entra ID Protection for the account** (Risky users, Risk detections).
   - Expect: no risk detections since T0.
   - If not: any detection puts the account in scope for steps 9 to 20. High risk, "Attacker in the Middle", "Anomalous token" or "Suspicious MFA authentication approval" = also escalate now.

---

## 2. Contain the device

Do steps 4 to 8 when step 2 found something, or when the device ran attacker code. Otherwise go to step 9.

4. **Check the device type and network before isolating.**
   - Domain controller, other Tier 0 server, or Hyper-V host: don't isolate it yourself. Escalate now. Isolating a Hyper-V host blocks network traffic to every VM on it.
   - Full-tunnel VPN: Microsoft says the device can't reach the Defender service once isolated. Do step 6 first, then step 5.
   - Behind a web proxy (PAC, WPAD or static): use selective isolation. Microsoft warns such devices might not recover from full isolation.
   - Expect: an ordinary workstation or member server. Go to step 5.

5. **Isolate the device** (Defender portal → device page → Isolate device).
   - Expect: the Action center shows the isolation as completed.
   - If not (pending or offline): Defender retries for up to three days. Escalate and report the device as not isolated.
   - Microsoft states isolation is lifted automatically after seven days (VERIFY (tenant)). Put the date in the ticket and re-check it.

6. **Collect the investigation package** (device page → Collect investigation package).
   - Expect: the package is downloadable from the Action center.
   - If not: collection can fail on low battery or a metered connection. Retry once, then record the failure and continue. Don't run any remediation on the device until this step is done or recorded as failed.

7. **Record the dump file; don't touch it.** If a command line names an output file (for example `C:\Users\Public\lsass.dmp`), record its path and the Live Response `fileinfo` output.
   - Don't download it: it holds the stolen credentials. Don't delete it. The IR lead decides on collection.
   - If not found: record that. It may have been moved or exfiltrated; it doesn't mean there was no dump.

8. **List every account exposed on the device.** In `DeviceLogonEvents` for this device: successful logons, every `LogonType` (including `Service` and `Batch`), from 30 days before T0 to now. Credential Guard doesn't change this list.
   - Expect: a list of accounts with logon types, privileged ones flagged.
   - If it holds a domain admin, another privileged account or a service account: escalate now.

---

## 3. Scope the accounts

Run steps 9 to 12 for every exposed account from step 8, or for the alert account if step 8 didn't apply.

9. **Check where each account logged on since T0** (user on multiple devices query).
   - Expect: only devices the account has a documented reason to use.
   - If not: lateral movement. Escalate, add each new device to scope and run steps 2 to 8 for it. Many devices is a reason to scope wider, never to close.

10. **Check the credential sweep for Kerberoasting, AS-REP roasting, DCSync and NTDS theft.** It runs estate-wide from T0 − 24h to T0 + 24h; rerun it with a later T0 if activity continued past that.
    - Expect: no hits.
    - If Kerberoasting or AS-REP roasting: record every account named in the command line; each needs a password reset in step 18. If no account is named, escalate so the IR lead decides which service accounts to reset.
    - If DCSync, `ntdsutil`, `ntds.dit` or a `reg save` of SAM, SYSTEM or SECURITY: escalate now.

11. **Check Entra sign-ins since T0 for each account with a cloud identity.** Run the impossible travel and MFA fatigue queries and filter to the UPN. Check legacy-auth sign-ins in the Entra sign-in logs (Client App column, interactive and non-interactive tabs).
    - Expect: no successful sign-in from an unfamiliar IP or country, and no legacy-auth success.
    - If an MFA burst: look for a successful sign-in from the first failed prompt to now. A success from a burst IP or country, or one the user doesn't recognise = compromised; escalate. With no success, still treat the password as known to the attacker.
    - If a legacy-auth success: escalate; the account needs step 19.

12. **Check for accounts and group changes the attacker made.** New local accounts: [new-local-accounts-created.kql](../../../kql/identity/new-local-accounts-created.kql). It matches `DeviceName` exactly and looks back 7 days from now, so enter the FQDN and widen the window if T0 is older. It filters on `TimeGenerated`; VERIFY (tenant) that it runs in your portal. Directory changes: the Entra audit log for role and group changes since T0.
    - Expect: no new accounts or memberships without a change record.
    - If not: record them. Don't remove anything yet; that is step 17.

---

## 4. Contain the accounts

Order: capture evidence, then disable, then revoke, then remove what the attacker added, then reset. Do this for every account confirmed or treated as compromised in steps 2 to 11.

13. **Capture identity evidence before changing anything.** For each account, export its sign-ins since T0 (interactive and non-interactive) and its audit log entries since T0, and record its registered authentication methods.
    - Why: "Require re-register MFA" deletes the user's phone numbers, Authenticator apps and software OATH tokens. Afterwards you can't see which one the attacker added.
    - Expect: exports attached to the ticket.

14. **Stop before acting on privileged or service accounts.** Service account, admin, or an account a production system uses: don't disable or reset it yourself. Disabling it may stop the service. Escalate; the IR lead decides. Do the same if a dump exposed many accounts (for example on a shared or terminal server): the IR lead sets the order.

15. **Disable the account.** Synced from AD: disable it in AD. Cloud-only: in the Entra admin center, clear Account enabled.
    - Expect: new sign-ins blocked. This is reversible; you re-enable it in step 20.
    - VERIFY (tenant): whether your sync writes the AD disabled state to Entra, and how quickly.
    - Disabling doesn't end Kerberos tickets already issued. Microsoft notes disabled users might keep accessing network services with tickets issued before. The Default Domain Policy ticket lifetime is 10 hours. If pass-the-ticket is suspected (`kerberos::` in the credential sweep), escalate.

16. **Revoke Entra sessions** (Entra admin center → user → Revoke sessions).
    - Expect: the user's refresh tokens are invalidated and every session must sign in again.
    - Gaps to record in the ticket: access tokens already issued stay valid until they expire (1 hour by default). Apps that issue their own session tokens keep them until they expire; Entra can't revoke those.
    - A password reset doesn't replace this step. After an admin reset in the Entra admin center, non-password-based cookies stay alive; revoking sessions ends them all.

17. **Remove what the attacker added.** Only after step 13.
    - Authentication methods added after T0 that the user doesn't recognise: delete them, or use "Require re-register MFA".
    - Accounts the attacker created (step 12): disable them. Delete them only with the IR lead's agreement.
    - Group or role memberships the attacker added (step 12): remove them.
    - App passwords: delete them. Legacy-auth apps that use them stop working.
    - Expect: nothing the attacker added remains.

18. **Reset the password from a clean device,** not the compromised device or any device in scope.
    - AD: reset twice. Microsoft advises this against pass-the-hash, especially with replication delays.
    - Cloud-only: reset in the Entra admin center, then repeat step 16.
    - Kerberoasted or AS-REP-roasted accounts (step 10): reset with the IR lead's approval; a service may break.
    - DCSync or NTDS theft: escalate. A krbtgt reset is the IR lead's decision, not yours.
    - Expect: the reset recorded in the ticket. The user signs in and re-registers MFA after step 20.

19. **Get legacy auth blocked if it was used** (step 11). Ask the identity team or IR lead for a Conditional Access block. Microsoft's procedure applies it to all users and starts it in report-only mode; don't create or change Conditional Access policies yourself.
    - Expect: a change reference in the ticket.

20. **Re-enable the account** once steps 16 to 19 are done and the sign-in logs show no attacker sign-in after step 16.
    - If an attacker sign-in appears after step 16: keep it disabled and escalate.

---

## 5. Remediate

21. **Run this playbook from step 2 for every device the exposed accounts reached since T0** (step 9).

22. **Check every device in scope for persistence** with the [persistence playbook](../04-persistence-detected/playbook.md).

23. **Get the IR lead's decision on the dumped device:** clean or reimage. Release it from isolation only after that work is done.

24. **Raise lateral-movement hardening with the customer as recommendations:** restrict remote logon rights for the exposed accounts, rotate local admin passwords (LAPS), and block remote WMI and WinRM where they aren't needed. Patching RDP doesn't stop logons with stolen credentials.

---

## 6. Close out

- [ ] Scope documented: which accounts (privileged flagged), which devices
- [ ] Timeline of lateral movement documented
- [ ] What was disabled, revoked, removed and reset, and when; any account not yet reset and why
- [ ] Customer informed: password resets, MFA review, hardening recommendations
- [ ] Findings written up

---

## Closing as a false positive

Close only with a named, verifiable benign cause, and record it. "Nothing else found", low volume, or "seen on many devices" is never enough; spread means scope wider.

Never close these yourself, even if a pen test is mentioned: an lsass dump command, tool or file; DCSync; NTDS.dit or hive theft; Mimikatz or other credential-tool keywords. Escalate; the IR lead confirms any authorised test.

| Signal | Close only if all of these hold |
|--------|---------------------------------|
| A process opened lsass | It runs from the security vendor's install folder. `DeviceFileCertificateInfo` for its SHA1 shows the vendor as `Signer` with `IsTrusted` true. The product is deployed at this customer (asset list or ticket). No dump command, dump file or credential-sweep hit on the device |
| MFA burst | The user confirms they caused the prompts. The burst IPs are the user's own known device or office. No successful sign-in from any other IP. No Entra ID Protection detection for the account |
| Impossible travel | One location is a documented corporate VPN or proxy egress (customer documentation or a named location in Entra), and the other is the user's usual location |
| Account on several devices | A documented role (for example IT support) with a ticket covering those devices. The account was not a Kerberoasting or AS-REP target and had no logon on a dumped host. Any remote execution came from a documented management server |

If any condition can't be confirmed, don't close: escalate.

---

## Escalate if

See also [escalation triggers](../../reference/escalation-triggers.md).

```
lsass opened by anything other than a verified security product, an lsass dump command or tool, or a dump file
SAM, SYSTEM or SECURITY hive saved, NTDS.dit copied, or DCSync seen
Mimikatz or other credential-tool keywords in a command line
Kerberoasting or AS-REP roasting seen
An exposed account logged on to a device it has no documented reason to use
PsExec, WMI or WinRM remote execution by an exposed account
A privileged, admin or service account among the exposed accounts
Successful sign-in after an MFA burst, or a High-risk user or token / AiTM detection in Entra ID Protection
Successful legacy-auth sign-in since T0
Device can't be isolated (pending, offline, domain controller, Hyper-V host)
```
