# soc-runbook

> L2 CSOC reference — Microsoft Sentinel & Defender XDR  
> Investigation guides, response playbooks, and KQL detection library

---

## Scenarios

Each scenario folder contains an **investigation guide** (what to look for, how to analyse) and a **playbook** (checklist at the top, step-by-step response, escalation triggers).

| Scenario | Investigation | Playbook |
|----------|--------------|---------|
| 01 — Malware alert | [investigation](docs/scenarios/01-malware-alert/investigation.md) | [playbook](docs/scenarios/01-malware-alert/playbook.md) |
| 02 — Suspicious process | [investigation](docs/scenarios/02-suspicious-process/investigation.md) | [playbook](docs/scenarios/02-suspicious-process/playbook.md) |
| 03 — Suspicious network activity | [investigation](docs/scenarios/03-suspicious-network-activity/investigation.md) | [playbook](docs/scenarios/03-suspicious-network-activity/playbook.md) |
| 04 — Persistence detected | [investigation](docs/scenarios/04-persistence-detected/investigation.md) | [playbook](docs/scenarios/04-persistence-detected/playbook.md) |
| 05 — Malicious file | [investigation](docs/scenarios/05-malicious-file/investigation.md) | [playbook](docs/scenarios/05-malicious-file/playbook.md) |
| 06 — Credential compromise | [investigation](docs/scenarios/06-credential-compromise/investigation.md) | [playbook](docs/scenarios/06-credential-compromise/playbook.md) |
| 07 — LOLBin abuse | [investigation](docs/scenarios/07-lolbin-abuse/investigation.md) | [playbook](docs/scenarios/07-lolbin-abuse/playbook.md) |
| 08 — C2 beaconing | [investigation](docs/scenarios/08-c2-beaconing/investigation.md) | [playbook](docs/scenarios/08-c2-beaconing/playbook.md) |
| 09 — LOTS & cloud C2 | [investigation](docs/scenarios/09-lots-cloud-c2/investigation.md) | [playbook](docs/scenarios/09-lots-cloud-c2/playbook.md) |
| 10 — Initial access | [investigation](docs/scenarios/10-initial-access/investigation.md) | [playbook](docs/scenarios/10-initial-access/playbook.md) |
| 11 — Defence evasion | [investigation](docs/scenarios/11-defence-evasion/investigation.md) | [playbook](docs/scenarios/11-defence-evasion/playbook.md) |
| 12 — Phishing email | [investigation](docs/scenarios/12-phishing-email/investigation.md) | [playbook](docs/scenarios/12-phishing-email/playbook.md) |

---

## Reference

| Doc | Covers |
|-----|--------|
| [Escalation triggers](docs/reference/escalation-triggers.md) | When to stop investigating and escalate — severity guide |
| [Threat intel enrichment](docs/reference/threat-intel-enrichment.md) | VirusTotal, AbuseIPDB, Shodan, URLScan, Defender TI |
| [KQL validation](docs/reference/kql-validation.md) | Running the syntax checker, adding new queries |

---

## KQL library

Full index with MITRE mappings in [kql/README.md](kql/README.md).

| Folder | Queries |
|--------|---------|
| [kql/process/](kql/process/) | PowerShell, LOLBins, office-spawning-shells, credential access sweep |
| [kql/network/](kql/network/) | Beaconing, DNS tunnelling, lateral movement, LOTS, unusual ports |
| [kql/persistence/](kql/persistence/) | Registry run keys, scheduled tasks, services, WMI subscriptions |
| [kql/files/](kql/files/) | Suspicious drops, hash sweep across estate |
| [kql/identity/](kql/identity/) | lsass access, lateral movement, new accounts, Entra ID anomalies |
| [kql/ransomware/](kql/ransomware/) | VSS deletion, mass renames, Defender disabled, log clearing |

---

## Escalate immediately if you see

```
lsass access by non-Windows process
rundll32.exe comsvcs.dll MiniDump
wmic shadowcopy delete / vssadmin delete shadows
Mass file renames
Confirmed C2 beaconing (live session)
Lateral movement — same hash/user on multiple devices
Event logs cleared
Defender/EDR tampered or killed
```

---

## MITRE ATT&CK coverage

Full technique mapping in [MITRE-mapping.md](MITRE-mapping.md) — covers 12 tactics and 40+ techniques.

---

## Running the KQL syntax checker

Requires .NET 8 SDK.

```powershell
pwsh ./scripts/test-kql.ps1
```
