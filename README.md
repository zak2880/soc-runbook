# soc-runbook

> L2 CSOC reference — Microsoft Sentinel & Defender XDR  
> Malware investigation guides + KQL detection library

---

## Investigation guides

| Doc | Covers |
|-----|--------|
| [01 — Malware triage](docs/01-malware-triage.md) | Full workflow from alert to close |
| [02 — Process investigation](docs/02-process-investigation.md) | Parent-child chains, LOLBins, encoded PowerShell |
| [03 — Network investigation](docs/03-network-investigation.md) | C2 beaconing, download cradles, lateral movement |
| [04 — Persistence](docs/04-persistence.md) | Run keys, scheduled tasks, services, WMI |
| [05 — File artefacts](docs/05-file-artefacts.md) | Suspicious drops, ransomware signals, hash hunting |
| [06 — Identity & credentials](docs/06-identity-and-credentials.md) | Credential dumping, lateral movement, Entra ID |
| [07 — LOLBins](docs/07-lolbins.md) | Per-binary abuse guide with log examples |
| [08 — C2 beaconing](docs/08-c2-beaconing.md) | Signals, patterns, false positives |
| [09 — Escalation triggers](docs/09-escalation-triggers.md) | When to stop investigating and shout |

---

## KQL library

| Folder | Queries |
|--------|---------|
| [kql/process/](kql/process/) | PowerShell, LOLBins, office-spawning-shells |
| [kql/network/](kql/network/) | Beaconing, DNS tunnelling, lateral movement scanning |
| [kql/persistence/](kql/persistence/) | Registry run keys, scheduled tasks, new services |
| [kql/files/](kql/files/) | Suspicious drops, ransomware file renames, hash sweep |
| [kql/identity/](kql/identity/) | lsass access, credential dumping, new accounts |
| [kql/ransomware/](kql/ransomware/) | VSS deletion, mass renames, defence evasion |

---

## Escalate immediately if you see

```
lsass access by non-Windows process
rundll32.exe comsvcs.dll MiniDump
wmic shadowcopy delete / vssadmin delete shadows
Mass file renames (ransomware)
Confirmed C2 beaconing (live session)
Lateral movement confirmed — same hash/user on multiple devices
Event logs cleared (wevtutil cl)
Defender/EDR tampered or killed
```

---

## Triage order

1. **Confirm** — what is it, which device, is it still live?
2. **Contain** — isolate via Defender XDR if active
3. **Investigate** — processes → network → persistence → files → identity
4. **Spread check** — same hash elsewhere? Same user on other devices? Email delivery?
5. **Close or escalate** — see [09-escalation-triggers.md](docs/09-escalation-triggers.md)

---

## Running the KQL syntax checker

Requires .NET 8 SDK.

```powershell
pwsh ./scripts/test-kql.ps1
```

See [docs/kql-validation.md](docs/kql-validation.md) for details.
