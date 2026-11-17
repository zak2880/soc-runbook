# soc-runbook

Personal SOC reference and KQL detection library for L2 analysis work in Microsoft Sentinel and Defender XDR.

## What this repo is

- Structured investigation guides covering the full malware triage workflow
- Ready-to-run KQL queries organised by MITRE tactic / investigation area
- LOLBin abuse reference with real log examples
- C2 beaconing detection patterns and false positive guidance
- Escalation triggers and incident severity guidance

## Who it's for

Built for daily use as an L2 CSOC Analyst. Queries are written against:
- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- `AlertInfo` and `AlertEvidence` (replace the retired `DeviceAlertEvents`)
- `DeviceLogonEvents`
- `DeviceEvents`
- `AADSignInEventsBeta`

All tables are standard Microsoft Defender XDR / Sentinel Advanced Hunting schema.

## Query conventions

- Queries use `HOSTNAME` (short device name, matched with `startswith`), `USERNAME` (SAM account name), `PASTE_SHA1_HERE` / `PASTE_SHA256_HERE` and a `T0` incident-time placeholder — replace before running; see [kql/README.md](kql/README.md)
- Investigation queries are anchored on `T0` (`Timestamp between ((T0 - X) .. (T0 + Y))`) rather than `ago()`; Advanced Hunting holds 30 days of native data
- Each query's second header line states where it runs (`// Runs in:`): `Timestamp` for Defender tables, `TimeGenerated` only for Sentinel-only tables
- No live schema validation — queries are syntax-checked only (see [docs/reference/kql-validation.md](docs/reference/kql-validation.md))

## Structure

```
soc-runbook/
├── docs/               Investigation guides (markdown)
├── kql/                KQL query library, organised by investigation area
│   ├── process/        Process and LOLBin queries
│   ├── network/        C2 beaconing and lateral movement
│   ├── persistence/    Registry, tasks, services, WMI
│   ├── files/          File artefacts and ransomware signals
│   ├── identity/       Credential access and lateral movement
│   ├── ransomware/     Ransomware-specific detection
│   ├── exfiltration/   Data staging and exfiltration
│   └── triage/         Post-alert quick checks
├── scripts/            Utility scripts (KQL smoke test runner)
├── tests/kql-smoke/    .NET KQL syntax validation harness
└── scratchpad/         Local working notes — not syntax-checked, not committed
```
