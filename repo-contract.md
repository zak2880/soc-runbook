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
- `DeviceAlertEvents`
- `DeviceLogonEvents`
- `DeviceEvents`
- `AADSignInEventsBeta`

All tables are standard Microsoft Defender XDR / Sentinel Advanced Hunting schema.

## Query conventions

- Queries use `HOSTNAME`, `USERNAME`, `HASH`, and datetime placeholders — replace before running
- Time windows default to `ago(24h)` or `ago(7d)` — adjust as needed
- No live schema validation — queries are syntax-checked only (see [docs/kql-validation.md](docs/kql-validation.md))

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
│   └── ransomware/     Ransomware-specific detection
├── scripts/            Utility scripts (KQL smoke test runner)
├── tests/kql-smoke/    .NET KQL syntax validation harness
└── scratchpad/         Local working notes — not syntax-checked, not committed
```
