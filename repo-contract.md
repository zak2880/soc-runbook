# soc-runbook

Personal SOC reference and KQL detection library for L2 analysis work in Microsoft Sentinel and Defender XDR.

## What this repo is

- Structured investigation guides covering the full malware triage workflow
- Ready-to-run KQL queries organised by MITRE tactic / investigation area
- LOLBin abuse reference with real log examples
- C2 beaconing detection patterns and false positive guidance
- Escalation triggers and incident severity guidance

## Who it's for

Built for daily use as an L2 CSOC Analyst. Queries are written against Microsoft Defender XDR Advanced Hunting and Microsoft Sentinel Log Analytics tables, including:
- `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceAlertEvents`, `DeviceLogonEvents`, `DeviceEvents`
- `EntraIdSignInEvents` (XDR) / `SigninLogs` (Sentinel)
- `CloudAppEvents` (both platforms) / `OfficeActivity` (Sentinel only) / `AuditLogs` (Sentinel only)
- `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `UrlClickEvents` (XDR only)

See [docs/reference/sentinel-vs-advanced-hunting.md](docs/reference/sentinel-vs-advanced-hunting.md) for the full per-table platform availability matrix.

## Query conventions

- The `kql/` folder is split into `kql/sentinel/` and `kql/xdr/` — see **Platform split** below.
- Queries use `HOSTNAME`, `USERNAME`, `HASH`, and datetime placeholders — replace before running
- Time windows default to `ago(24h)` or `ago(7d)` — adjust as needed, set as `let` bindings at the top of each query
- No live schema validation — queries are syntax-checked only (see [docs/reference/kql-validation.md](docs/reference/kql-validation.md))

## Platform split

`kql/` has two top-level platform trees, not one flat set of queries:

```
kql/
├── sentinel/   Microsoft Sentinel (Log Analytics) — time column is TimeGenerated
└── xdr/        Microsoft Defender XDR Advanced Hunting — time column is Timestamp
```

Each has the same nine subfolders (`process/`, `network/`, `persistence/`, `files/`, `identity/`, `ransomware/`, `email/`, `pivots/`, `functions/`), and every detection exists as a file in both trees. The two versions of a given query are not always a mechanical `TimeGenerated`/`Timestamp` rename of each other:

- **Device-scoped queries** (`process/`, `network/`, `persistence/`, `files/`, `ransomware/`, most of `functions/`) query the same `Device*` tables on both platforms, so the Sentinel and XDR versions differ only in time column and header comment.
- **Identity queries** (`identity/`, most of `pivots/`) query genuinely different tables on each platform — Sentinel uses `SigninLogs`, `OfficeActivity`, and `AuditLogs`; XDR uses `EntraIdSignInEvents` and `CloudAppEvents`. These are real rewrites against different schemas, not renames.
- **Email queries** (`email/`, some of `pivots/`) query `EmailEvents`/`EmailAttachmentInfo`/`UrlClickEvents`, which are XDR Advanced Hunting-only tables not currently exposed in Sentinel Log Analytics. The Sentinel-tree versions of these are kept for structural parity and documented in-file as non-functional against a real Sentinel workspace today — see [docs/reference/sentinel-vs-advanced-hunting.md](docs/reference/sentinel-vs-advanced-hunting.md).

## Structure

```
soc-runbook/
├── docs/               Investigation guides (markdown)
├── kql/                KQL query library, organised by platform then investigation area
│   ├── sentinel/       Microsoft Sentinel (TimeGenerated)
│   │   ├── process/        Process and LOLBin queries
│   │   ├── network/        C2 beaconing and lateral movement
│   │   ├── persistence/    Registry, tasks, services, WMI
│   │   ├── files/          File artefacts and ransomware signals
│   │   ├── identity/       Credential access and lateral movement
│   │   ├── ransomware/     Ransomware-specific detection
│   │   ├── email/          Phishing delivery, attachments, URL clicks
│   │   ├── pivots/         Cross-table attack-chain queries
│   │   └── functions/      Reusable let function definitions
│   └── xdr/             Microsoft Defender XDR Advanced Hunting (Timestamp) — same subfolders
├── scripts/            Utility scripts (KQL smoke test runner)
├── tests/kql-smoke/    .NET KQL syntax validation harness
└── scratchpad/         Local working notes — not syntax-checked, not committed
```
