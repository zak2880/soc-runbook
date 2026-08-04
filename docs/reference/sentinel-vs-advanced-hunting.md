# Sentinel vs Advanced Hunting

> The single most common reason a query "doesn't work" in this repo isn't bad KQL — it's running it on the wrong platform, or with the wrong time-column name for that platform. This page exists so you can check that in ten seconds instead of re-debugging a query that was fine all along.

---

## Section 1 — The key difference

Every table in this repo's scope lives natively in **Microsoft Defender XDR Advanced Hunting**, where the time column is called `Timestamp`. Some of those tables are *also* streamed into **Microsoft Sentinel** (Log Analytics) via the Microsoft Defender XDR data connector — and when they land there, the time column is exposed as `TimeGenerated` instead, matching the convention every other Sentinel/Log Analytics table uses. Same data, same rows, different column name depending on where you're running the query.

This repo's `.kql` files are all written using `TimeGenerated`, matching Sentinel's convention — that's a deliberate choice, not an inconsistency. If you're pasting a query straight into the Defender XDR portal's Advanced Hunting screen, rename `TimeGenerated` to `Timestamp` first (a simple find-and-replace).

**Before (Sentinel / Log Analytics):**
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "powershell.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine
```

**After (Defender XDR Advanced Hunting):**
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, ProcessCommandLine
```

Everything else in the query — table name, columns, operators, `where`/`project`/`summarize` logic — is identical. Only the time column changes.

**Why the field name matters — and why it fails quietly:** if you reference a column that genuinely doesn't exist on that platform (e.g. `Timestamp` in a Sentinel workspace where that table only exposes `TimeGenerated`), Kusto raises a hard "column not found" error — annoying, but at least it's obvious something's wrong. The dangerous case is subtler: the Sentinel portal has its own time-range picker control, separate from your query text, and it filters on `TimeGenerated` regardless of what your `where` clause says. If a query written for Advanced Hunting happens to run without erroring in Sentinel (for example, because you're working against a table that still carries both column names), the portal's time-range picker is still silently narrowing your results against `TimeGenerated` in the background. You can end up staring at "no results" and conclude an estate is clean, when the real problem is a mismatched time filter — not an absence of activity. Always check which column your `where` clause is actually filtering on before trusting a clean result.

---

## Section 2 — Where to run each query type

| Table | Available in Sentinel | Available in Advanced Hunting |
|-------|:---:|:---:|
| `DeviceProcessEvents` | Yes — via the Microsoft Defender XDR connector | Yes (native) |
| `DeviceNetworkEvents` | Yes — via the Microsoft Defender XDR connector | Yes (native) |
| `DeviceFileEvents` | Yes — via the Microsoft Defender XDR connector | Yes (native) |
| `DeviceRegistryEvents` | Yes — via the Microsoft Defender XDR connector | Yes (native) |
| `DeviceLogonEvents` | Yes — via the Microsoft Defender XDR connector | Yes (native) |
| `DeviceAlertEvents` | No | Yes (native) |
| `DeviceEvents` | Yes — via the Microsoft Defender XDR connector | Yes (native) |
| `EntraIdSignInEvents` | No — the Sentinel equivalent is `SigninLogs` via the Azure AD / Entra ID connector, with a different schema | Yes (native) |
| `EmailEvents` | No — not exposed as a queryable Sentinel table even with the connector configured | Yes (native) |
| `EmailAttachmentInfo` | No | Yes (native) |
| `EmailUrlInfo` | No | Yes (native) |
| `UrlClickEvents` | No | Yes (native) |
| `CloudAppEvents` | Yes — no separate connector needed; exposed automatically once Microsoft Defender for Cloud Apps is deployed in the tenant's Defender XDR environment | Yes (native) |
| `OfficeActivity` | Yes — via the **Office 365** data connector | No |

**Connector notes:**
- `OfficeActivity` requires the **Office 365** data connector to be enabled in your Sentinel workspace, and unified audit logging enabled in the tenant — without both, the table exists but stays empty.
- `EntraIdSignInEvents` has no Sentinel path at all — don't go looking for a connector to enable. If you need sign-in log data in Sentinel, that's `SigninLogs` via the **Azure Active Directory** connector, and you'll need to rewrite the query against its schema (see Section 4).
- `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, and `DeviceEvents` all require the **Microsoft Defender XDR** connector in Sentinel to appear at all — without it, those table names simply don't exist in your workspace.
- `CloudAppEvents` does **not** require a separate Sentinel connector — it's available in Sentinel automatically once Microsoft Defender for Cloud Apps is deployed in the tenant's Defender XDR environment, same schema as Advanced Hunting. As of February 2026, data lake tier ingestion for `CloudAppEvents` into Sentinel is generally available.

---

## Section 3 — Common gotchas

- **`Timestamp` in Advanced Hunting is UTC. `TimeGenerated` in Sentinel is also UTC — but the portal may display it in your local time zone.** Always confirm which you're looking at before correlating a timestamp across sources, especially when handing a timeline to someone in a different time zone.
- **`DeviceAlertEvents` is only available in Advanced Hunting** — not in Sentinel Log Analytics directly. `all-alerts-for-device.kql` will not run in a Sentinel workspace.
- **`EmailEvents` and the other email tables are Advanced Hunting only** — not available in Sentinel unless you're bringing individual alerts across via the Microsoft 365 Defender connector's incident/alert sync, which is not the same as being able to query the raw table.
- **`OfficeActivity` is Sentinel-only**, via the Office 365 data connector — it does not exist in Advanced Hunting. Don't go looking for it there.
- **`CloudAppEvents` is available in both platforms with the same schema** — no separate Sentinel connector needed, just Microsoft Defender for Cloud Apps deployed in the tenant. Don't confuse it with `OfficeActivity`, which is a genuinely different, Sentinel-only table.
- **Case sensitivity: `==` is case sensitive, `=~` is not.** Use `=~` for usernames, device names, and filenames — Windows itself is largely case-insensitive for these, and a hostname or account logged as `DESKTOP-ABC` won't match a hardcoded `"desktop-abc"` under `==`. Every query in this repo that filters on `FileName` uses `=~` for exactly this reason.
- **`ago()` is relative to when the query runs, not to any fixed clock.** A query with `ago(24h)` run at 3am covers a completely different 24-hour window than the same query run at 9am the same day. If you're re-running a query to reproduce yesterday's results, use explicit `datetime()` bounds instead of `ago()`.

---

## Section 4 — Quick conversion reference

| Defender XDR (Advanced Hunting) | Sentinel (Log Analytics) | Notes |
|---|---|---|
| `Timestamp` | `TimeGenerated` | The one that catches everyone — see Section 1 |
| `DeviceName` | `DeviceName` | Identical on Device* tables in both platforms |
| `InitiatingProcessFileName` | `InitiatingProcessFileName` | Identical on Device* tables in both platforms |
| `AccountName` | `AccountName` | Identical on Device* tables in both platforms |
| `| join kind=inner (...) on Column` | `| join kind=inner (...) on Column` | Join syntax itself doesn't change between platforms — only the tables/columns on either side of it do |
| `EntraIdSignInEvents` (whole table) | `SigninLogs` | Different table, different schema — e.g. `AccountUpn` becomes `UserPrincipalName`, `Country` has to be pulled out of the `LocationDetails` dynamic column instead of being a top-level field |
| `CloudAppEvents` (whole table) | `CloudAppEvents` | No conversion needed — same table, same schema, in both platforms (requires Defender for Cloud Apps) |
| `OfficeActivity` (whole table) | *(no Advanced Hunting equivalent)* | This table only exists in Sentinel; there is nothing to convert it to |

---

## Section 5 — Licence requirements for tables in this repo

| Table | Minimum licence |
|-------|-----------------|
| `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceAlertEvents`, `DeviceEvents` | Microsoft Defender for Endpoint Plan 2 (bundled in Microsoft 365 E5) |
| `EntraIdSignInEvents` | Microsoft Entra ID P1 at minimum for sign-in log retention; full Advanced Hunting visibility additionally needs Microsoft Defender for Cloud Apps, or Entra ID P2 with Identity Protection integrated into Defender XDR |
| `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `UrlClickEvents` | Defender for Office 365 Plan 1 minimum (Plan 2 adds richer attachment/URL detonation verdicts, but the raw events exist on Plan 1) |
| `CloudAppEvents` | Microsoft Defender for Cloud Apps (as of February 2026, also available via Sentinel's data lake tier ingestion, now generally available) |
| `OfficeActivity` | Any Microsoft 365 licence covering the audited workload (Exchange Online, SharePoint Online, etc.), **plus** the Sentinel Office 365 data connector configured and unified audit logging enabled in the tenant — the licence alone isn't sufficient without both |

Microsoft 365 E5 covers every row in this table. If your tenant is on E3, expect to be missing at least Defender for Cloud Apps and Defender for Endpoint Plan 2 — check with the client before assuming a query in this repo will return anything.
