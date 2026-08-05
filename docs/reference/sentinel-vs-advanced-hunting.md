# Sentinel vs Advanced Hunting

> The single most common reason a query "doesn't work" in this repo isn't bad KQL — it's running it on the wrong platform, or with the wrong time-column name for that platform. This page exists so you can check that in ten seconds instead of re-debugging a query that was fine all along.

---

## Section 1 — The key difference

Every table in this repo's scope lives natively in **Microsoft Defender XDR Advanced Hunting**, where the time column is called `Timestamp`. Some of those tables are *also* streamed into **Microsoft Sentinel** (Log Analytics) via the Microsoft Defender XDR data connector — and when they land there, the time column is exposed as `TimeGenerated` instead, matching the convention every other Sentinel/Log Analytics table uses. Same data, same rows, different column name depending on where you're running the query.

**The `kql/` folder is split by platform**: `kql/sentinel/` (time column `TimeGenerated`) and `kql/xdr/` (time column `Timestamp`), with matching subfolders on each side. Every detection in this repo now exists as a file in both trees, so there's no more find-and-replace step — pick the file under the tree that matches where you're running the query. See [kql/README.md](../../kql/README.md) for the full index. A handful of files exist in `kql/sentinel/` purely for structural parity even though the table they query isn't actually available in Sentinel (`DeviceAlertEvents`, `EmailEvents`, `EmailAttachmentInfo`, `UrlClickEvents`) — each of those files says so in its own header comment, and Section 2 below explains why.

Where a detection queries a table that only exists on one platform under a *different* schema entirely — sign-in data (`SigninLogs` vs `EntraIdSignInEvents`), or app/mailbox activity (`OfficeActivity`/`AuditLogs` vs `CloudAppEvents`) — the two files are genuine independent rewrites against each platform's real schema, not a column rename. See Section 4 for the field-level differences.

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
| `SigninLogs` | Yes — via the **Azure Active Directory** / Entra ID data connector | No — the Advanced Hunting equivalent is `EntraIdSignInEvents`, with a different schema |
| `EmailEvents` | No — not exposed as a queryable Sentinel table even with the connector configured | Yes (native) |
| `EmailAttachmentInfo` | No | Yes (native) |
| `EmailUrlInfo` | No | Yes (native) |
| `UrlClickEvents` | No | Yes (native) |
| `CloudAppEvents` | **Yes, in both platforms** — no separate Sentinel connector needed; exposed automatically once Microsoft Defender for Cloud Apps is deployed in the tenant's Defender XDR environment, same schema on both sides | Yes (native) |
| `OfficeActivity` | Yes — via the **Office 365** data connector | No |
| `AuditLogs` | Yes — via the **Azure Active Directory** / Entra ID data connector (directory audit events: role assignments, app/service principal changes, OAuth consent grants) | No — nearest Advanced Hunting equivalent is the subset of activity `CloudAppEvents` also captures via the Azure AD app connector, not a 1:1 match |

**Connector notes:**
- `OfficeActivity` requires the **Office 365** data connector to be enabled in your Sentinel workspace, and unified audit logging enabled in the tenant — without both, the table exists but stays empty.
- `EntraIdSignInEvents` has no Sentinel path at all — don't go looking for a connector to enable. If you need sign-in log data in Sentinel, that's `SigninLogs` via the **Azure Active Directory** connector, and you'll need to rewrite the query against its schema (see Section 4).
- `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, and `DeviceEvents` all require the **Microsoft Defender XDR** connector in Sentinel to appear at all — without it, those table names simply don't exist in your workspace.
- `CloudAppEvents` does **not** require a separate Sentinel connector — it's available in Sentinel automatically once Microsoft Defender for Cloud Apps is deployed in the tenant's Defender XDR environment, same schema as Advanced Hunting. As of February 2026, data lake tier ingestion for `CloudAppEvents` into Sentinel is generally available.
- `AuditLogs` (Sentinel directory audit events — role assignments, service principal/app changes, OAuth consent grants) requires the **Azure Active Directory** connector, the same one that provides `SigninLogs`. It has no Advanced Hunting equivalent table; the closest thing on that side is the subset of the same activity `CloudAppEvents` picks up via its Azure AD app connector, which is not a full substitute.

---

## Section 3 — Common gotchas

- **`Timestamp` in Advanced Hunting is UTC. `TimeGenerated` in Sentinel is also UTC — but the portal may display it in your local time zone.** Always confirm which you're looking at before correlating a timestamp across sources, especially when handing a timeline to someone in a different time zone.
- **`DeviceAlertEvents` is only available in Advanced Hunting** — not in Sentinel Log Analytics directly. [kql/sentinel/identity/all-alerts-for-device.kql](../../kql/sentinel/identity/all-alerts-for-device.kql) will not run in a Sentinel workspace; it's kept only for structural parity with [kql/xdr/identity/all-alerts-for-device.kql](../../kql/xdr/identity/all-alerts-for-device.kql), which does.
- **`EmailEvents` and the other email tables are Advanced Hunting only** — not available in Sentinel unless you're bringing individual alerts across via the Microsoft 365 Defender connector's incident/alert sync, which is not the same as being able to query the raw table. Every file under `kql/sentinel/email/` and the email-dependent stages of `kql/sentinel/pivots/phishing-to-device-compromise.kql` and `email-click-to-execution.kql` carry this same caveat in their header comments.
- **`OfficeActivity` is Sentinel-only**, via the Office 365 data connector — it does not exist in Advanced Hunting. Don't go looking for it there.
- **`AuditLogs` is Sentinel-only**, via the Azure Active Directory connector — it does not exist in Advanced Hunting either. `kql/sentinel/identity/entra-post-compromise-oauth-grants.kql` and `entra-post-compromise-persistence.kql` use it directly rather than working around it via `OfficeActivity`.
- **`CloudAppEvents` is available in both platforms with the same schema** — no separate Sentinel connector needed, just Microsoft Defender for Cloud Apps deployed in the tenant. Don't confuse it with `OfficeActivity` or `AuditLogs`, which are genuinely different, Sentinel-only tables.
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
| `EntraIdSignInEvents` (whole table) | `SigninLogs` | Different table, different schema — e.g. `AccountUpn` becomes `UserPrincipalName`, `Country` becomes `Location`, `ErrorCode` becomes a string-typed `ResultType`, and `IsCompliant`/`IsManaged` move from top-level fields to the `DeviceDetail` dynamic column |
| `CloudAppEvents` (whole table) | `CloudAppEvents` | No conversion needed — same table, same schema, in both platforms (requires Defender for Cloud Apps) |
| `OfficeActivity` (whole table) | *(no Advanced Hunting equivalent)* | This table only exists in Sentinel; there is nothing to convert it to |
| *(no Advanced Hunting equivalent)* | `AuditLogs` (whole table) | This table only exists in Sentinel; the nearest Advanced Hunting substitute is the subset of the same directory-audit activity `CloudAppEvents` also picks up, not a straight conversion |

---

## Section 5 — Licence requirements for tables in this repo

| Table | Minimum licence |
|-------|-----------------|
| `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceAlertEvents`, `DeviceEvents` | Microsoft Defender for Endpoint Plan 2 (bundled in Microsoft 365 E5) |
| `EntraIdSignInEvents` | Microsoft Entra ID P1 at minimum for sign-in log retention; full Advanced Hunting visibility additionally needs Microsoft Defender for Cloud Apps, or Entra ID P2 with Identity Protection integrated into Defender XDR |
| `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `UrlClickEvents` | Defender for Office 365 Plan 1 minimum (Plan 2 adds richer attachment/URL detonation verdicts, but the raw events exist on Plan 1) |
| `CloudAppEvents` | Microsoft Defender for Cloud Apps (as of February 2026, also available via Sentinel's data lake tier ingestion, now generally available) |
| `OfficeActivity` | Any Microsoft 365 licence covering the audited workload (Exchange Online, SharePoint Online, etc.), **plus** the Sentinel Office 365 data connector configured and unified audit logging enabled in the tenant — the licence alone isn't sufficient without both |
| `SigninLogs`, `AuditLogs` | Microsoft Entra ID P1 at minimum, **plus** the Sentinel Azure Active Directory data connector configured — both tables ride the same connector |

Microsoft 365 E5 covers every row in this table. If your tenant is on E3, expect to be missing at least Defender for Cloud Apps and Defender for Endpoint Plan 2 — check with the client before assuming a query in this repo will return anything.
