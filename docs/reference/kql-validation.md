# KQL validation

## What the smoke test checks

The `tests/kql-smoke/` harness (`KqlSmoke.csproj`) parses every `.kql` file under `kql/` using `Microsoft.Azure.Kusto.Language` and reports **syntax-level errors only**.

It also scans every `.md` file in the repo (scratchpad/ excluded) for ```` ```kql ```` fenced code blocks and syntax-checks each extracted block the same way, using the same grammar-only check. This matters because most queries now live only in their `.md` file — see [Adding new queries](#adding-new-queries) — so the `.md` file is the thing that actually needs to parse cleanly.

It does **not** validate against a live schema. The following are intentional and will not cause failures:
- Placeholder values: `HOSTNAME`, `USERNAME`, `PASTE_HASH_HERE`, datetime literals
- Unknown table names: `DeviceProcessEvents`, `EntraIdSignInEvents`, etc.
- Unknown column names, functions, or variables

## Running it

Requires .NET 8 SDK.

```powershell
pwsh ./scripts/test-kql.ps1
```

Expected output for a clean repo:

```
soc-runbook — KQL syntax check
Root : C:\...\soc-runbook
Files: 40 .kql, 45 .md (scratchpad/ excluded)
------------------------------------------------------------------------
PASS  kql/network/beacon-after-hours.kql
PASS  kql/network/beacon-high-connection-count.kql
...
PASS  kql/identity/entra-device-code-auth-flow.md (block 1, line 18)
PASS  docs/scenarios/06-credential-compromise/investigation.md (block 1, line 24)
...
------------------------------------------------------------------------
KQL files: 40   Pass: 40   Fail: 0   |   MD blocks: 61   Pass: 61   Fail: 0
```

## What causes a FAIL

Real grammar errors — e.g. in a `.kql` file:

```
FAIL  kql/process/suspicious-powershell.kql
      line 8, col 3: A closing parenthesis was expected
```

Or in a ```` ```kql ```` block inside a `.md` file — reported with the block number (a `.md` file can contain several independent blocks, each checked on its own) and the block's approximate starting line in the source file, so the failure is easy to locate:

```
FAIL  kql/identity/entra-device-code-auth-flow.md (block 1, line 18)
      line 20, col 3: A closing parenthesis was expected
```

The `line` in the diagnostic itself is the absolute line number in the `.md` file, not an offset within the block.

## scratchpad/ folder

Files in `scratchpad/` are excluded from the syntax check and from git. Use it for work-in-progress queries before committing.

## Adding new queries

Most queries should be documented as a `.md` file (MITRE mapping, false positives, investigation notes, "why this query" context) with the query itself inside a ```` ```kql ```` fenced block — that block is what the harness checks, so it's both the canonical query and the validated one.

1. Create a `.md` file in the appropriate subfolder under `kql/`, with the query in a ```` ```kql ```` block
2. Run `pwsh ./scripts/test-kql.ps1` to confirm the block passes
3. Add a row to `kql/README.md` pointing at the `.md` file
4. Commit

A standalone `.kql` file is only needed for queries that don't (yet) have `.md` documentation — e.g. `functions/`, and undocumented queries elsewhere. Once a `.kql` file gains an `.md` companion with the same base name, delete the `.kql` file — it becomes a duplicate of the query already checked inside the `.md` block.
