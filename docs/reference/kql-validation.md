# KQL validation

## What the smoke test checks

The `tests/kql-smoke/` harness (`KqlSmoke.csproj`) parses every `.kql` file under `kql/` using `Microsoft.Azure.Kusto.Language` and reports **syntax-level errors only**.

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
Files: 32 (scratchpad/ excluded)
------------------------------------------------------------------------
PASS  kql/network/beacon-after-hours.kql
PASS  kql/network/beacon-high-connection-count.kql
...
------------------------------------------------------------------------
Total: 32   Pass: 32   Fail: 0
```

## What causes a FAIL

Real grammar errors — e.g.:

```
FAIL  kql/process/suspicious-powershell.kql
      line 8, col 3: A closing parenthesis was expected
```

## scratchpad/ folder

Files in `scratchpad/` are excluded from the syntax check and from git. Use it for work-in-progress queries before committing.

## Adding new queries

1. Create a `.kql` file in the appropriate subfolder under `kql/`
2. Run `pwsh ./scripts/test-kql.ps1` to confirm it passes
3. Add a row to `kql/README.md`
4. Commit
