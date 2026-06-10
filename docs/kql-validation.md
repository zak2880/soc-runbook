# KQL validation

## What the smoke test checks

The `tests/kql-smoke/` harness (`KqlSyntaxCheck.csproj`) parses every `.kql` file under `kql/` using `Microsoft.Azure.Kusto.Language` and reports **syntax-level errors only** — things like malformed operators, unclosed brackets, invalid `let` statements, or broken pipe chains.

It does **not** validate against a live schema. The following are intentional and will not cause failures:

- Placeholder values: `HOSTNAME`, `USERNAME`, `PASTE_HASH_HERE`, datetime literals like `2024-01-01T10:00`
- Unknown table names: `DeviceProcessEvents`, `AADSignInEventsBeta`, etc. (no live Sentinel/Defender connection)
- Unknown column names, functions, or variables
- Unbound identifiers in `let` blocks

## Running it

Requires .NET 8 SDK installed on your machine.

```powershell
pwsh ./scripts/test-kql.ps1
```

Expected output for a clean repo:

```
soc-runbook — KQL syntax check
Root : C:\...\soc-runbook
Files: 22 (scratchpad/ excluded)
------------------------------------------------------------------------
PASS  kql/network/beacon-after-hours.kql
PASS  kql/network/beacon-high-connection-count.kql
...
------------------------------------------------------------------------
Total: 22   Pass: 22   Fail: 0
```

## What causes a FAIL

Real grammar errors — e.g.:

```
FAIL  kql/process/suspicious-powershell.kql
      line 8, col 3: A closing parenthesis was expected
```

Fix the syntax in the `.kql` file and re-run.

## scratchpad/ folder

Files in `scratchpad/` are excluded from the syntax check and from git commits (see `.gitignore`). Use it for work-in-progress queries before they're ready to commit.

## Adding new queries

1. Create a `.kql` file in the appropriate subfolder under `kql/`
2. Run `pwsh ./scripts/test-kql.ps1` to confirm it passes syntax check
3. Commit

Keep one query per file. Add a comment block at the top explaining what the query does, what it detects, and which doc it relates to (see existing files for the pattern).
