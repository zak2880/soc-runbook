#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Run the KQL syntax check against soc-runbook.

.DESCRIPTION
    Builds and runs the .NET tool under tests/kql-smoke/ which parses every
    .kql file under kql/ and reports syntax-level diagnostics.
    Syntax-only — does not validate against a live Sentinel or Defender XDR
    schema. Placeholder values (HOSTNAME, USERNAME, PASTE_HASH_HERE) and
    unresolved table/column names are expected and will not cause failures.
    See docs/kql-validation.md for details.

.PARAMETER RepoRoot
    Override the repo root. Defaults to the parent of this script's directory.

.PARAMETER Configuration
    Build configuration. Defaults to Release.

.EXAMPLE
    pwsh ./scripts/test-kql.ps1

.EXAMPLE
    pwsh ./scripts/test-kql.ps1 -Configuration Debug
#>

[CmdletBinding()]
param(
    [string] $RepoRoot,
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'

if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

$toolDir = Join-Path $RepoRoot 'tests/kql-smoke'
if (-not (Test-Path $toolDir)) {
    Write-Error "KQL smoke tool not found at $toolDir"
    exit 2
}

Write-Host "Building harness ($Configuration)..." -ForegroundColor Cyan
dotnet build $toolDir --configuration $Configuration --nologo --verbosity quiet
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed."
    exit $LASTEXITCODE
}

Write-Host "Running against $RepoRoot..." -ForegroundColor Cyan
dotnet run --project $toolDir --configuration $Configuration --no-build --no-restore -- $RepoRoot
exit $LASTEXITCODE
