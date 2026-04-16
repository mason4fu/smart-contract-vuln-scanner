<#
.SYNOPSIS
    Run presentation demo scans for access-control and unchecked external calls.
.DESCRIPTION
    Executes scanner commands for demo contracts in contracts/src/demo and prints
    clear section headers. Includes vulnerable and safe examples plus a
    bytecode-only fallback for unchecked external calls.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$failed = $false

function Invoke-DemoScan {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
    Write-Host ("uv " + ($Args -join " ")) -ForegroundColor DarkGray

    uv @Args
    $exitCode = if ($null -eq $LASTEXITCODE) { 1 } else { $LASTEXITCODE }
    if ($exitCode -ne 0) {
        Write-Host "FAIL: $Title" -ForegroundColor Red
        $script:failed = $true
    } else {
        Write-Host "[OK] $Title" -ForegroundColor Green
    }
}

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "FAIL: uv not found on PATH" -ForegroundColor Red
    exit 1
}

Write-Host "Demo scan output directory: reports/demo" -ForegroundColor Yellow

$scanSteps = @(
    @{
        Title = "Access Control - Missing Guard (vulnerable)"
        Args = @("run", "scanner", "scan", "contracts/src/demo/DemoAccessControlMissingGuard.sol", "--detector", "access-control", "--format", "text", "--output", "reports/demo")
    },
    @{
        Title = "Access Control - Admin Change (vulnerable)"
        Args = @("run", "scanner", "scan", "contracts/src/demo/DemoAccessControlAdminChange.sol", "--detector", "access-control", "--format", "text", "--output", "reports/demo")
    },
    @{
        Title = "Access Control - Role Grant (vulnerable)"
        Args = @("run", "scanner", "scan", "contracts/src/demo/DemoAccessControlRoleGrant.sol", "--detector", "access-control", "--format", "text", "--output", "reports/demo")
    },
    @{
        Title = "Access Control - Safe Contract (negative control)"
        Args = @("run", "scanner", "scan", "contracts/src/demo/DemoAccessControlSafe.sol", "--detector", "access-control", "--format", "text", "--output", "reports/demo")
    },
    @{
        Title = "Unchecked Calls - Ignored Result (vulnerable)"
        Args = @("run", "scanner", "scan", "contracts/src/demo/DemoUncheckedCallIgnored.sol", "--detector", "unchecked-external-calls", "--format", "text", "--output", "reports/demo")
    },
    @{
        Title = "Unchecked Calls - Assigned Unused (vulnerable)"
        Args = @("run", "scanner", "scan", "contracts/src/demo/DemoUncheckedCallAssignedUnused.sol", "--detector", "unchecked-external-calls", "--format", "text", "--output", "reports/demo")
    },
    @{
        Title = "Unchecked Calls - Safe Require (negative control)"
        Args = @("run", "scanner", "scan", "contracts/src/demo/DemoUncheckedCallSafeRequire.sol", "--detector", "unchecked-external-calls", "--format", "text", "--output", "reports/demo")
    },
    @{
        Title = "Unchecked Calls - Safe Revert (negative control)"
        Args = @("run", "scanner", "scan", "contracts/src/demo/DemoUncheckedCallSafeRevert.sol", "--detector", "unchecked-external-calls", "--format", "text", "--output", "reports/demo")
    },
    @{
        Title = "Unchecked Calls - Mixed Pattern"
        Args = @("run", "scanner", "scan", "contracts/src/demo/DemoUncheckedCallMixed.sol", "--detector", "unchecked-external-calls", "--format", "text", "--output", "reports/demo")
    },
    @{
        Title = "Unchecked Calls - Bytecode Fallback Fixture"
        Args = @("run", "scanner", "scan", "tests/fixtures/UncheckedExternalCalls.sol", "--detector", "unchecked-external-calls", "--bytecode-only", "--format", "text", "--output", "reports/demo")
    }
)

foreach ($step in $scanSteps) {
    Invoke-DemoScan -Title $step.Title -Args $step.Args
}

if ($failed) {
    Write-Host "`n=== Demo scan completed with failures ===" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== Demo scan completed successfully ===" -ForegroundColor Green
