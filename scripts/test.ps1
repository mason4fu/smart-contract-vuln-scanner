<#
.SYNOPSIS
    Run all tests (Python and Foundry).
.DESCRIPTION
    Runs pytest for Python tests and forge test for Solidity tests.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$failed = $false

Write-Host "=== Running Python Tests ===" -ForegroundColor Cyan
uv run pytest
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: Python tests failed" -ForegroundColor Red
    $failed = $true
} else {
    Write-Host "[OK] Python tests passed" -ForegroundColor Green
}

Write-Host "`n=== Running Foundry Tests ===" -ForegroundColor Cyan
if (Get-Command forge -ErrorAction SilentlyContinue) {
    forge test -v
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: Foundry tests failed" -ForegroundColor Red
        $failed = $true
    } else {
        Write-Host "[OK] Foundry tests passed" -ForegroundColor Green
    }
} else {
    Write-Host "SKIP: forge not found, skipping Foundry tests" -ForegroundColor Yellow
}

if ($failed) {
    Write-Host "`n=== Some tests FAILED ===" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`n=== All tests passed ===" -ForegroundColor Green
}
