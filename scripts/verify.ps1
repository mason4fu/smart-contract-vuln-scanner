<#
.SYNOPSIS
    Full verification: lint, test, and build.
.DESCRIPTION
    Runs the complete CI-equivalent verification locally:
    lint, format check, Python tests, Foundry build, Foundry tests.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$failed = $false

Write-Host "=== Full Verification ===" -ForegroundColor Cyan

# 1. Lint
Write-Host "`n--- Ruff lint ---" -ForegroundColor Yellow
uv run ruff check src/ tests/
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: Lint errors found" -ForegroundColor Red
    $failed = $true
} else {
    Write-Host "[OK] Lint passed" -ForegroundColor Green
}

# 2. Format check
Write-Host "`n--- Ruff format check ---" -ForegroundColor Yellow
uv run ruff format --check src/ tests/
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: Formatting issues found (run: uv run ruff format src/ tests/)" -ForegroundColor Red
    $failed = $true
} else {
    Write-Host "[OK] Format check passed" -ForegroundColor Green
}

# 3. Python tests
Write-Host "`n--- Python tests ---" -ForegroundColor Yellow
uv run pytest
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: Python tests failed" -ForegroundColor Red
    $failed = $true
} else {
    Write-Host "[OK] Python tests passed" -ForegroundColor Green
}

# 4. Foundry build
if (Get-Command forge -ErrorAction SilentlyContinue) {
    Write-Host "`n--- Forge build ---" -ForegroundColor Yellow
    forge build
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: Forge build failed" -ForegroundColor Red
        $failed = $true
    } else {
        Write-Host "[OK] Forge build passed" -ForegroundColor Green
    }

    # 5. Foundry tests
    Write-Host "`n--- Forge test ---" -ForegroundColor Yellow
    forge test -v
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: Forge tests failed" -ForegroundColor Red
        $failed = $true
    } else {
        Write-Host "[OK] Forge tests passed" -ForegroundColor Green
    }
} else {
    Write-Host "`nSKIP: forge not installed, skipping Foundry checks" -ForegroundColor Yellow
}

# Summary
Write-Host ""
if ($failed) {
    Write-Host "=== VERIFICATION FAILED ===" -ForegroundColor Red
    exit 1
} else {
    Write-Host "=== ALL CHECKS PASSED ===" -ForegroundColor Green
}
