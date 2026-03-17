<#
.SYNOPSIS
    Bootstrap the development environment.
.DESCRIPTION
    Installs Python dependencies with uv, verifies Foundry is present,
    and installs pre-commit hooks.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "=== Smart Contract Vuln Scanner - Setup ===" -ForegroundColor Cyan

# Check uv
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: uv is not installed. Install it from https://docs.astral.sh/uv/" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] uv found: $(uv --version)" -ForegroundColor Green

# Sync Python dependencies
Write-Host "`nSyncing Python dependencies..." -ForegroundColor Yellow
uv sync
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: uv sync failed" -ForegroundColor Red; exit 1 }
Write-Host "[OK] Python dependencies installed" -ForegroundColor Green

# Install pre-commit hooks
Write-Host "`nInstalling pre-commit hooks..." -ForegroundColor Yellow
uv run pre-commit install
if ($LASTEXITCODE -ne 0) { Write-Host "WARN: pre-commit install failed (non-fatal)" -ForegroundColor Yellow }
else { Write-Host "[OK] Pre-commit hooks installed" -ForegroundColor Green }

# Check Foundry
Write-Host ""
if (-not (Get-Command forge -ErrorAction SilentlyContinue)) {
    Write-Host "WARN: forge (Foundry) is not installed." -ForegroundColor Yellow
    Write-Host "      Install it from https://getfoundry.sh or:" -ForegroundColor Yellow
    Write-Host "      Invoke-WebRequest -Uri https://github.com/foundry-rs/foundry/releases/latest/download/foundry_nightly_win32_amd64.zip -OutFile foundry.zip" -ForegroundColor Yellow
} else {
    Write-Host "[OK] forge found: $(forge --version)" -ForegroundColor Green
}

Write-Host "`n=== Setup complete ===" -ForegroundColor Cyan
