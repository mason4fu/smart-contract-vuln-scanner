# Development Environment Setup

Step-by-step guide for getting started on Windows.

## Prerequisites

1. **Python 3.12+** – Download from [python.org](https://www.python.org/downloads/)
2. **uv** – Python package/environment manager
3. **Foundry** – Solidity toolchain (forge, cast, anvil)
4. **Git** – Version control
5. **PowerShell 7+** – Recommended for running scripts (`pwsh`)

## Install uv

```powershell
irm https://astral.sh/uv/install.ps1 | iex
```

Restart your terminal after installing.

## Install Foundry

```powershell
# Download and extract
$url = "https://github.com/foundry-rs/foundry/releases/latest/download/foundry_nightly_win32_amd64.zip"
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\foundry.zip"
New-Item -ItemType Directory -Force "$env:USERPROFILE\.foundry\bin" | Out-Null
Expand-Archive "$env:TEMP\foundry.zip" -DestinationPath "$env:USERPROFILE\.foundry\bin" -Force

# Add to PATH permanently (run once)
[Environment]::SetEnvironmentVariable(
    "Path",
    "$env:USERPROFILE\.foundry\bin;$([Environment]::GetEnvironmentVariable('Path', 'User'))",
    "User"
)
```

Restart your terminal, then verify with `forge --version`.

## Clone and Setup

```powershell
git clone https://github.com/mason4fu/smart-contract-vuln-scanner.git
cd smart-contract-vuln-scanner
pwsh scripts/setup.ps1
```

The setup script will:
- Install Python dependencies via `uv sync`
- Install pre-commit hooks
- Verify that Foundry is available

## Verify Everything Works

```powershell
pwsh scripts/verify.ps1
```

This runs lint, format checks, Python tests, forge build, and forge tests.

## Environment File

Copy `.env.example` to `.env` to customize local settings:

```powershell
Copy-Item .env.example .env
```

Edit `.env` to change the Solidity compiler version, output directory, or log level.

## Editor Setup

The `.editorconfig` file configures consistent formatting. Most editors
(VS Code, IntelliJ, etc.) support it natively or via plugin.

Recommended VS Code extensions:
- Python (Microsoft)
- Solidity (Nomic Foundation)
- EditorConfig for VS Code
- Ruff (Astral)
