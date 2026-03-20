# Repository Map

Quick reference for where everything lives and where new code should go.

## Top-Level Layout

| Path | Purpose |
|------|---------|
| `src/scanner/` | Python scanner package (all analysis code) |
| `contracts/src/` | Solidity fixture contracts |
| `contracts/test/` | Foundry/Forge tests for Solidity |
| `tests/` | Python tests (pytest) |
| `scripts/` | PowerShell helper scripts |
| `samples/` | Sample inputs and compiled outputs |
| `reports/` | Generated reports (gitignored) |
| `docs/` | Developer documentation |
| `lib/` | Foundry dependencies (forge-std) |
| `.github/workflows/` | CI pipeline definitions |

## Python Package (`src/scanner/`)

| Module | What goes here |
|--------|---------------|
| `cli.py` | CLI commands and argument parsing |
| `config.py` | Configuration loading and validation |
| `compiler/` | Solidity compilation, solc management |
| `ast/` | AST extraction, traversal, querying |
| `bytecode/` | Bytecode extraction, loading, disassembly |
| `models/` | Data models: Finding, Severity, SourceLocation |
| `output/` | Report rendering: JSON, text, future SARIF |
| `utils/` | Shared helpers: paths, logging, hashing |
| `detectors/` | *(to be created)* Individual vulnerability detectors |

## Where to Put New Code

| If you're adding... | Put it in... |
|---------------------|-------------|
| A new detector | `src/scanner/detectors/<name>.py` |
| A new data model | `src/scanner/models/` |
| AST analysis helpers | `src/scanner/ast/` |
| Bytecode analysis helpers | `src/scanner/bytecode/` |
| A new CLI command | `src/scanner/cli.py` |
| A new output format | `src/scanner/output/` |
| A Python test | `tests/test_<name>.py` |
| A Solidity fixture | `contracts/src/<Name>.sol` |
| A Forge test | `contracts/test/<Name>.t.sol` |
| A sample contract | `samples/contracts/` |
| Documentation | `docs/` |

## Test Organization

| Test file | What it tests |
|-----------|--------------|
| `tests/test_imports.py` | All package imports succeed |
| `tests/test_cli.py` | CLI help, version, sub-commands |
| `tests/test_paths.py` | Path resolution, config loading |
| `tests/test_models.py` | Finding creation, serialization, rendering |
| `contracts/test/*.t.sol` | Solidity fixtures compile and behave correctly |

## Configuration Files

| File | Purpose |
|------|---------|
| `pyproject.toml` | Python project metadata, deps, tool config |
| `foundry.toml` | Foundry/Forge settings |
| `.python-version` | Pinned Python version |
| `.editorconfig` | Editor formatting rules |
| `.pre-commit-config.yaml` | Pre-commit hook definitions |
| `.env.example` | Template for local environment variables |
| `remappings.txt` | Solidity import remappings for Foundry |
| `Makefile` | Make targets (optional, mostly for Linux/macOS) |
