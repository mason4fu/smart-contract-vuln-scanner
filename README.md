# Smart Contract Vulnerability Scanner

A static-analysis tool for detecting vulnerabilities in Solidity smart contracts.
Supports both **source-level (AST)** and **bytecode-level (EVM)** analysis.

> **CS 521 – Foundations in Blockchain** · Group Project

---

## Status

| Area | Status |
|------|--------|
| Repository structure | ✅ Complete |
| Python package scaffold | ✅ Complete |
| Foundry workspace | ✅ Complete |
| CI pipelines | ✅ Complete |
| Smoke tests | ✅ Complete |
| Vulnerability detectors | ✅ Complete (access-control, reentrancy, unchecked external calls, arithmetic) |
| Full analysis pipeline | ✅ Complete |

The scanner includes access-control, reentrancy, unchecked external call, and
arithmetic detectors with source-level AST analysis and bytecode-level EVM
analysis. Run
`uv run scanner scan <file.sol>` to start scanning.

---

## Usage

### Scan a Solidity file

```bash
uv run scanner scan contracts/MyContract.sol
uv run scanner scan contracts/MyContract.sol --format json
```

### Scan a directory

```bash
uv run scanner scan contracts/ --format text
```

### Scan pre-compiled output

```bash
uv run scanner scan out/MyContract.json
```

### Scan raw bytecode

```bash
uv run scanner scan MyContract.bin
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--format`, `-f` | `text` | Output format: `json` or `text` |
| `--output`, `-o` | `reports/` | Report output directory |
| `--detector`, `-d` | all | Run only a specific detector |
| `--bytecode-only` | false | Skip source analysis |
| `--solc-version` | `0.8.28` | Solidity compiler version |

## Detectors

### `access-control` (implemented)

Detects access control vulnerabilities in Solidity contracts.

| Rule | ID | Severity | Description |
|------|----|----------|-------------|
| tx.origin Auth | SWC-115 | HIGH | Authorization using tx.origin instead of msg.sender |
| Callable Constructor-like Init | SWC-118 | HIGH/MEDIUM | Externally callable constructor-like initialization that mutates ownership |
| Missing Auth Guard | SWC-105 | HIGH | Sensitive public/external functions with no authorization check |
| Uninitialized Owner | SWC-105 | MEDIUM | Owner variable declared but never set in constructor |
| Dangerous Renounce | SWC-106 | LOW | renounceOwnership() with no two-step transfer protection |
| Unguarded Role Grant | SWC-105 | HIGH | Role/privilege grant function with no authorization guard |

See [`docs/access-control-detector.md`](docs/access-control-detector.md) for details.

### `reentrancy` (implemented)

Detects potential reentrancy vulnerabilities in Solidity contracts (external
interaction before state effects / checks-effects-interactions risk).

| Rule | ID | Severity | Description |
|------|----|----------|-------------|
| External call before state update | SWC-107 | HIGH | Function performs external CALL-family interaction before a later state write (checks-effects-interactions violation risk) |
| Bytecode corroboration (confidence boost) | SWC-107 | MEDIUM/HIGH confidence | Deployed runtime bytecode shows CALL-family opcode before later SSTORE, used as corroborating heuristic |

Examples:

```powershell
uv run scanner scan tests/fixtures/ReentrancyPatterns.sol --detector reentrancy
uv run scanner scan contracts/src --detector reentrancy --format json
```

See `src/scanner/detectors/reentrancy.py` and `tests/test_reentrancy_detector.py` for details.

### `unchecked-external-calls` (implemented)

Detects unchecked success handling for Solidity low-level external calls.

| Rule | ID | Severity | Description |
|------|----|----------|-------------|
| Unchecked low-level call result | SWC-104 | MEDIUM | `.call`, `.delegatecall`, `.staticcall`, or `.send` success result is ignored, discarded, or not used as a failure gate |
| Ambiguous bytecode call handling | SWC-104 | LOW/MEDIUM | Runtime bytecode contains CALL-family opcodes whose success handling is unclear without source |

Examples:

```powershell
uv run scanner scan tests/fixtures/UncheckedExternalCalls.sol --detector unchecked-external-calls
uv run scanner scan contracts/src --detector unchecked-external-calls --format json
uv run scanner scan out/MyContract.sol/MyContract.json --detector unchecked-external-calls
uv run scanner scan sample.bin --detector unchecked-external-calls --bytecode-only --format json
```

The detector treats `require(success)`, `assert(success)`, `if (!success) revert`,
bounded success aliases such as `handled = success` or `failed = !success`,
private/internal helper checks, returning success to the caller, and event-only
failure observers with no later continuation effects as handled.
It does not target high-level typed external calls or `.transfer(...)`.

See [`docs/unchecked-external-calls.md`](docs/unchecked-external-calls.md) for details.

### `arithmetic` (implemented)

Detects potential integer overflow/underflow (SWC-101) for risky arithmetic:
`+`, `-`, `*`, compound assignments (`+=`, `-=`, `*=`), and unary `++` / `--`.

**Version gating:** Solidity `>=0.8.0` uses checked arithmetic by default, so the
detector only reports arithmetic inside `unchecked { ... }` unless the pragma
resolves to pre-0.8.

**Suppressions (precision-first):** Skips `library` contracts and constructors;
recognizes SafeMath-style `.add` / `.sub` / `.mul` usage; treats classic additive
overflow guards like `require(a + b >= a)` as sufficient for `+` when the guard
matches the operands.

| Rule | ID | Severity | Description |
|------|----|----------|-------------|
| Unchecked state/accounting arithmetic | SWC-101 | HIGH | Risky arithmetic updates state/accounting values without recognized guard |
| Sensitive-path arithmetic construction | SWC-101 | HIGH/MEDIUM | Arithmetic feeds transfer/mint/burn/value-sensitive behavior |
| Bytecode arithmetic hint | SWC-101 | LOW | Bytecode-only `ADD`/`SUB`/`MUL` near `SSTORE` heuristic (low confidence) |

Examples:

```bash
uv run scanner scan tests/fixtures/ArithmeticPatterns.sol --detector arithmetic --solc-version 0.4.25
uv run scanner scan tests/fixtures/ArithmeticSafe08.sol --detector arithmetic --format json
uv run scanner scan tests/fixtures/ArithmeticUnchecked08.sol --detector arithmetic --format json
```

```powershell
uv run scanner scan tests/fixtures/ArithmeticPatterns.sol --detector arithmetic --solc-version 0.4.25
uv run scanner scan sample.bin --detector arithmetic --bytecode-only --format json
```

Line-level benchmark labels live under [`datasets/arithmetic/`](datasets/arithmetic/).
Run [`scripts/evaluate_arithmetic.py`](scripts/evaluate_arithmetic.py) against that ground truth.

See [`docs/arithmetic-detector-spec.md`](docs/arithmetic-detector-spec.md) for the full rule/suppression matrix.

Implementation: `src/scanner/detectors/arithmetic.py` · Tests: `tests/test_arithmetic_detector.py`

## Evaluation Datasets

- **Access control**
  - SmartBugs Curated — compiled `15/18`, precision `1.000`, recall `1.000`, F1 `1.000`
  - Not-So-Smart-Contracts — compiled `3/3`, precision `1.000`, recall `1.000`, F1 `1.000`
  - SWC Registry pinned subset — compiled `10/10`, precision `1.000`, recall `1.000`, F1 `1.000`
- **Unchecked external calls**:
  - SmartBugs unchecked subset — precision 1.000, recall 1.000, F1=1.000
  - SolidiFI Unhandled-Exceptions scoped subset — precision 1.000, recall 0.898, F1=0.946
  - Not-So-Smart-Contracts unchecked external call — precision 1.000, recall 1.000, F1=1.000
  - Primary scoped aggregate — precision 1.000, recall 0.918, F1=0.957
  - Raw all-label diagnostic aggregate — precision 1.000, recall 0.508, F1=0.673
  - Held-out Slither unchecked-lowlevel/unchecked-send fixtures — precision 1.000, recall 1.000, F1=1.000
- **Arithmetic (SmartBugs curated arithmetic subset, line-level ±6)**:
  - Compiled 15/15
  - TP=21, FP=1, FN=2
  - precision 0.955, recall 0.913, F1=0.933
- **Reentrancy (SmartBugs curated reentrancy subset, structural heuristic)**:
  - Compiled 31/31
  - Contract recall 31/31 = 1.000
  - Line overlap at ±3 lines: 30/31 = 0.968

Saved benchmark artifacts for the final report live under `reports/final-report/`.
See `reports/final-report/summary.md` and [`docs/final-report-prep.md`](docs/final-report-prep.md).

Run the access control detector against the evaluation datasets:

```bash
uv run python scripts/evaluate_smartbugs.py
uv run python scripts/evaluate_smartbugs.py --output results.json
uv run python scripts/evaluate_nssc.py
uv run python scripts/fetch_swc_registry.py
uv run python scripts/evaluate_swc_registry.py
uv run python scripts/fetch_unchecked_call_datasets.py
uv run python scripts/evaluate_unchecked_calls.py
uv run python scripts/evaluate_arithmetic.py --output reports/arithmetic-eval.json
```

See [`docs/evaluation.md`](docs/evaluation.md) for methodology and results.

---

## Repository Structure

```
smart-contract-vuln-scanner/
├── src/scanner/             # Python scanner package
│   ├── cli.py               # CLI entrypoint (Typer)
│   ├── config.py            # Configuration (Pydantic)
│   ├── compiler/            # Solidity compilation via py-solc-x
│   ├── ast/                 # AST extraction and traversal
│   ├── bytecode/            # Bytecode loading and disassembly
│   ├── models/              # Shared data models (Finding, Severity)
│   ├── output/              # Report rendering (JSON, text)
│   └── utils/               # Path resolution, helpers
├── contracts/
│   ├── src/                 # Solidity fixture contracts
│   └── test/                # Foundry tests
├── tests/                   # Python tests (pytest)
├── scripts/                 # PowerShell scripts (Windows-friendly)
│   ├── setup.ps1            # Bootstrap environment
│   ├── test.ps1             # Run all tests
│   └── verify.ps1           # Full CI-equivalent check
├── samples/
│   ├── contracts/           # Sample Solidity inputs
│   └── compiled/            # Compiled output artifacts
├── reports/                 # Generated scan reports
├── docs/                    # Developer documentation
├── lib/                     # Foundry dependencies (forge-std)
├── .github/workflows/       # GitHub Actions CI
├── pyproject.toml           # Python project config
├── foundry.toml             # Foundry config
└── Makefile                 # Make targets (optional)
```

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| **Python** | ≥ 3.12 | [python.org](https://www.python.org/downloads/) |
| **uv** | latest | `irm https://astral.sh/uv/install.ps1 \| iex` |
| **Foundry** | latest | See [Foundry install](#foundry-setup) below |
| **Git** | any | [git-scm.com](https://git-scm.com/) |

---

## Windows Quickstart

```powershell
# 1. Clone the repo
git clone https://github.com/mason4fu/smart-contract-vuln-scanner.git
cd smart-contract-vuln-scanner

# 2. Run the setup script (installs deps, pre-commit hooks)
pwsh scripts/setup.ps1

# 3. Run all tests
pwsh scripts/test.ps1

# 4. Full verification (lint + format + tests + forge)
pwsh scripts/verify.ps1
```

### Python Environment Setup

```powershell
# Install uv (if not already installed)
irm https://astral.sh/uv/install.ps1 | iex

# Sync dependencies
uv sync

# Run Python tests
uv run pytest

# Run the CLI
uv run scanner --help
uv run scanner --version
```

### Foundry Setup

Download Foundry for Windows:

```powershell
# Download latest release
$url = "https://github.com/foundry-rs/foundry/releases/latest/download/foundry_nightly_win32_amd64.zip"
Invoke-WebRequest -Uri $url -OutFile foundry.zip
Expand-Archive foundry.zip -DestinationPath "$env:USERPROFILE\.foundry\bin" -Force
# Add to PATH (add this to your PowerShell profile for persistence)
$env:Path = "$env:USERPROFILE\.foundry\bin;$env:Path"

# Verify
forge --version
```

Then build and test contracts:

```powershell
forge build
forge test -v
```

---

## Running Checks

### Python only

```powershell
uv run pytest                              # tests
uv run ruff check src/ tests/              # lint
uv run ruff format src/ tests/             # auto-format
```

### Foundry only

```powershell
forge build                                # compile contracts
forge test -v                              # run Solidity tests
```

### Full verification

```powershell
pwsh scripts/verify.ps1                    # everything at once
```

---

## Branch Naming Convention

| Prefix | Purpose |
|--------|---------|
| `feature/<name>` | New features or detectors |
| `fix/<name>` | Bug fixes |
| `setup/<name>` | Tooling / infrastructure |
| `docs/<name>` | Documentation changes |
| `test/<name>` | Test additions |

Examples: `feature/reentrancy-detector`, `fix/ast-loader-crash`, `docs/add-examples`

---

## Contribution Workflow

1. Create a branch from `master`: `git checkout -b feature/my-detector`
2. Make changes in small, focused commits
3. Run `pwsh scripts/verify.ps1` before pushing
4. Push and open a Pull Request
5. Get at least one review before merging

---

## What to Build Next

Contributors should implement vulnerability detectors. Each detector should:

1. Live in a new module (e.g., `src/scanner/detectors/reentrancy.py`)
2. Accept compiler output (AST and/or bytecode) as input
3. Produce `Finding` objects (see `scanner.models.findings`)
4. Have corresponding tests in `tests/`
5. Have a Solidity fixture contract in `contracts/src/` if needed

### Suggested first detectors

- Reentrancy (unchecked external calls before state updates) — implemented
- Unchecked return values on low-level calls — implemented (`unchecked-external-calls`)
- Access control issues (missing `onlyOwner` patterns) — implemented
- Integer overflow/underflow (pre-0.8.0 patterns) — implemented (`arithmetic`)
- Further ideas: timestamp dependence, weak randomness, front-running heuristics

### Architecture pointers

- `scanner.compiler.solc` – compile Solidity and get AST + bytecode
- `scanner.ast.loader` – extract and walk ASTs
- `scanner.bytecode.loader` – extract bytecode from compiler output
- `scanner.bytecode.disasm` – disassemble bytecode via pyevmasm
- `scanner.models.findings` – the `Finding` model all detectors produce
- `scanner.output.report` – render findings into reports

See [`docs/architecture.md`](docs/architecture.md) for the full design overview.

---

## License

[MIT](LICENSE)
