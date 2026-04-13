# Architecture

High-level design of the smart contract vulnerability scanner.

## Overview

The scanner is a **static analysis tool** that examines Solidity smart contracts
for known vulnerability patterns. It operates at two levels:

1. **Source-level analysis** – Works with the Solidity AST (Abstract Syntax Tree)
   to detect patterns in the contract's logical structure.
2. **Bytecode-level analysis** – Works with compiled EVM bytecode to detect
   patterns that are only visible after compilation.

## Pipeline

```
┌─────────────────┐
│  Solidity Source │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────┐
│  Compiler (solc) │────▶│ Compiler JSON │
└────────┬────────┘     └──────┬───────┘
         │                     │
    ┌────┴────┐          ┌─────┴──────┐
    ▼         ▼          ▼            ▼
┌──────┐ ┌────────┐ ┌─────────┐ ┌────────────┐
│  AST │ │Bytecode│ │Source Map│ │Storage Info│
└──┬───┘ └───┬────┘ └────┬────┘ └──────┬─────┘
   │         │           │             │
   ▼         ▼           │             │
┌──────────────────────────────────────────────┐
│              Detector Engine                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐     │
│  │Detector 1│ │Detector 2│ │Detector N│ ... │
│  └──────────┘ └──────────┘ └──────────┘     │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
                ┌──────────────┐
                │   Findings   │
                └──────┬───────┘
                       │
                       ▼
                ┌──────────────┐
                │    Report    │
                │ (JSON/text)  │
                └──────────────┘
```

## Module Responsibilities

### `scanner.compiler`
- Wraps py-solc-x for Solidity compilation
- Manages solc version installation
- Produces full compiler JSON output (AST, bytecode, source maps, ABI)
- Handles saving/loading compiled artifacts

### `scanner.ast`
- Extracts AST from compiler output
- Provides tree-walking and node-filtering utilities
- Extracts detector-specific source IR such as unchecked low-level call sites
- Future: visitor pattern for detectors

### `scanner.bytecode`
- Extracts creation and deployed bytecode
- Loads raw bytecode from files
- Disassembles to EVM instructions via pyevmasm
- Provides lightweight opcode heuristics for CALL-family result handling
- Future: control flow graph construction

### `scanner.models`
- `Finding` – represents a single vulnerability instance
- `Severity` – classification (critical/high/medium/low/info)
- `SourceLocation` – points into source code
- `ExternalCallSite`, `CallResultUsage`, `FollowupEffect` – unchecked call IR
- Future: `DetectorResult`, `ScanReport` aggregates

### `scanner.output`
- Renders findings into JSON, plain text
- Writes report files to disk
- Future: SARIF, markdown, HTML formats

### `scanner.config`
- Loads settings from environment / .env files
- Validates via Pydantic
- Provides defaults for solc version, output paths, log level

### `scanner.cli`
- Typer-based command-line interface
- `scan` command orchestrates the full pipeline
- Future: `compile`, `disasm`, `list-detectors` sub-commands

### `scanner.utils`
- Project root detection
- Path resolution (cross-platform)
- Future: logging setup, hashing

## Adding a New Detector

1. Create `src/scanner/detectors/<name>.py`
2. Implement a function or class that:
   - Accepts compiler output (AST dict, bytecode, or both)
   - Returns a list of `Finding` objects
3. Register it in a detector registry (to be created)
4. Add tests in `tests/test_<name>.py`
5. Add a Solidity fixture in `contracts/src/` if needed

## Foundry Side

The `contracts/` directory is a standard Foundry project:
- `contracts/src/` – Solidity source files (fixtures for testing)
- `contracts/test/` – Forge tests (`.t.sol` files)
- `lib/` – Foundry dependencies (forge-std)

Foundry is used **only** for:
- Compiling fixture contracts
- Validating contract behavior with Forge tests
- Generating compilation artifacts for the Python scanner

The Python scanner does **not** depend on Foundry at runtime. It uses
py-solc-x to compile Solidity independently.
