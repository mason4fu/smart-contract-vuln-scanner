# Unchecked External Calls

## What It Detects

The `unchecked-external-calls` detector flags low-level external calls whose
success result is ignored or not used to gate failure handling:

- `.call(...)`
- `.delegatecall(...)`
- `.staticcall(...)`
- `.send(...)`
- legacy `.call.value(...)(...)` and related Solidity 0.4 call chains where the AST exposes them
- bytecode `CALL`, `DELEGATECALL`, `STATICCALL`, and legacy `CALLCODE`

The detector reports `SWC-104` findings. Normal high-level typed external calls
and `.transfer(...)` are not part of this rule.

## Why It Matters

Solidity low-level calls do not automatically bubble failure the same way normal
external calls do. `call`, `delegatecall`, and `staticcall` return a success
boolean plus returndata. `send` returns a success boolean. If that success value
is ignored, execution can continue after a failed transfer or external call.

## Source Analysis

Source analysis runs from the compiler standard JSON output. It reads the AST,
source content, and source locations to build `ExternalCallSite` records.

Handled patterns include:

- `require(success)` or `assert(success)`
- `if (!success) revert`, `throw`, `return`, or similar terminating branches
- bounded helper checks such as `_requireSuccess(success)`
- returning the success value from the current function

Reported patterns include:

- standalone low-level calls such as `target.call("")`
- tuple assignment where `success` is assigned but never checked
- tuple assignment where only returndata is captured
- success values used only in logs, state writes, or non-gating calls
- sensitive follow-up effects before a clear failure gate

Findings include source file, line, function, call kind, and evidence text.

## Bytecode Analysis

Bytecode analysis disassembles runtime bytecode with `pyevmasm` and scans for
CALL-family opcodes. It classifies nearby usage heuristically:

- `CALL; POP` is treated as clearly unchecked.
- `CALL ... JUMPI` is treated as checked or handled by conditional control flow.
- `CALL ... SSTORE`, `LOG*`, another call, or `SELFDESTRUCT` before a conditional
  branch is treated as probably unchecked.
- Other cases are reported as ambiguous, low-confidence bytecode findings.

This is intentionally not full symbolic execution. Bytecode-only findings should
be reviewed with source or source maps when available.

## Evaluation

Run:

```powershell
uv run python scripts/fetch_unchecked_call_datasets.py
uv run python scripts/evaluate_unchecked_calls.py --output reports/unchecked-call-eval.json
```

The current evaluation uses line-level matching with a default `+/-5` line
tolerance. Compile failures are reported and excluded from precision, recall,
and F1.

| Dataset | TP | FP | FN | Precision | Recall | F1 |
|---------|----|----|----|-----------|--------|----|
| SmartBugs Curated unchecked subset | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| SolidiFI Unchecked-Send / Unhandled-Exceptions subset | 29 | 4 | 71 | 0.879 | 0.290 | 0.436 |
| Not-So-Smart-Contracts unchecked external call | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Aggregate micro-average | 43 | 4 | 71 | 0.915 | 0.377 | 0.534 |

SolidiFI injects many variants under broad "Unchecked-Send" and
"Unhandled-Exceptions" labels. The low recall there is a known limitation of
this first practical pass, not a target for syntax-specific tuning.

## Known Limitations

- No full CFG, symbolic execution, or interprocedural dataflow.
- Inline assembly and Yul are handled only through bytecode heuristics.
- Checks far from the call or through complex helper chains may be missed.
- Bytecode-only mode can false-positive optimized code that stores and checks
  success later.
- The scanner does not reason about whether the target account exists.
- High-level external calls and `.transfer(...)` are intentionally out of scope.
