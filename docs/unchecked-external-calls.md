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
- bounded aliases such as `bool handled = success; require(handled)`
- inverted aliases such as `bool failed = !success; if (failed) revert`
- bounded private/internal helper checks such as `_requireSuccess(success)`
- returning the success value from the current function
- event-only failure observers such as `if (!success) emit Failed(...)` when
  the failure branch has no other effects and the function has no later
  continuation effects

Reported patterns include:

- standalone low-level calls such as `target.call("")`
- tuple assignment where `success` is assigned but never checked
- tuple assignment where only returndata is captured
- success values used only in logs, state writes, or non-gating calls
- event-only failure observers followed by state mutation, another call, value
  transfer, or any other meaningful continuation effect
- observer branches that also mutate state, assign values, or perform calls
- tautological or non-failure-only observer conditions such as `!success || true`
- helpers that only log, mutate state, call non-gating functions, or `return`
  from the helper without terminating the caller
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

The primary evaluation uses one-to-one line-level matching with a default
`+/-6` line tolerance. Compile failures are reported and excluded from
precision, recall, and F1. SolidiFI `Unchecked-Send` samples in this subset are
reported separately because they use `.transfer(...)`, which is outside this
detector's SWC-104 low-level-call scope.

| Primary scoped dataset | TP | FP | FN | Precision | Recall | F1 |
|---------|----|----|----|-----------|--------|----|
| SmartBugs Curated unchecked subset | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| SolidiFI Unhandled-Exceptions subset | 53 | 0 | 6 | 1.000 | 0.898 | 0.946 |
| Not-So-Smart-Contracts unchecked external call | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Primary scoped aggregate | 67 | 0 | 6 | 1.000 | 0.918 | 0.957 |

Raw all-label diagnostics, including the out-of-scope `.transfer(...)` labels,
are still printed by the evaluator. On the current subset the raw aggregate is
TP=67, FP=0, FN=65, precision=1.000, recall=0.508, F1=0.673.

The remaining six scoped SolidiFI `Unhandled-Exceptions` false negatives are
labels on `if (!addr.send(...) || 1==1) { revert(); }` patterns. The detector
keeps these classified as checked because failure cannot continue past the
always-reverting branch.

Held-out Slither validation used exact source-line matching against the
`UncheckedLowLevel` and `UncheckedSend` snapshot expression lines for Solidity
0.4.25, 0.5.16, 0.6.11, and 0.7.6 fixtures:

| Held-out Slither subset | TP | FP | FN | Precision | Recall | F1 |
|---------|----|----|----|-----------|--------|----|
| unchecked-lowlevel | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| unchecked-send | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Combined | 8 | 0 | 0 | 1.000 | 1.000 | 1.000 |

## Known Limitations

- No full CFG, symbolic execution, or interprocedural dataflow.
- Inline assembly and Yul are handled only through bytecode heuristics.
- Checks far from the call or through complex helper chains may be missed.
  Helper reasoning is limited to bounded private/internal bool-gating chains.
- Bytecode-only mode can false-positive optimized code that stores and checks
  success later.
- The scanner does not reason about whether the target account exists.
- High-level external calls and `.transfer(...)` are intentionally out of scope.
