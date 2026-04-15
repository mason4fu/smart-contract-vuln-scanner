# Arithmetic Detector Spec (SWC-101)

This document defines the **step-1 spec** for a new arithmetic detector focused on
integer overflow/underflow risks (SWC-101), with emphasis on Solidity
**pre-0.8.0** semantics.

## Goal

Detect high-signal arithmetic overflow/underflow issues while keeping false
positives low enough for practical auditing workflows.

## Scope

- In scope (v1):
  - Source-level detection over Solidity AST and compiler output metadata.
  - Arithmetic operators: `+`, `-`, `*`, `++`, `--`, `+=`, `-=`, `*=`.
  - State-impacting and value-sensitive contexts (state writes, transfer/mint
    amount construction, accounting updates, loop/index math used for writes).
  - Solidity versions where overflow/underflow is not automatically checked
    (`<0.8.0`), or where arithmetic is explicitly `unchecked`.
- Out of scope (v1):
  - Full symbolic execution and multi-transaction theorem proving.
  - Complete interprocedural range analysis across arbitrary call graphs.
  - Assembly/Yul precision beyond optional bytecode hints.

## Version Gating Policy

1. **Pre-0.8.0 contracts**: arithmetic is treated as potentially wrapping by
   default.
2. **0.8.0+ contracts**:
   - Default arithmetic is considered checked by compiler-generated guards.
   - Only operations inside `unchecked { ... }` blocks are considered reportable.
3. If exact pragma cannot be resolved, report at lower confidence unless there is
   strong contextual evidence of exploitability.

## Rule Matrix (Detection)

| Rule ID | Rule Name | SWC | Severity | Base Confidence | Trigger Pattern |
|---|---|---|---|---|---|
| A1 | Unchecked state arithmetic write | SWC-101 | HIGH | HIGH | State variable assigned/updated via risky arithmetic with no recognized guard |
| A2 | Unchecked balance/accounting arithmetic | SWC-101 | HIGH | HIGH | Balance/supply/credit/debt style variables modified via risky arithmetic without guard |
| A3 | Unchecked amount used for transfer/mint/burn | SWC-101 | HIGH | MEDIUM | Arithmetic-built amount flows into transfer-like sensitive action |
| A4 | Unchecked loop/index arithmetic affecting writes | SWC-101 | MEDIUM | MEDIUM | Arithmetic in loop/index expression may wrap and influence storage writes |
| A5 | Potentially unchecked arithmetic (insufficient context) | SWC-101 | MEDIUM | LOW | Arithmetic appears risky but version/guard context is incomplete |
| A6 | Bytecode arithmetic risk hint (optional fallback) | SWC-101 | LOW | LOW | Bytecode-only heuristic suggests arithmetic wrap risk without source proof |

## Suppression Matrix (False-Positive Controls)

| Suppression ID | Suppression Condition | Effect on Finding |
|---|---|---|
| S1 | Solidity `>=0.8.0` and expression not in `unchecked` | Suppress |
| S2 | Expression guarded by explicit bound check in same control path (e.g., `require(a + b >= a)` or equivalent for `-`/`*`) | Suppress |
| S3 | Operation performed via recognized SafeMath-style wrapper (e.g., `SafeMath.add/sub/mul`) | Suppress |
| S4 | Expression is compile-time constant-folded with safe bounds | Suppress |
| S5 | Arithmetic appears in non-state, non-sensitive temporary context only | Downgrade to LOW or suppress |
| S6 | Proven saturating/clamped logic immediately bounds output before use | Suppress or downgrade |
| S7 | Guard exists but only partially covers branches/paths | Keep finding, downgrade confidence by one level |

## Confidence Policy

- **HIGH**
  - Pre-0.8.0 (or `unchecked` in 0.8+) arithmetic directly mutates state or core
    accounting variables, with no valid suppression.
- **MEDIUM**
  - Risky arithmetic influences sensitive behavior but some context is inferred
    heuristically (e.g., value-flow inferred from naming or shallow analysis).
- **LOW**
  - Ambiguous context, missing version certainty, or bytecode-only fallback.

Confidence demotion rules:
- Unknown/ambiguous pragma: HIGH -> MEDIUM.
- Partial/branch-limited guard: HIGH -> MEDIUM or MEDIUM -> LOW.
- Bytecode-only path: force LOW.

## Severity Policy

- **HIGH**
  - Direct state/accounting corruption risk:
    - balance/supply/credit/debt updates,
    - privilege-affecting counters,
    - arithmetic feeding transfer/mint/burn paths with exploit impact.
- **MEDIUM**
  - Arithmetic may alter behavior or storage but exploitability is less direct or
    depends on additional conditions.
- **LOW**
  - Bytecode-only hints or weakly contextualized arithmetic warnings.

## Finding Template Policy

Each SWC-101 finding should include:
- detector name,
- title with rule ID and context,
- concise explanation of why operation may wrap,
- `swc_id = "SWC-101"`,
- severity + confidence per policy,
- contract/function/source location,
- remediation recommendation.

Recommended remediation text:
- "Use Solidity >=0.8 checked arithmetic or wrap operation with explicit bounds checks."
- "Use audited SafeMath-style operations for pre-0.8 code."

## Canonical Classification Examples (for implementation/tests)

### Expected TP (report)

1. `balance[msg.sender] += amount;` in Solidity 0.6 with no guard (A2, HIGH/HIGH).
2. `totalSupply = totalSupply + minted;` pre-0.8, no checks (A2, HIGH/HIGH).
3. `uint payout = stake * multiplier; token.transfer(msg.sender, payout);` pre-0.8
   without multiplication guard (A3, HIGH/MEDIUM).
4. `counter++;` in privileged accounting path pre-0.8 (A1, HIGH/HIGH).
5. `i++` in loop controlling storage writes where wrap can re-enter write range
   (A4, MEDIUM/MEDIUM).

### Expected TN (suppress)

6. Solidity 0.8 default arithmetic: `x += y;` outside `unchecked` (S1).
7. `z = a.add(b);` through recognized SafeMath wrapper (S3).
8. `require(a + b >= a); z = a + b;` same path bound check (S2).
9. Pure temporary arithmetic never persisted or used in sensitive action (S5).
10. Clamped arithmetic pattern with immediate strict cap before use (S6).

### Expected Borderline (report at reduced confidence)

11. Unknown pragma file with risky accounting update and no guard (A5, MEDIUM/LOW).
12. Guard exists only on one branch before shared update (S7 => confidence demotion).

## Initial Acceptance Criteria (Step 1 Complete)

Step 1 is considered complete when this policy is accepted and used as the
implementation contract for:
- detector rules (A1-A6),
- suppression logic (S1-S7),
- confidence/severity assignment,
- TP/TN/borderline test expectations.

## Step 2 — Labeled subset and expected outputs (complete)

Delivered artifacts:

- [`datasets/arithmetic/ground_truth.json`](../datasets/arithmetic/ground_truth.json) — 15 SmartBugs arithmetic contracts, **28** total labeled lines (`SWC-101`), paths relative to repo root under `smartbugs-curated/dataset/arithmetic/`.
- [`datasets/arithmetic/expected_outputs.md`](../datasets/arithmetic/expected_outputs.md) — human-readable manifest of expected vulnerable lines per file.
- [`datasets/arithmetic/README.md`](../datasets/arithmetic/README.md) — schema, tolerance defaults, regeneration instructions.
- [`scripts/generate_arithmetic_ground_truth.py`](../scripts/generate_arithmetic_ground_truth.py) — regenerates `ground_truth.json` from [`smartbugs-curated/vulnerabilities.json`](../smartbugs-curated/vulnerabilities.json).

Labels are merged from all `category: "arithmetic"` blocks per file in the SmartBugs metadata. Safe / 0.8 negative fixtures are reserved for pytest in later steps (see dataset README).
