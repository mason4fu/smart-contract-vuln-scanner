# Demo Contracts for Class Presentation

This page documents the presentation-focused contracts under `contracts/src/demo/`, plus a few **scanner fixtures** that intentionally live outside the Foundry `src` tree.

## Presentation order (class)

1. **Reentrancy and integer arithmetic (SWC-107, SWC-101)** — source-level scans only; commands in [Reentrancy & arithmetic demos](#reentrancy--arithmetic-demos-source-only).
2. **Access control and unchecked external calls (SWC-105, SWC-104)** — later segment; commands in the tables below.

---

## Reentrancy & arithmetic demos (source-only)

These runs use the Solidity AST pipeline only (no `--bytecode-only`). Pre-0.8 arithmetic stays in `tests/fixtures/` so the repo keeps a single Foundry `solc_version` for `contracts/src`.

| Contract / fixture | Concept | Vulnerable or Safe | Exact scanner command | Expected findings summary | Caveats |
|---|---|---|---|---|---|
| `contracts/src/demo/DemoReentrancyVulnerable.sol` | External call before balance write | Vulnerable | `uv run scanner scan contracts/src/demo/DemoReentrancyVulnerable.sol --detector reentrancy --format text --output reports/demo` | At least one SWC-107 (HIGH): external interaction before state update on `withdraw` | Heuristic ordering signal, not a proof of exploitable reentrancy. |
| `contracts/src/demo/DemoReentrancySafe.sol` | CEI: state decremented before external call | Safe | `uv run scanner scan contracts/src/demo/DemoReentrancySafe.sol --detector reentrancy --format text --output reports/demo` | `No findings.` | Negative control for the same detector. |
| `tests/fixtures/ArithmeticPatterns.sol` | Pre-0.8 wrapping risk on `+=` / `*` paths | Mixed (vulnerable + safe examples in one file) | `uv run scanner scan tests/fixtures/ArithmeticPatterns.sol --detector arithmetic --solc-version 0.4.25 --format text --output reports/demo` | SWC-101 on `unguardedAdd` and `payout`; guarded patterns suppressed | Must pass `--solc-version 0.4.25`. Kept under `tests/fixtures/` to avoid a second solc in Foundry `src`. |
| `contracts/src/demo/DemoArithmeticSafe08.sol` | Default checked math on 0.8 | Safe | `uv run scanner scan contracts/src/demo/DemoArithmeticSafe08.sol --detector arithmetic --format text --output reports/demo` | `No findings.` | Shows version gating: default 0.8 arithmetic is not reported. |
| `contracts/src/demo/DemoArithmeticUnchecked08.sol` | `unchecked` restores wrap risk | Vulnerable | `uv run scanner scan contracts/src/demo/DemoArithmeticUnchecked08.sol --detector arithmetic --format text --output reports/demo` | SWC-101 on `incrementUnchecked` | On 0.8+, detector focuses on explicit `unchecked` blocks (and similar). |

---

## Access-Control Demos (No tx.origin)

| Contract | Concept | Vulnerable or Safe | Source-demo friendly | Bytecode-demo friendly | Exact scanner command | Expected findings summary | Caveats |
|---|---|---|---|---|---|---|---|
| `contracts/src/demo/DemoAccessControlMissingGuard.sol` | Public owner reassignment with no auth guard | Vulnerable | Yes | No | `uv run scanner scan contracts/src/demo/DemoAccessControlMissingGuard.sol --detector access-control --format text --output reports/demo` | 1 finding: `Unguarded admin-surface mutation` (SWC-105, HIGH) on `setOwner` | Bytecode-only mode does not report this pattern without `tx.origin` signal. |
| `contracts/src/demo/DemoAccessControlAdminChange.sol` | Public admin reassignment with guarded contrast | Vulnerable | Yes | No | `uv run scanner scan contracts/src/demo/DemoAccessControlAdminChange.sol --detector access-control --format text --output reports/demo` | 1 finding: `Unguarded admin-surface mutation` (SWC-105, HIGH) on `setAdmin` | `setAdminSafely` is intentionally present as a side-by-side safe reference. |
| `contracts/src/demo/DemoAccessControlRoleGrant.sol` | Unguarded role/admin mapping write | Vulnerable | Yes | No | `uv run scanner scan contracts/src/demo/DemoAccessControlRoleGrant.sol --detector access-control --format text --output reports/demo` | 1 finding: `Unguarded role grant` (SWC-105, HIGH) on `grantRole` | `grantRoleSafely` is intentionally present for immediate contrast. |
| `contracts/src/demo/DemoAccessControlSafe.sol` | Owner-guarded admin surface with modifier and inline state updates | Safe | Yes | No | `uv run scanner scan contracts/src/demo/DemoAccessControlSafe.sol --detector access-control --format text --output reports/demo` | `No findings.` | Safe negative control for this detector section. |

### Access-control bytecode note

For this demo scope (excluding `tx.origin`), bytecode-only access-control output is not meaningful for proving `msg.sender` authorization quality.

Reference check command:

```powershell
uv run scanner scan contracts/src/demo/DemoAccessControlMissingGuard.sol --detector access-control --bytecode-only --format text --output reports/demo
```

Expected output: `No findings.`

This is expected and does not indicate a source-detector issue.

## Unchecked External Call Demos

| Contract | Concept | Vulnerable or Safe | Source-demo friendly | Bytecode-demo friendly | Exact scanner command | Expected findings summary | Caveats |
|---|---|---|---|---|---|---|---|
| `contracts/src/demo/DemoUncheckedCallIgnored.sol` | Standalone low-level `.call` result ignored | Vulnerable | Yes | No (current heuristic outcome) | `uv run scanner scan contracts/src/demo/DemoUncheckedCallIgnored.sol --detector unchecked-external-calls --format text --output reports/demo` | 1 finding: `Unchecked external call result` (SWC-104, MEDIUM) on `ping` | Bytecode-only scan currently returns no findings for this tiny contract. |
| `contracts/src/demo/DemoUncheckedCallAssignedUnused.sol` | Success assigned but not used as failure gate | Vulnerable | Yes | No (current heuristic outcome) | `uv run scanner scan contracts/src/demo/DemoUncheckedCallAssignedUnused.sol --detector unchecked-external-calls --format text --output reports/demo` | 1 finding: `Unchecked external call result` (SWC-104, MEDIUM) on `notify` | Uses minimal syntax close to real mistakes; no detector-specific hacks. |
| `contracts/src/demo/DemoUncheckedCallSafeRequire.sol` | Safe gating with `require(success)` | Safe | Yes | N/A | `uv run scanner scan contracts/src/demo/DemoUncheckedCallSafeRequire.sol --detector unchecked-external-calls --format text --output reports/demo` | `No findings.` | Safe negative control. |
| `contracts/src/demo/DemoUncheckedCallSafeRevert.sol` | Safe gating with `if (!success) revert` | Safe | Yes | N/A | `uv run scanner scan contracts/src/demo/DemoUncheckedCallSafeRevert.sol --detector unchecked-external-calls --format text --output reports/demo` | `No findings.` | Safe negative control. |
| `contracts/src/demo/DemoUncheckedCallMixed.sol` | Unsafe event-only observation plus safe revert branch | Mixed (vulnerable + safe) | Yes | No (current heuristic outcome) | `uv run scanner scan contracts/src/demo/DemoUncheckedCallMixed.sol --detector unchecked-external-calls --format text --output reports/demo` | 1 finding: `Probably unchecked external call result` (SWC-104, MEDIUM) on `notifyUnchecked`; no finding expected on `notifyChecked` | Good for teaching why logging success is not the same as gating on success. |

### Bytecode-friendly unchecked-call fallback

For a reliable bytecode-only classroom demo in this repo, use the existing fixture:

```powershell
uv run scanner scan tests/fixtures/UncheckedExternalCalls.sol --detector unchecked-external-calls --bytecode-only --format text --output reports/demo
```

Expected output: at least one SWC-104 bytecode finding, often a mix of:
- `Unchecked external call result (bytecode)` (MEDIUM)
- `Ambiguous external call result handling (bytecode)` (LOW)

## Fast Demo Command Set

From repo root, run these in sequence.

**Part 1 — reentrancy & arithmetic (source-only):**

```powershell
uv run scanner scan contracts/src/demo/DemoReentrancyVulnerable.sol --detector reentrancy --format text --output reports/demo
uv run scanner scan contracts/src/demo/DemoReentrancySafe.sol --detector reentrancy --format text --output reports/demo
uv run scanner scan tests/fixtures/ArithmeticPatterns.sol --detector arithmetic --solc-version 0.4.25 --format text --output reports/demo
uv run scanner scan contracts/src/demo/DemoArithmeticSafe08.sol --detector arithmetic --format text --output reports/demo
uv run scanner scan contracts/src/demo/DemoArithmeticUnchecked08.sol --detector arithmetic --format text --output reports/demo
```

**Part 2 — access control & unchecked external calls:**

```powershell
uv run scanner scan contracts/src/demo/DemoAccessControlMissingGuard.sol --detector access-control --format text --output reports/demo
uv run scanner scan contracts/src/demo/DemoAccessControlAdminChange.sol --detector access-control --format text --output reports/demo
uv run scanner scan contracts/src/demo/DemoAccessControlRoleGrant.sol --detector access-control --format text --output reports/demo
uv run scanner scan contracts/src/demo/DemoAccessControlSafe.sol --detector access-control --format text --output reports/demo
uv run scanner scan contracts/src/demo/DemoUncheckedCallIgnored.sol --detector unchecked-external-calls --format text --output reports/demo
uv run scanner scan contracts/src/demo/DemoUncheckedCallAssignedUnused.sol --detector unchecked-external-calls --format text --output reports/demo
uv run scanner scan contracts/src/demo/DemoUncheckedCallSafeRequire.sol --detector unchecked-external-calls --format text --output reports/demo
uv run scanner scan contracts/src/demo/DemoUncheckedCallSafeRevert.sol --detector unchecked-external-calls --format text --output reports/demo
uv run scanner scan contracts/src/demo/DemoUncheckedCallMixed.sol --detector unchecked-external-calls --format text --output reports/demo
```

These commands require no external dataset and are presentation-ready.
