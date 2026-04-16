# Demo Contracts for Class Presentation

This page documents the presentation-focused contracts under `contracts/src/demo/`.

Scope for this section:
- Access-control flaws excluding `tx.origin`
- Unchecked external calls (SWC-104)
- Small contracts that are easy to explain live

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

From repo root, run these in sequence:

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
