# Access Control Detector

The `access-control` detector identifies authorization flaws in Solidity smart contracts at both source (AST) and bytecode (EVM disassembly) levels.

## Detection Rules

### Rule 1: tx.origin Authorization (SWC-115)

**Severity**: HIGH | **Confidence**: HIGH (source), MEDIUM (bytecode)

Detects functions that use `tx.origin` for authorization decisions.

**Why it's dangerous**: `tx.origin` refers to the original external account that initiated the transaction chain. A malicious intermediate contract can trick a victim into executing a transaction, allowing the attacker to pass `tx.origin == owner` checks. Use `msg.sender` instead.

**Example (vulnerable)**:
```solidity
function withdraw() external {
    require(tx.origin == owner, "not owner"); // vulnerable
    payable(owner).transfer(address(this).balance);
}
```

**Example (safe)**:
```solidity
function withdraw() external {
    require(msg.sender == owner, "not owner"); // safe
    payable(owner).transfer(address(this).balance);
}
```

### Rule 2: Missing Authorization on Sensitive Function (SWC-105/106)

**Severity**: HIGH | **Confidence**: MEDIUM (source)

Detects public/external state-mutating functions that lack any authorization guard and perform sensitive operations.

**Sensitive operations include**:
- Ownership/admin changes
- Role grants or revocations
- Pause/unpause controls
- Upgrade or proxy configuration
- ETH/token withdrawal or transfer
- `selfdestruct` / `suicide`
- `delegatecall`

**Authorization guards recognized**:
- Modifiers containing `msg.sender` checks (e.g., `onlyOwner`)
- Inline `require(msg.sender == ...)` or `require(msg.sender != ...)`
- Inline `if (...) revert` with msg.sender condition
- One-hop: function calls internal helper that has an auth check

**Example (vulnerable)**:
```solidity
function changeOwner(address newOwner) public {
    owner = newOwner; // no auth guard!
}
```

**Example (safe)**:
```solidity
modifier onlyOwner() {
    require(msg.sender == owner, "not owner");
    _;
}

function changeOwner(address newOwner) external onlyOwner {
    owner = newOwner;
}
```

### Rule 3: Uninitialized Owner (SWC-105)

**Severity**: MEDIUM | **Confidence**: MEDIUM (source)

Detects contracts that declare an owner-like state variable but never assign it in the constructor or at declaration.

**Why it matters**: When `owner` is never initialized it defaults to `address(0)`. This either makes all owner-gated functions permanently inaccessible (locked contract) or, in some patterns, allows any caller to claim ownership by being the first to call an initialization function.

**Example (vulnerable)**:
```solidity
contract Vault {
    address public owner; // never set!

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function withdraw() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

**Example (safe)**:
```solidity
contract Vault {
    address public owner;

    constructor() {
        owner = msg.sender; // initialized in constructor
    }
}
```

**Remediation**: Set `owner = msg.sender` in the constructor, or assign an initial value at declaration (`address public owner = msg.sender` is not valid in Solidity, so always use the constructor).

---

### Rule 4: Dangerous Ownership Renounce (SWC-106)

**Severity**: LOW | **Confidence**: MEDIUM (source)

Detects a `renounceOwnership()` function that sets `owner` to `address(0)` without implementing a two-step confirmation pattern.

**Why it matters**: A single accidental or malicious call to `renounceOwnership()` permanently locks the contract from all owner-restricted operations. There is no recovery path once ownership is renounced to the zero address.

**Example (vulnerable)**:
```solidity
function renounceOwnership() external onlyOwner {
    owner = address(0); // irreversible in one step
}
```

**Example (safe — two-step transfer)**:
```solidity
address public pendingOwner;

function transferOwnership(address newOwner) external onlyOwner {
    pendingOwner = newOwner;
}

function acceptOwnership() external {
    require(msg.sender == pendingOwner, "not pending owner");
    owner = pendingOwner;
    pendingOwner = address(0);
}
```

**Remediation**: Replace single-step renounce with a two-step transfer pattern using `pendingOwner` + `acceptOwnership()`. If renouncing is intentional, add a time-lock or multi-sig confirmation.

---

### Rule 5: Unguarded Role Grant (SWC-105)

**Severity**: HIGH | **Confidence**: MEDIUM (source)

Detects public or external functions that write to role or permission mappings without any authorization guard.

**Why it matters**: Any caller can invoke such a function to grant themselves or others administrative privileges, leading to complete privilege escalation and contract takeover.

**Example (vulnerable)**:
```solidity
mapping(address => bool) public isAdmin;

function grantAdmin(address account) external {
    isAdmin[account] = true; // no auth check!
}
```

**Example (safe)**:
```solidity
mapping(address => bool) public isAdmin;

function grantAdmin(address account) external onlyOwner {
    isAdmin[account] = true;
}
```

**Remediation**: Add an `onlyOwner` modifier or an equivalent role-based access guard (e.g., `require(hasRole(ADMIN_ROLE, msg.sender))`) to all functions that write to role or permission mappings.

---

## Source Analysis Pipeline

1. **Compile** the Solidity file using `py-solc-x` (standard JSON interface)
2. **Extract AST** using `scanner.ast.loader.extract_ast()`
3. **Walk ContractDefinition nodes** to extract `ContractInfo` IR
4. For each contract, extract:
   - **State variables** (to detect owner/admin patterns)
   - **Modifiers** (check if they contain msg.sender auth checks)
   - **Functions** (visibility, mutability, applied modifiers, inline checks, sensitive actions)
5. **Compute `has_auth_guard`** per function:
   - Applied modifier with auth check, OR
   - Inline `require(msg.sender == ...)`, OR
   - Calls internal helper with auth check (one-hop)
6. **Run detection rules** against the populated IR

## Bytecode Analysis Pipeline

1. **Extract deployed bytecode** from compiler output
2. **Disassemble** using `pyevmasm`
3. **Scan for ORIGIN opcode** (0x32) — any occurrence indicates `tx.origin` usage
4. **Scan for CALLER...EQ...JUMPI patterns** — indicates msg.sender authorization gates
5. **Extract function selectors** from PUSH4...EQ...JUMPI dispatcher patterns

Bytecode analysis is the fallback path when source is unavailable and provides lower-confidence findings.

## Known Limitations

- **Sensitivity heuristics**: Sensitive function classification relies on name patterns and body opcodes. Unusual naming may cause false negatives.
- **One-hop helper resolution**: Only follows one level of internal function calls for auth check propagation. Deeper call chains are not analyzed.
- **Inherited modifier support**: Modifiers from base contracts within the same compilation unit are now resolved. If the base contract is not part of the same compilation (e.g., imported from a separate file that fails to compile), inherited modifiers may not be tracked.
- **OpenZeppelin patterns**: Well-known modifier names (`onlyOwner`, `onlyAdmin`, `onlyRole`, etc.) are recognized as authorization guards even without seeing the modifier body. Custom modifier names outside this known set require the modifier body to be visible in the same compilation unit.
- **Complex role systems**: OpenZeppelin AccessControl or custom RBAC patterns using `hasRole(ROLE, msg.sender)` inside a modifier are detected if the modifier contains a msg.sender check. If the role system is implemented differently, it may be missed.
- **Bytecode-only mode limitations**: Cannot determine function names, exact line numbers, or detailed reasoning. Findings are lower confidence.
- **Solidity 0.4.x AST**: Source analysis targets the compact JSON AST format (Solidity >=0.5). Legacy AST (0.4.x) has different node types. Bytecode analysis works for all versions.

## Adding New Access Control Rules

1. Add detection logic to `src/scanner/detectors/access_control.py`
2. Add a helper function `_check_<rule_name>(contract)` following existing patterns
3. Call it from `detect_from_source()` or `detect_from_bytecode()`
4. Add a Solidity fixture to `tests/fixtures/` and a test case to `tests/test_access_control_detector.py`
