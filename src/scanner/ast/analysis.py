"""AST-level analysis for access-control vulnerability detection.

Walks the Solidity compact JSON AST to populate ContractInfo IR models,
extracting functions, modifiers, auth checks, and sensitive actions.
"""

from __future__ import annotations

import re
from typing import Any

from scanner.ast.loader import walk_ast, walk_ast_filtered
from scanner.models.findings import SourceLocation
from scanner.models.ir import (
    AuthCheck,
    ContractInfo,
    FunctionInfo,
    ModifierInfo,
    SensitiveAction,
)
from scanner.utils.source_map import build_line_map, offset_to_line_col

# Well-known modifier names that imply auth/access control
_KNOWN_AUTH_MODIFIERS: frozenset[str] = frozenset({
    "onlyOwner", "onlyAdmin", "onlyRole", "onlyGovernance",
    "onlyMinter", "onlyPauser", "onlyOperator",
    "whenNotPaused", "whenPaused",
    "nonReentrant",
})

# Well-known base contracts that provide access control
_KNOWN_AUTH_BASES: frozenset[str] = frozenset({
    "Ownable", "AccessControl", "AccessControlEnumerable", "Pausable",
})

# Names that strongly suggest ownership / admin state variables
_OWNER_VAR_PATTERNS = re.compile(
    r"^(_)?(owner|admin|governance|authority|controller|manager|minter|pauser|operator)s?$",
    re.IGNORECASE,
)

# Function name patterns that suggest sensitive operations
_SENSITIVE_FUNC_PATTERNS = re.compile(
    r"(owner|admin|role|pause|unpause|upgrade|proxy|withdraw|transfer|mint|burn|"
    r"kill|destroy|suicide|selfdestruct|set[A-Z_]|grant|revoke|initialize|migrate)",
)

# Role / access mapping variable names
_ROLE_VAR_PATTERNS = re.compile(
    r"(role|permission|access|whitelist|blacklist|allowed)",
    re.IGNORECASE,
)


def analyze_source(compiler_output: dict[str, Any]) -> list[ContractInfo]:
    """Analyze compiler output and return ContractInfo for all contracts.

    Args:
        compiler_output: Standard JSON compiler output dict.

    Returns:
        List of ContractInfo objects, one per contract definition.
    """
    from scanner.ast.loader import extract_ast

    asts = extract_ast(compiler_output)
    # Source content may be embedded in the input sources (standard JSON input)
    # or available on disk; use it to build accurate line maps.
    input_sources: dict[str, Any] = compiler_output.get("sources", {})
    results: list[ContractInfo] = []
    for source_file, ast_root in asts.items():
        # Try to get source content for accurate line numbers
        line_map: list[int] | None = None
        source_content: str = input_sources.get(source_file, {}).get("content", "")
        if not source_content:
            # Fallback: try reading the file from disk
            try:
                with open(source_file) as fh:
                    source_content = fh.read()
            except OSError:
                source_content = ""
        if source_content:
            line_map = build_line_map(source_content)
        contracts = _analyze_ast(ast_root, source_file, line_map=line_map)
        results.extend(contracts)
    return results


def analyze_contract_ast(
    ast_root: dict[str, Any], source_file: str = "", line_map: list[int] | None = None
) -> list[ContractInfo]:
    """Analyze a single AST root and return ContractInfo objects."""
    return _analyze_ast(ast_root, source_file, line_map=line_map)


def _analyze_ast(
    ast_root: dict[str, Any], source_file: str, line_map: list[int] | None = None
) -> list[ContractInfo]:
    # Pass 1: Extract all contracts
    results: list[ContractInfo] = []
    for node in walk_ast_filtered(ast_root, {"ContractDefinition"}):
        # Only top-level contract definitions (not nested)
        contract = _extract_contract(node, source_file, line_map=line_map)
        results.append(contract)
    # Pass 2: Resolve inherited modifiers
    _resolve_inherited_modifiers(results)
    return results


def _extract_contract(
    node: dict[str, Any], source_file: str, line_map: list[int] | None = None
) -> ContractInfo:
    name = node.get("name", "")
    contract_kind = node.get("contractKind", "contract")
    if contract_kind not in ("contract", "library", "interface", "abstract"):
        contract_kind = "contract"

    # Base contracts
    base_contracts: list[str] = []
    for base in node.get("baseContracts", []):
        base_name = base.get("baseName", {}).get("name", "")
        if base_name:
            base_contracts.append(base_name)

    # State variables
    state_variables: list[str] = []
    for child in node.get("nodes", []):
        if child.get("nodeType") == "VariableDeclaration":
            var_name = child.get("name", "")
            if var_name:
                state_variables.append(var_name)

    has_owner_pattern = any(_is_owner_variable(v) for v in state_variables)
    # If any base contract is a well-known auth base, treat as having owner pattern
    if not has_owner_pattern and any(b in _KNOWN_AUTH_BASES for b in base_contracts):
        has_owner_pattern = True

    # Extract modifiers first (functions may reference them)
    modifier_nodes = [c for c in node.get("nodes", []) if c.get("nodeType") == "ModifierDefinition"]
    modifiers = [_extract_modifier(m, source_file, line_map=line_map) for m in modifier_nodes]
    modifier_map = {m.name: m for m in modifiers}

    # Extract internal function definitions (for one-hop helper resolution)
    internal_funcs: dict[str, FunctionInfo] = {}
    for child in node.get("nodes", []):
        if child.get("nodeType") == "FunctionDefinition":
            vis = child.get("visibility", "internal")
            if vis in ("internal", "private"):
                f = _extract_function(
                    child, source_file, modifier_map, {}, state_variables, line_map=line_map
                )
                internal_funcs[f.name] = f

    # Extract all functions
    functions: list[FunctionInfo] = []
    constructor_node: dict[str, Any] | None = None
    for child in node.get("nodes", []):
        if child.get("nodeType") == "FunctionDefinition":
            f = _extract_function(
                child, source_file, modifier_map, internal_funcs, state_variables, line_map=line_map
            )
            functions.append(f)
            if child.get("kind") == "constructor":
                constructor_node = child

    # Detect whether any owner-like state variable is initialized
    owner_initialized_in_constructor = False
    owner_vars = [v for v in state_variables if _is_owner_variable(v)]
    if owner_vars:
        for var_name in owner_vars:
            if _state_var_has_initial_value(node, var_name):
                owner_initialized_in_constructor = True
                break
            if constructor_node is not None and _constructor_assigns_variable(
                constructor_node, var_name
            ):
                owner_initialized_in_constructor = True
                break

    loc = _source_loc(node, source_file, line_map=line_map)
    return ContractInfo(
        name=name,
        source_file=source_file,
        kind=contract_kind,  # type: ignore[arg-type]
        base_contracts=base_contracts,
        modifiers=modifiers,
        functions=functions,
        state_variables=state_variables,
        has_owner_pattern=has_owner_pattern,
        owner_initialized_in_constructor=owner_initialized_in_constructor,
        source_location=loc,
    )


def _extract_modifier(
    node: dict[str, Any], source_file: str, line_map: list[int] | None = None
) -> ModifierInfo:
    name = node.get("name", "")
    auth_checks: list[AuthCheck] = []

    body = node.get("body", {})
    if body:
        for stmt in walk_ast(body):
            ac = _detect_auth_check_in_node(stmt)
            if ac:
                auth_checks.append(ac)

    has_auth_check = bool(auth_checks)
    # A modifier that uses msg.sender counts as an auth check
    if not has_auth_check:
        for stmt in walk_ast(body) if body else []:
            if _node_uses_msg_sender(stmt):
                has_auth_check = True
                break

    return ModifierInfo(
        name=name,
        has_auth_check=has_auth_check,
        auth_checks=auth_checks,
        source_location=_source_loc(node, source_file, line_map=line_map),
    )


def _extract_function(
    node: dict[str, Any],
    source_file: str,
    modifier_map: dict[str, ModifierInfo],
    internal_funcs: dict[str, FunctionInfo],
    state_variables: list[str],
    line_map: list[int] | None = None,
) -> FunctionInfo:
    name = node.get("name", "")
    kind = node.get("kind", "function")  # function, constructor, fallback, receive

    is_constructor = kind == "constructor"
    is_fallback = kind == "fallback"
    is_receive = kind == "receive"

    visibility = node.get("visibility", "internal")
    state_mutability = node.get("stateMutability", "nonpayable")

    # Applied modifier names
    applied_modifiers: list[str] = []
    for mod_invoc in node.get("modifiers", []):
        mod_name = mod_invoc.get("modifierName", {}).get("name", "")
        if mod_name:
            applied_modifiers.append(mod_name)

    # Walk function body for auth checks and sensitive actions
    auth_checks: list[AuthCheck] = []
    sensitive_actions: list[SensitiveAction] = []
    uses_tx_origin = False

    body = node.get("body", {})
    if body:
        all_nodes = walk_ast(body)
        for stmt in all_nodes:
            ac = _detect_auth_check_in_node(stmt)
            if ac:
                auth_checks.append(ac)
                if ac.uses_tx_origin:
                    uses_tx_origin = True
            sa = _detect_sensitive_action(stmt, state_variables)
            if sa:
                sensitive_actions.append(sa)

        # Check for tx.origin anywhere in the body
        if not uses_tx_origin:
            for stmt in all_nodes:
                if _node_uses_tx_origin(stmt):
                    uses_tx_origin = True
                    break

    # Compute has_auth_guard:
    # 1. Any applied modifier with has_auth_check, or a well-known auth modifier name
    modifier_guarded = any(
        modifier_map.get(m, ModifierInfo(name=m)).has_auth_check or m in _KNOWN_AUTH_MODIFIERS
        for m in applied_modifiers
    )
    # 2. Any inline require/if with msg.sender
    inline_guarded = any(ac.uses_msg_sender for ac in auth_checks)
    # 3. One-hop: calls internal function that has inline auth
    one_hop_guarded = False
    if not modifier_guarded and not inline_guarded and body:
        for stmt in walk_ast(body):
            if stmt.get("nodeType") == "FunctionCall":
                expr = stmt.get("expression", {})
                callee = expr.get("name", "") or expr.get("memberName", "")
                if callee in internal_funcs:
                    helper = internal_funcs[callee]
                    if any(ac.uses_msg_sender for ac in helper.auth_checks):
                        one_hop_guarded = True
                        break

    has_auth_guard = modifier_guarded or inline_guarded or one_hop_guarded

    # Classify function sensitivity by name if no body actions found
    if (
        not sensitive_actions
        and not is_constructor
        and not is_fallback
        and not is_receive
        and _is_sensitive_by_name(name)
    ):
        sensitive_actions.append(
            SensitiveAction(
                kind="state_mutation",
                description=f"Function '{name}' name suggests privileged operation",
            )
        )

    return FunctionInfo(
        name=name,
        visibility=visibility,  # type: ignore[arg-type]
        state_mutability=state_mutability,  # type: ignore[arg-type]
        is_constructor=is_constructor,
        is_fallback=is_fallback,
        is_receive=is_receive,
        modifiers=applied_modifiers,
        auth_checks=auth_checks,
        sensitive_actions=sensitive_actions,
        has_auth_guard=has_auth_guard,
        uses_tx_origin=uses_tx_origin,
        source_location=_source_loc(node, source_file, line_map=line_map),
    )


def _collect_inherited_modifiers(
    base_names: list[str],
    contract_map: dict[str, ContractInfo],
) -> dict[str, ModifierInfo]:
    """DFS-collect all ModifierInfo objects reachable from base_names."""
    inherited: dict[str, ModifierInfo] = {}
    visited: set[str] = set()
    stack = list(base_names)
    while stack:
        name = stack.pop()
        if name in visited:
            continue
        visited.add(name)
        base = contract_map.get(name)
        if base is None:
            continue
        for mod in base.modifiers:
            if mod.name not in inherited:
                inherited[mod.name] = mod
        stack.extend(base.base_contracts)
    return inherited


def _resolve_inherited_modifiers(contracts: list[ContractInfo]) -> None:
    """Resolve modifiers inherited from base contracts (two-pass analysis).

    For each contract with base_contracts, find modifiers defined in the base
    contracts and make them available in the derived contract. Then re-evaluate
    has_auth_guard for functions that use those modifiers.
    """
    # Build name -> ContractInfo lookup
    contract_map: dict[str, ContractInfo] = {c.name: c for c in contracts}

    for contract in contracts:
        if not contract.base_contracts:
            continue

        # Gather all inherited modifiers (DFS through base chains)
        inherited_mods = _collect_inherited_modifiers(contract.base_contracts, contract_map)

        if not inherited_mods:
            continue

        # Build the modifier map: local modifiers take precedence
        local_mod_names = {m.name for m in contract.modifiers}
        new_mods = [m for name, m in inherited_mods.items() if name not in local_mod_names]
        contract.modifiers.extend(new_mods)

        # Rebuild has_auth_guard for functions using inherited modifiers
        modifier_map = {m.name: m for m in contract.modifiers}
        for func in contract.functions:
            if func.has_auth_guard:
                continue  # already guarded
            for mod_name in func.modifiers:
                if mod_name in modifier_map and modifier_map[mod_name].has_auth_check:
                    func.has_auth_guard = True
                    break
                if mod_name in _KNOWN_AUTH_MODIFIERS:
                    func.has_auth_guard = True
                    break


def _detect_auth_check_in_node(
    node: dict[str, Any], source_file: str | None = None, line_map: list[int] | None = None
) -> AuthCheck | None:
    """Return an AuthCheck if this node is a require/assert/if-revert with auth logic."""
    node_type = node.get("nodeType", "")

    if node_type == "FunctionCall":
        expr = node.get("expression", {})
        func_name = expr.get("name", "")
        if func_name in ("require", "assert"):
            args = node.get("arguments", [])
            if args:
                condition = args[0]
                uses_ms = _node_uses_msg_sender(condition)
                uses_tx = _node_uses_tx_origin(condition)
                refs_owner = _node_references_owner(condition)
                refs_role = _node_references_role(condition)
                if uses_ms or uses_tx or refs_owner or refs_role:
                    kind: str = "require" if func_name == "require" else "assert"
                    return AuthCheck(
                        kind=kind,  # type: ignore[arg-type]
                        uses_msg_sender=uses_ms,
                        uses_tx_origin=uses_tx,
                        references_owner=refs_owner,
                        references_role=refs_role,
                        raw_expression=str(condition.get("nodeType", "")),
                    )

    if node_type == "IfStatement":
        condition = node.get("condition", {})
        uses_ms = _node_uses_msg_sender(condition)
        uses_tx = _node_uses_tx_origin(condition)
        refs_owner = _node_references_owner(condition)
        # Check if the true body is a revert
        true_body = node.get("trueBody", {})
        is_revert = _body_is_revert(true_body)
        if is_revert and (uses_ms or uses_tx or refs_owner):
            return AuthCheck(
                kind="if_revert",
                uses_msg_sender=uses_ms,
                uses_tx_origin=uses_tx,
                references_owner=refs_owner,
                references_role=_node_references_role(condition),
                raw_expression="if_revert",
            )

    return None


def _body_is_revert(node: dict[str, Any]) -> bool:
    """Check if an AST node is or directly contains a revert/throw."""
    if not node:
        return False
    nt = node.get("nodeType", "")
    if nt in ("Throw", "RevertStatement"):
        return True
    if nt == "Block":
        stmts = node.get("statements", [])
        if stmts and stmts[0].get("nodeType", "") in ("Throw", "RevertStatement"):
            return True
        # revert() as a function call
        if stmts:
            first = stmts[0]
            if first.get("nodeType") == "ExpressionStatement":
                expr = first.get("expression", {})
                if expr.get("nodeType") == "FunctionCall":
                    callee = expr.get("expression", {}).get("name", "")
                    if callee == "revert":
                        return True
    # ExpressionStatement wrapping a revert() call
    if nt == "ExpressionStatement":
        expr = node.get("expression", {})
        if expr.get("nodeType") == "FunctionCall":
            callee = expr.get("expression", {}).get("name", "")
            if callee == "revert":
                return True
    return False


def _node_uses_msg_sender(node: dict[str, Any]) -> bool:
    """Return True if this node or any descendant accesses msg.sender."""
    for n in walk_ast(node):
        if n.get("nodeType") == "MemberAccess" and n.get("memberName") == "sender":
            expr = n.get("expression", {})
            if expr.get("name") == "msg" or (
                expr.get("nodeType") == "Identifier" and expr.get("name") == "msg"
            ):
                return True
    return False


def _node_uses_tx_origin(node: dict[str, Any]) -> bool:
    """Return True if this node or any descendant accesses tx.origin."""
    for n in walk_ast(node):
        if n.get("nodeType") == "MemberAccess" and n.get("memberName") == "origin":
            expr = n.get("expression", {})
            if expr.get("name") == "tx":
                return True
    return False


def _node_references_owner(node: dict[str, Any]) -> bool:
    """Return True if the node references an owner-like variable."""
    for n in walk_ast(node):
        if n.get("nodeType") == "Identifier" and _is_owner_variable(n.get("name", "")):
            return True
    return False


def _node_references_role(node: dict[str, Any]) -> bool:
    """Return True if the node references a role/access mapping variable."""
    for n in walk_ast(node):
        if n.get("nodeType") == "Identifier":
            name = n.get("name", "")
            if _ROLE_VAR_PATTERNS.search(name):
                return True
    return False


def _detect_sensitive_action(
    node: dict[str, Any], state_variables: list[str]
) -> SensitiveAction | None:
    """Classify a statement as a sensitive action if applicable."""
    node_type = node.get("nodeType", "")

    # selfdestruct / suicide
    if node_type == "FunctionCall":
        expr = node.get("expression", {})
        func_name = expr.get("name", "")
        if func_name in ("selfdestruct", "suicide"):
            return SensitiveAction(kind="selfdestruct", description="selfdestruct call")

        # delegatecall
        if expr.get("nodeType") == "MemberAccess" and expr.get("memberName") == "delegatecall":
            return SensitiveAction(
                kind="delegatecall", description="delegatecall to external address"
            )

        # .transfer() or .send() (ETH transfer)
        if expr.get("nodeType") == "MemberAccess":
            member = expr.get("memberName", "")
            if member in ("transfer", "send"):
                return SensitiveAction(kind="eth_transfer", description=f"ETH {member}()")

        # .call{value: ...}() pattern
        if expr.get("nodeType") == "MemberAccess" and expr.get("memberName") == "call":
            return SensitiveAction(kind="eth_transfer", description="low-level .call()")

    # Assignment to owner-like state variable
    if node_type == "ExpressionStatement":
        inner = node.get("expression", {})
        if inner.get("nodeType") == "Assignment":
            lhs = inner.get("leftHandSide", {})
            lhs_name = lhs.get("name", "")
            if lhs_name and _is_owner_variable(lhs_name) and lhs_name in state_variables:
                return SensitiveAction(kind="owner_change", description=f"assigns to '{lhs_name}'")
            # role mapping write: roles[addr] = ...
            if lhs.get("nodeType") == "IndexAccess":
                base = lhs.get("baseExpression", {})
                base_name = base.get("name", "")
                if base_name and _ROLE_VAR_PATTERNS.search(base_name):
                    return SensitiveAction(
                        kind="role_grant",
                        description=f"writes to role mapping '{base_name}'",
                    )

    return None


def _constructor_assigns_variable(constructor_node: dict[str, Any], var_name: str) -> bool:
    """Return True if the constructor body contains an assignment to var_name."""
    body = constructor_node.get("body", {})
    if not body:
        return False
    for n in walk_ast(body):
        if n.get("nodeType") == "Assignment":
            lhs = n.get("leftHandSide", {})
            lhs_name = lhs.get("name", "")
            if lhs_name == var_name:
                return True
        # ExpressionStatement wrapping an Assignment
        if n.get("nodeType") == "ExpressionStatement":
            expr = n.get("expression", {})
            if expr.get("nodeType") == "Assignment":
                lhs = expr.get("leftHandSide", {})
                lhs_name = lhs.get("name", "")
                if lhs_name == var_name:
                    return True
    return False


def _state_var_has_initial_value(contract_node: dict[str, Any], var_name: str) -> bool:
    """Return True if var_name is declared with a non-null initialValue in the contract AST."""
    for child in contract_node.get("nodes", []):
        if (
            child.get("nodeType") == "VariableDeclaration"
            and child.get("name") == var_name
            and (child.get("value") is not None or child.get("initialValue") is not None)
        ):
            return True
    return False


def _is_owner_variable(name: str) -> bool:
    """Return True if name matches an owner/admin/authority pattern."""
    return bool(_OWNER_VAR_PATTERNS.match(name))


def _is_sensitive_by_name(func_name: str) -> bool:
    """Return True if function name suggests a privileged operation."""
    return bool(_SENSITIVE_FUNC_PATTERNS.search(func_name))


def _source_loc(
    node: dict[str, Any], source_file: str, line_map: list[int] | None = None
) -> SourceLocation | None:
    """Extract a SourceLocation from an AST node's src string.

    If line_map is provided, converts byte offsets to real line/column numbers.
    Otherwise, falls back to storing the raw byte offset in line_start.
    """
    src = node.get("src", "")
    if not src:
        return None
    try:
        # src format: "offset:length:file_index"
        parts = src.split(":")
        if len(parts) >= 2:
            offset = int(parts[0])
            length = int(parts[1])
            if line_map is not None:
                line_start, column_start, line_end, column_end = offset_to_line_col(
                    offset, length, line_map
                )
                return SourceLocation(
                    file=source_file,
                    line_start=line_start,
                    column_start=column_start,
                    line_end=line_end,
                    column_end=column_end,
                )
            # Fallback: store raw byte offset (legacy behavior)
            return SourceLocation(file=source_file, line_start=offset)
    except (ValueError, IndexError):
        pass
    return SourceLocation(file=source_file, line_start=0)
