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
_KNOWN_AUTH_MODIFIERS: frozenset[str] = frozenset(
    {
        "onlyOwner",
        "onlyAdmin",
        "onlyRole",
        "onlyGovernance",
        "onlyMinter",
        "onlyPauser",
        "onlyOperator",
    }
)

# Well-known base contracts that provide access control
_KNOWN_AUTH_BASES: frozenset[str] = frozenset(
    {
        "Ownable",
        "AccessControl",
        "AccessControlEnumerable",
    }
)

# Names that strongly suggest ownership / admin state variables
_OWNER_VAR_PATTERNS = re.compile(
    r"^(_)?(owner|admin|governance|authority|controller|manager|minter|pauser|operator|creator|root)s?$",
    re.IGNORECASE,
)

# Function names that are strongly associated with privileged control surface.
_HIGH_CONF_SENSITIVE_FUNC_PATTERNS = re.compile(
    r"(owner|admin|role|pause|unpause|upgrade|proxy|kill|destroy|suicide|"
    r"selfdestruct|grant|revoke|initialize|migrate|renounce)",
    re.IGNORECASE,
)

# Lower-confidence names that can be business-flow operations unless paired with
# privileged context.
_LOW_CONF_SENSITIVE_FUNC_PATTERNS = re.compile(
    r"(withdraw|transfer|mint|burn|set[a-zA-Z_]|init[a-zA-Z_])",
    re.IGNORECASE,
)

_PRIVILEGED_NAME_CONTEXT = re.compile(
    r"(owner|admin|role|governance|authority|controller|manager|minter|pauser|"
    r"operator|creator|root)",
    re.IGNORECASE,
)

_CONSTRUCTOR_CANDIDATE_PATTERNS = re.compile(
    r"^(constructor|construct|init|initialize|initializer|setup)",
    re.IGNORECASE,
)

_COMPARISON_OPERATORS: frozenset[str] = frozenset({"==", "!=", ">", ">=", "<", "<="})

# Role / access mapping variable names
_ROLE_VAR_PATTERNS = re.compile(
    r"(role|permission|access|whitelist|blacklist|allowed|admin)",
    re.IGNORECASE,
)

_CONFIG_VAR_PATTERNS = re.compile(
    r"(treasury|beneficiar|recipient|collector|vault|reserve|router|oracle|"
    r"implementation|logic|beacon|wallet|receiver|destination|fee)",
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
    modifiers = [
        _extract_modifier(m, source_file, state_variables, line_map=line_map)
        for m in modifier_nodes
    ]
    modifier_map = {m.name: m for m in modifiers}

    def build_function(
        child: dict[str, Any],
        helper_map: dict[str, FunctionInfo],
    ) -> FunctionInfo:
        return _extract_function(
            child,
            name,
            source_file,
            modifier_map,
            helper_map,
            state_variables,
            has_owner_pattern,
            line_map=line_map,
        )

    function_nodes = [
        child for child in node.get("nodes", []) if child.get("nodeType") == "FunctionDefinition"
    ]

    # Extract internal function definitions (for one-hop helper resolution)
    internal_funcs: dict[str, FunctionInfo] = {}
    for child in function_nodes:
        vis = child.get("visibility", "internal")
        if vis in ("internal", "private"):
            f = build_function(child, {})
            internal_funcs[f.name] = f

    # Extract all functions
    functions: list[FunctionInfo] = []
    constructor_node: dict[str, Any] | None = None
    for child in function_nodes:
        f = build_function(child, internal_funcs)
        functions.append(f)
        if child.get("kind") == "constructor" or bool(child.get("isConstructor", False)):
            constructor_node = child

    _propagate_internal_function_sensitivity(functions)

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


def _propagate_internal_function_sensitivity(functions: list[FunctionInfo]) -> None:
    """Lift helper-side sensitive actions onto their externally callable entrypoints.

    Access-control risk often lives in an internal/private helper such as
    `_setOwner(...)` or `_grantRole(...)`, while the public entrypoint only calls
    that helper. We propagate helper actions through the internal call graph so
    the externally callable function inherits the privileged surface it exposes.
    """
    helper_map = {
        func.name: func for func in functions if func.visibility in ("internal", "private") and func.name
    }
    if not helper_map:
        return

    for func in functions:
        propagated = _collect_sensitive_actions_from_helpers(func, helper_map, depth=4)
        if not propagated:
            continue
        func.sensitive_actions = _merge_sensitive_actions(func.sensitive_actions, propagated)


def _collect_sensitive_actions_from_helpers(
    func: FunctionInfo,
    helper_map: dict[str, FunctionInfo],
    *,
    depth: int,
    visited: set[str] | None = None,
) -> list[SensitiveAction]:
    if depth <= 0:
        return []
    if visited is None:
        visited = set()

    propagated: list[SensitiveAction] = []
    for callee in func.extra.get("called_functions", []) if func.extra else []:
        helper = helper_map.get(callee)
        if helper is None or callee in visited:
            continue
        next_visited = visited | {callee}
        propagated.extend(
            _tag_helper_actions(helper.sensitive_actions, helper_name=callee)
        )
        propagated.extend(
            _collect_sensitive_actions_from_helpers(
                helper,
                helper_map,
                depth=depth - 1,
                visited=next_visited,
            )
        )
    return _merge_sensitive_actions([], propagated)


def _tag_helper_actions(
    actions: list[SensitiveAction],
    *,
    helper_name: str,
) -> list[SensitiveAction]:
    tagged: list[SensitiveAction] = []
    for action in actions:
        desc = action.description or action.kind
        if "via helper" not in desc:
            desc = f"{desc} via helper '{helper_name}'"
        tagged.append(
            action.model_copy(
                update={
                    "description": desc,
                }
            )
        )
    return tagged


def _merge_sensitive_actions(
    base: list[SensitiveAction],
    extra: list[SensitiveAction],
) -> list[SensitiveAction]:
    seen: set[tuple[str, str, int]] = set()
    merged: list[SensitiveAction] = []
    for action in [*base, *extra]:
        loc_line = action.source_location.line_start if action.source_location else 0
        key = (action.kind, action.description, loc_line)
        if key in seen:
            continue
        seen.add(key)
        merged.append(action)
    return merged


def _extract_modifier(
    node: dict[str, Any],
    source_file: str,
    state_variables: list[str],
    line_map: list[int] | None = None,
) -> ModifierInfo:
    name = node.get("name", "")
    auth_checks: list[AuthCheck] = []
    called_functions: set[str] = set()

    body = node.get("body", {})
    if body:
        for stmt in walk_ast(body):
            ac = _detect_auth_check_in_node(stmt, state_variables)
            if ac:
                auth_checks.append(ac)
            callee = _callee_name(stmt)
            if callee:
                called_functions.add(callee)

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
        called_functions=sorted(called_functions),
        source_location=_source_loc(node, source_file, line_map=line_map),
    )


def _extract_function(
    node: dict[str, Any],
    contract_name: str,
    source_file: str,
    modifier_map: dict[str, ModifierInfo],
    internal_funcs: dict[str, FunctionInfo],
    state_variables: list[str],
    has_owner_pattern: bool,
    line_map: list[int] | None = None,
) -> FunctionInfo:
    name = node.get("name", "")
    kind = node.get("kind", "function")  # function, constructor, fallback, receive

    # Legacy Solidity ASTs may expose boolean flags instead of kind values.
    is_constructor = kind == "constructor" or bool(node.get("isConstructor", False))
    is_fallback = kind == "fallback" or bool(node.get("isFallback", False))
    is_receive = kind == "receive" or bool(node.get("isReceiveEther", False))
    is_constructor_candidate = _is_constructor_candidate_name(contract_name, name, is_constructor)

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
    called_functions: set[str] = set()

    body = node.get("body", {})
    if body:
        all_nodes = walk_ast(body)
        for stmt in all_nodes:
            ac = _detect_auth_check_in_node(stmt, state_variables)
            if ac:
                auth_checks.append(ac)
                if ac.uses_tx_origin:
                    uses_tx_origin = True
            sa = _detect_sensitive_action(stmt, state_variables, function_name=name)
            if sa:
                sa.source_location = _source_loc(stmt, source_file, line_map=line_map)
                sensitive_actions.append(sa)
            callee = _callee_name(stmt)
            if callee:
                called_functions.add(callee)

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
    modifier_helper_guarded = _modifier_calls_guarded_helper(
        applied_modifiers,
        modifier_map,
        internal_funcs,
        depth=2,
    )
    # 2. Any inline require/if with msg.sender
    inline_guarded = any(_auth_check_is_guard(ac) for ac in auth_checks)
    # 3. Bounded helper-call auth propagation through internal functions.
    helper_guarded = _has_guarded_helper_path(called_functions, internal_funcs, depth=2)

    has_auth_guard = modifier_guarded or modifier_helper_guarded or inline_guarded or helper_guarded
    has_sender_flow_check = any(
        ac.uses_msg_sender
        and not ac.uses_tx_origin
        and not ac.references_owner
        and not ac.references_role
        for ac in auth_checks
    )

    # Classify function sensitivity by name if no body actions found
    if (
        not sensitive_actions
        and has_owner_pattern
        and not is_constructor
        and not is_fallback
        and not is_receive
        and _is_sensitive_name_with_context(name)
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
        is_constructor_candidate=is_constructor_candidate,
        is_fallback=is_fallback,
        is_receive=is_receive,
        modifiers=applied_modifiers,
        auth_checks=auth_checks,
        sensitive_actions=sensitive_actions,
        has_auth_guard=has_auth_guard,
        uses_tx_origin=uses_tx_origin,
        source_location=_source_loc(node, source_file, line_map=line_map),
        extra={
            "called_functions": sorted(called_functions),
            "has_sender_flow_check": has_sender_flow_check,
        },
    )


def _auth_check_is_guard(auth_check: AuthCheck) -> bool:
    """Return True for auth checks that gate privileged access.

    We treat tx.origin checks as an authorization guard signal even though they
    are insecure, to avoid also misclassifying the function as "missing auth".
    """
    return auth_check.uses_tx_origin or (
        auth_check.uses_msg_sender and (auth_check.references_owner or auth_check.references_role)
    )


def _has_guarded_helper_path(
    callees: set[str] | list[str],
    internal_funcs: dict[str, FunctionInfo],
    depth: int,
    visited: set[str] | None = None,
) -> bool:
    """Bounded DFS through internal call graph to detect propagated auth guards."""
    if depth <= 0:
        return False
    if visited is None:
        visited = set()

    for callee in callees:
        if callee in visited or callee not in internal_funcs:
            continue
        visited.add(callee)
        helper = internal_funcs[callee]

        if any(_auth_check_is_guard(ac) for ac in helper.auth_checks):
            return True

        nested = helper.extra.get("called_functions", []) if helper.extra else []
        if nested and _has_guarded_helper_path(nested, internal_funcs, depth - 1, visited):
            return True

    return False


def _modifier_calls_guarded_helper(
    modifier_names: list[str],
    modifier_map: dict[str, ModifierInfo],
    internal_funcs: dict[str, FunctionInfo],
    depth: int,
) -> bool:
    """Return True when any applied modifier calls helper auth logic."""
    for mod_name in modifier_names:
        mod = modifier_map.get(mod_name)
        if mod is None or not mod.called_functions:
            continue
        if _has_guarded_helper_path(set(mod.called_functions), internal_funcs, depth=depth):
            return True
    return False


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
        internal_funcs = {
            f.name: f for f in contract.functions if f.visibility in ("internal", "private")
        }
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
                if _modifier_calls_guarded_helper(
                    [mod_name], modifier_map, internal_funcs, depth=2
                ):
                    func.has_auth_guard = True
                    break


def _detect_auth_check_in_node(
    node: dict[str, Any],
    state_variables: list[str] | None = None,
) -> AuthCheck | None:
    """Return an AuthCheck if this node is a require/assert/if-revert with auth logic."""
    node_type = node.get("nodeType", "")

    state_variables = state_variables or []

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
                comparison_operator, left_sender_state, right_sender_state = _comparison_metadata(
                    condition, state_variables
                )
                if uses_ms or uses_tx or refs_owner or refs_role:
                    kind: str = "require" if func_name == "require" else "assert"
                    return AuthCheck(
                        kind=kind,  # type: ignore[arg-type]
                        uses_msg_sender=uses_ms,
                        uses_tx_origin=uses_tx,
                        references_owner=refs_owner,
                        references_role=refs_role,
                        comparison_operator=comparison_operator,
                        comparison_left_uses_sender_scoped_state=left_sender_state,
                        comparison_right_uses_sender_scoped_state=right_sender_state,
                        raw_expression=str(condition.get("nodeType", "")),
                    )

    if node_type == "IfStatement":
        condition = node.get("condition", {})
        uses_ms = _node_uses_msg_sender(condition)
        uses_tx = _node_uses_tx_origin(condition)
        refs_owner = _node_references_owner(condition)
        comparison_operator, left_sender_state, right_sender_state = _comparison_metadata(
            condition, state_variables
        )
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
                comparison_operator=comparison_operator,
                comparison_left_uses_sender_scoped_state=left_sender_state,
                comparison_right_uses_sender_scoped_state=right_sender_state,
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


def _callee_name(node: dict[str, Any]) -> str:
    """Return function callee name/member when node is a FunctionCall."""
    if node.get("nodeType") != "FunctionCall":
        return ""
    expr = node.get("expression", {})
    return expr.get("name", "") or expr.get("memberName", "")


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


def _comparison_metadata(
    node: dict[str, Any], state_variables: list[str]
) -> tuple[str, bool, bool]:
    """Return comparison metadata for the first sender-relevant comparison in a node."""
    for comparison in walk_ast(node):
        if comparison.get("nodeType") != "BinaryOperation":
            continue
        operator = comparison.get("operator", "")
        if operator not in _COMPARISON_OPERATORS:
            continue
        left = comparison.get("leftExpression", {})
        right = comparison.get("rightExpression", {})
        left_sender_state = _node_references_sender_scoped_state(left, state_variables)
        right_sender_state = _node_references_sender_scoped_state(right, state_variables)
        if left_sender_state or right_sender_state:
            return operator, left_sender_state, right_sender_state
    return "", False, False


def _node_references_sender_scoped_state(node: dict[str, Any], state_variables: list[str]) -> bool:
    """Return True if a node references a state variable indexed by msg.sender."""
    for n in walk_ast(node):
        if n.get("nodeType") != "IndexAccess":
            continue
        base = n.get("baseExpression", {})
        base_name = base.get("name", "")
        if not base_name or base_name not in state_variables:
            continue
        index = n.get("indexExpression", {})
        if _node_uses_msg_sender(index):
            return True
    return False


def _detect_sensitive_action(
    node: dict[str, Any],
    state_variables: list[str],
    *,
    function_name: str = "",
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
            if (
                lhs_name
                and lhs_name in state_variables
                and _CONFIG_VAR_PATTERNS.search(lhs_name)
                and not _is_owner_variable(lhs_name)
            ):
                config_desc = f"assigns to config variable '{lhs_name}'"
                if function_name:
                    config_desc += f" via '{function_name}'"
                return SensitiveAction(kind="config_set", description=config_desc)
            # role mapping write: roles[addr] = ...
            if lhs.get("nodeType") == "IndexAccess":
                base = lhs.get("baseExpression", {})
                base_name = base.get("name", "")
                if base_name and _ROLE_VAR_PATTERNS.search(base_name):
                    return SensitiveAction(
                        kind="role_grant",
                        description=f"writes to role mapping '{base_name}'",
                    )
            # dynamic array length write: arr.length = ...
            if lhs.get("nodeType") == "MemberAccess" and lhs.get("memberName") == "length":
                base = lhs.get("expression", {})
                base_name = base.get("name", "")
                if base_name and base_name in state_variables:
                    return SensitiveAction(
                        kind="state_mutation",
                        description=f"writes dynamic length of '{base_name}'",
                    )

        # dynamic array length update: arr.length-- / arr.length++
        if inner.get("nodeType") == "UnaryOperation" and inner.get("operator") in ("--", "++"):
            sub = inner.get("subExpression", {})
            if sub.get("nodeType") == "MemberAccess" and sub.get("memberName") == "length":
                base = sub.get("expression", {})
                base_name = base.get("name", "")
                if base_name and base_name in state_variables:
                    return SensitiveAction(
                        kind="state_mutation",
                        description=f"updates dynamic length of '{base_name}'",
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


def _is_sensitive_name_with_context(func_name: str) -> bool:
    """Return True when function name and context strongly suggest privileged control.

    High-confidence names always qualify. Low-confidence names must include
    privileged context terms to avoid over-triggering on user-flow functions.
    """
    if _HIGH_CONF_SENSITIVE_FUNC_PATTERNS.search(func_name):
        return True
    if _LOW_CONF_SENSITIVE_FUNC_PATTERNS.search(func_name):
        return bool(_PRIVILEGED_NAME_CONTEXT.search(func_name))
    return False


def _is_constructor_candidate_name(
    contract_name: str, func_name: str, is_constructor: bool
) -> bool:
    """Return True when a non-constructor function appears to be initialization logic."""
    if is_constructor or not func_name:
        return False
    if func_name.lower() == contract_name.lower():
        return True
    return bool(_CONSTRUCTOR_CANDIDATE_PATTERNS.search(func_name))


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
