"""Reentrancy detector (AST-based heuristics).

This detector implements a lightweight approximation of the classic
checks-effects-interactions guideline:

- Flag functions where an external call (e.g., `call`, `delegatecall`,
  `staticcall`, `send`, `transfer`) appears before a write to a state
  variable.

Bytecode-level corroboration is intentionally deferred to a later step.
"""

from __future__ import annotations

from typing import Any

from scanner.ast.loader import extract_ast
from scanner.models.findings import Finding, Severity, SourceLocation


def detect_reentrancy(compiler_output: dict[str, Any]) -> list[Finding]:
    """Detect potential reentrancy vulnerabilities (AST-based).

    Args:
        compiler_output: Standard JSON compiler output from `solcx`.

    Returns:
        List of detected `Finding` objects.
    """

    findings: list[Finding] = []
    ast_by_file = extract_ast(compiler_output)

    for file_name, ast_root in ast_by_file.items():
        if not isinstance(ast_root, dict) or not ast_root:
            continue

        for contract_node in _walk_solc_nodes(ast_root):
            if contract_node.get("nodeType") != "ContractDefinition":
                continue

            contract_name = ""
            contract_name_val = contract_node.get("name")
            if isinstance(contract_name_val, str):
                contract_name = contract_name_val
            state_vars = _extract_state_variable_names(contract_node)
            if not state_vars:
                continue

            for fn_node in _walk_solc_nodes(contract_node):
                if fn_node.get("nodeType") != "FunctionDefinition":
                    continue

                function_name = _function_display_name(fn_node)
                if _function_has_nonreentrant_modifier(fn_node):
                    continue

                call_candidates: list[tuple[int, dict[str, Any]]] = []
                write_candidates: list[tuple[int, dict[str, Any]]] = []

                for node in _walk_solc_nodes(fn_node):
                    node_type = node.get("nodeType")

                    if node_type == "FunctionCall" and _is_external_call(node):
                        start = _parse_src_start(node.get("src"))
                        if start is not None:
                            call_candidates.append((start, node))
                    elif node_type == "Assignment" and _assignment_writes_state(node, state_vars):
                        start = _parse_src_start(node.get("src"))
                        if start is not None:
                            write_candidates.append((start, node))
                    elif node_type == "UnaryOperation" and _unary_op_writes_state(node, state_vars):
                        start = _parse_src_start(node.get("src"))
                        if start is not None:
                            write_candidates.append((start, node))

                if not call_candidates or not write_candidates:
                    continue

                # If there exists a write that occurs after some external call,
                # raise a finding (heuristic approximation).
                suspicious = any(
                    call_start < write_start
                    for call_start, _call_node in call_candidates
                    for write_start, _write_node in write_candidates
                )
                if not suspicious:
                    continue

                _, earliest_call_node = min(call_candidates, key=lambda t: t[0])
                location = _node_source_location(file_name, earliest_call_node)

                findings.append(
                    Finding(
                        detector="reentrancy",
                        title="Potential reentrancy: external call before state update",
                        description=(
                            "A function performs an external call (e.g., call/send/transfer) "
                            "before updating a state variable. This ordering violates "
                            "checks-effects-interactions and may enable reentrant re-execution."
                        ),
                        severity=Severity.HIGH,
                        confidence="medium",
                        location=location,
                        contract=contract_name,
                        function=function_name,
                    )
                )

    return findings


_EXTERNAL_CALL_MEMBER_NAMES = {
    # Low-level call family
    "call",
    "delegatecall",
    "staticcall",
    "callcode",
    # Common transfer helpers
    "send",
    "transfer",
}


def _parse_src_start(src: Any) -> int | None:
    """Extract the `start` integer from Solidity AST `src` strings."""
    if not isinstance(src, str):
        return None
    # Typical format: "123:45:0"
    start_str = src.split(":", 1)[0]
    try:
        return int(start_str)
    except ValueError:
        return None


def _walk_solc_nodes(root: Any) -> list[dict[str, Any]]:
    """Deep-walk any Solc JSON AST, collecting dicts with a `nodeType` key.

    The repo's `scanner.ast.loader.walk_ast()` is tailored for a subset of keys
    (`nodes`, `body`, `statements`). Solc's AST nests most data under many
    other keys (e.g., `expression`). For detector heuristics we use a generic
    deep traversal instead.
    """

    out: list[dict[str, Any]] = []

    def rec(x: Any) -> None:
        if isinstance(x, dict):
            node_type = x.get("nodeType")
            if isinstance(node_type, str):
                out.append(x)
            for v in x.values():
                rec(v)
        elif isinstance(x, list):
            for item in x:
                rec(item)

    rec(root)
    return out


def _extract_state_variable_names(contract_node: dict[str, Any]) -> set[str]:
    state_vars: set[str] = set()
    for node in _walk_solc_nodes(contract_node):
        if node.get("nodeType") != "VariableDeclaration":
            continue
        if node.get("stateVariable") is not True:
            continue
        name = node.get("name")
        if isinstance(name, str) and name:
            state_vars.add(name)
    return state_vars


def _function_display_name(fn_node: dict[str, Any]) -> str:
    name = fn_node.get("name")
    if isinstance(name, str) and name:
        return name
    kind = fn_node.get("kind")
    if isinstance(kind, str) and kind:
        return kind
    return ""


def _function_has_nonreentrant_modifier(fn_node: dict[str, Any]) -> bool:
    modifiers = fn_node.get("modifiers", [])
    if not isinstance(modifiers, list):
        return False

    for mod in modifiers:
        if not isinstance(mod, dict):
            continue

        mod_name: str | None = None
        modifier_name = mod.get("modifierName")
        if isinstance(modifier_name, dict) and isinstance(
            modifier_name.get("name"), str
        ):
            mod_name = modifier_name["name"]
        elif isinstance(mod.get("name"), dict) and isinstance(
            mod["name"].get("name"), str
        ):
            mod_name = mod["name"]["name"]
        elif isinstance(mod.get("modifierName"), str):
            mod_name = mod.get("modifierName")

        if isinstance(mod_name, str) and mod_name.lower() == "nonreentrant":
            return True

    return False


def _is_external_call(fn_call_node: dict[str, Any]) -> bool:
    expr = fn_call_node.get("expression")
    if not isinstance(expr, dict):
        return False
    if expr.get("nodeType") != "MemberAccess":
        return False

    member_name = expr.get("memberName")
    if not isinstance(member_name, str):
        return False
    return member_name in _EXTERNAL_CALL_MEMBER_NAMES


def _assignment_writes_state(assign_node: dict[str, Any], state_vars: set[str]) -> bool:
    lhs = assign_node.get("leftHandSide")
    if not isinstance(lhs, dict):
        return False
    for node in _walk_solc_nodes(lhs):
        if node.get("nodeType") == "Identifier":
            name = node.get("name")
            if isinstance(name, str) and name in state_vars:
                return True
    return False


def _unary_op_writes_state(unary_node: dict[str, Any], state_vars: set[str]) -> bool:
    if unary_node.get("operator") not in {"++", "--"}:
        return False
    subexpr = unary_node.get("subExpression")
    if not isinstance(subexpr, dict):
        return False
    for node in _walk_solc_nodes(subexpr):
        if node.get("nodeType") == "Identifier":
            name = node.get("name")
            if isinstance(name, str) and name in state_vars:
                return True
    return False


def _node_source_location(file_name: str, node: dict[str, Any]) -> SourceLocation | None:
    loc = node.get("loc")
    if not isinstance(loc, dict):
        return None
    start = loc.get("start")
    end = loc.get("end")

    if not isinstance(start, dict) or not isinstance(end, dict):
        return None
    line_start = start.get("line", 0)
    line_end = end.get("line", 0)
    col_start = start.get("column", 0)
    col_end = end.get("column", 0)

    if not all(isinstance(v, int) for v in (line_start, line_end, col_start, col_end)):
        return None

    return SourceLocation(
        file=file_name,
        line_start=line_start,
        line_end=line_end,
        column_start=col_start,
        column_end=col_end,
    )


