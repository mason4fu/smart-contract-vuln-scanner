"""Reentrancy detector (AST + bytecode heuristics).

AST: flag functions where an external call (e.g. `call`, `delegatecall`,
`staticcall`, `send`, `transfer`) appears before a state-variable write.

Bytecode: if deployed runtime code contains a CALL-family opcode before a
later SSTORE, corroborate AST findings (raise confidence to high).
"""

from __future__ import annotations

from typing import Any

from scanner.ast.loader import extract_ast
from scanner.bytecode.disasm import disassemble
from scanner.bytecode.loader import ContractBytecode, extract_bytecode
from scanner.detectors import BaseDetector, register_detector
from scanner.models.findings import Finding, Severity, SourceLocation
from scanner.models.ir import ContractInfo

_CALL_MNEMONICS = frozenset({"CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"})


def detect_reentrancy(compiler_output: dict[str, Any]) -> list[Finding]:
    """Detect potential reentrancy vulnerabilities (AST-based).

    Args:
        compiler_output: Standard JSON compiler output from `solcx`.

    Returns:
        List of detected `Finding` objects.
    """

    findings: list[Finding] = []
    bytecode_corroboration = _bytecode_call_before_sstore_by_contract(compiler_output)
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
                    elif (
                        node_type == "Assignment" and _assignment_writes_state(node, state_vars)
                    ) or (
                        node_type == "UnaryOperation" and _unary_op_writes_state(node, state_vars)
                    ):
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

                bc_ok = bytecode_corroboration.get(contract_name, False)
                confidence = "high" if bc_ok else "medium"
                desc = (
                    "A function performs an external call (e.g., call/send/transfer) "
                    "before updating a state variable. This ordering violates "
                    "checks-effects-interactions and may enable reentrant re-execution."
                )
                if bc_ok:
                    desc += (
                        " Deployed bytecode also shows a CALL-family instruction "
                        "before a later SSTORE (heuristic corroboration)."
                    )

                findings.append(
                    Finding(
                        detector="reentrancy",
                        title="Potential reentrancy: external call before state update",
                        description=desc,
                        severity=Severity.HIGH,
                        confidence=confidence,
                        location=location,
                        contract=contract_name,
                        function=function_name,
                        swc_id="SWC-107",
                    )
                )

    return findings


def _instruction_mnemonic(instr: Any) -> str:
    for attr in ("mnemonic", "name"):
        v = getattr(instr, attr, None)
        if isinstance(v, str):
            return v.upper()
    return ""


def _deployed_bytecode_suggests_call_before_sstore(deployed_hex: str) -> bool:
    raw = deployed_hex.strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not raw:
        return False
    try:
        instructions = disassemble(raw)
    except (OSError, ValueError):
        return False
    saw_call = False
    for instr in instructions:
        m = _instruction_mnemonic(instr)
        if m in _CALL_MNEMONICS:
            saw_call = True
        elif m == "SSTORE" and saw_call:
            return True
    return False


def _bytecode_call_before_sstore_by_contract(compiler_output: dict[str, Any]) -> dict[str, bool]:
    out: dict[str, bool] = {}
    for cb in extract_bytecode(compiler_output):
        if _deployed_bytecode_suggests_call_before_sstore(cb.deployed_bytecode):
            out[cb.contract_name] = True
    return out


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
        if isinstance(modifier_name, dict) and isinstance(modifier_name.get("name"), str):
            mod_name = modifier_name["name"]
        elif isinstance(mod.get("name"), dict) and isinstance(mod["name"].get("name"), str):
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
    # `addr.call{value: x}("")` is a FunctionCall whose callee is FunctionCallOptions
    # wrapping a MemberAccess (`.call`).
    if expr.get("nodeType") == "FunctionCallOptions":
        inner = expr.get("expression")
        if isinstance(inner, dict) and inner.get("nodeType") == "MemberAccess":
            member_name = inner.get("memberName")
            return isinstance(member_name, str) and member_name in _EXTERNAL_CALL_MEMBER_NAMES
        return False
    if expr.get("nodeType") != "MemberAccess":
        return False

    member_name = expr.get("memberName")
    if not isinstance(member_name, str):
        return False
    return member_name in _EXTERNAL_CALL_MEMBER_NAMES


def _assignment_writes_state(assign_node: dict[str, Any], state_vars: set[str]) -> bool:
    lhs = assign_node.get("leftHandSide")
    return _expression_writes_state(lhs, state_vars)


def _expression_writes_state(expr: Any, state_vars: set[str]) -> bool:
    """True if the expression is (or ends in) a write to a contract state variable."""
    if not isinstance(expr, dict):
        return False
    nt = expr.get("nodeType")
    if nt == "Identifier":
        name = expr.get("name")
        return isinstance(name, str) and name in state_vars
    if nt == "IndexAccess":
        base = expr.get("baseExpression") or expr.get("base")
        return _expression_writes_state(base, state_vars)
    return False


def _unary_op_writes_state(unary_node: dict[str, Any], state_vars: set[str]) -> bool:
    if unary_node.get("operator") not in {"++", "--"}:
        return False
    subexpr = unary_node.get("subExpression")
    return _expression_writes_state(subexpr, state_vars)


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


@register_detector
class ReentrancyDetector(BaseDetector):
    """Registers the AST/bytecode reentrancy heuristic with the scanner CLI."""

    name = "reentrancy"
    description = (
        "Flags external calls that may execute before subsequent state updates "
        "(checks-effects-interactions heuristic; bytecode corroboration when available)."
    )

    def detect_from_source(self, contracts: list[ContractInfo]) -> list[Finding]:
        return []

    def detect_from_bytecode(
        self, bytecodes: list[ContractBytecode], extra: dict[str, Any] | None = None
    ) -> list[Finding]:
        return []

    def detect_from_compiler_output(self, compiler_output: dict[str, Any]) -> list[Finding]:
        return detect_reentrancy(compiler_output)
