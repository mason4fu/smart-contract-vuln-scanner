"""Arithmetic overflow/underflow detector (SWC-101).

v1 focus:
- Source-level AST detection for risky arithmetic patterns
- Solidity version gating (pre-0.8.0 by default, or unchecked blocks in 0.8+)
"""

from __future__ import annotations

import re
from typing import Any

from scanner.bytecode.loader import ContractBytecode
from scanner.detectors import BaseDetector, register_detector
from scanner.models.findings import Finding, Severity, SourceLocation
from scanner.models.ir import ContractInfo
from scanner.utils.source_map import build_line_map, offset_to_line_col

_DETECTOR_NAME = "arithmetic"
_RISKY_BINARY_OPS = {"+", "-", "*"}
_RISKY_ASSIGNMENT_OPS = {"+=", "-=", "*="}
_SAFE_MATH_MEMBERS = {"add", "sub", "mul"}
_ACCOUNTING_HINTS = re.compile(
    r"(balance|supply|total|credit|debit|allowance|amount|value|shares|points|counter)",
    re.IGNORECASE,
)
_SENSITIVE_CALL_HINTS = re.compile(
    r"(transfer|send|mint|burn|withdraw|deposit|payout|redeem)",
    re.IGNORECASE,
)


@register_detector
class ArithmeticDetector(BaseDetector):
    """Detects SWC-101 arithmetic overflow/underflow risks."""

    name = _DETECTOR_NAME
    description = (
        "Flags risky +, -, * arithmetic in pre-0.8.0 Solidity (or unchecked blocks in 0.8+) "
        "when used in state/accounting-sensitive paths."
    )

    def detect_from_source(self, contracts: list[ContractInfo]) -> list[Finding]:
        return []

    def detect_from_compiler_output(self, compiler_output: dict[str, Any]) -> list[Finding]:
        return detect_arithmetic(compiler_output)

    def detect_from_bytecode(
        self,
        bytecodes: list[ContractBytecode],
        extra: dict[str, Any] | None = None,
    ) -> list[Finding]:
        return []


def detect_arithmetic(compiler_output: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    sources = compiler_output.get("sources", {})
    for source_file, source_data in sources.items():
        ast_root = source_data.get("ast")
        if not isinstance(ast_root, dict):
            continue
        source_content = source_data.get("content", "")
        if not isinstance(source_content, str):
            source_content = ""
        line_map = build_line_map(source_content) if source_content else None
        source_version = _detect_version_tuple(source_content)

        for contract in _find_nodes(ast_root, "ContractDefinition"):
            contract_name = str(contract.get("name", ""))
            state_vars = _state_vars(contract)
            for function in _find_nodes(contract, "FunctionDefinition"):
                if function.get("implemented") is False:
                    continue
                fn_name = _function_name(function)
                is_unchecked_fn = False
                for node, ancestors in _walk_with_ancestors(function):
                    finding = _evaluate_node(
                        node=node,
                        ancestors=ancestors,
                        source_file=source_file,
                        line_map=line_map,
                        source_version=source_version,
                        contract_name=contract_name,
                        function_name=fn_name,
                        state_vars=state_vars,
                    )
                    if finding is None:
                        continue
                    # Keep only one finding per function for v1 precision-first behavior.
                    findings.append(finding)
                    is_unchecked_fn = True
                    break
                if is_unchecked_fn:
                    continue
    return findings


def _evaluate_node(
    *,
    node: dict[str, Any],
    ancestors: list[dict[str, Any]],
    source_file: str,
    line_map: list[int] | None,
    source_version: tuple[int, int, int] | None,
    contract_name: str,
    function_name: str,
    state_vars: set[str],
) -> Finding | None:
    node_type = node.get("nodeType")
    op = ""
    kind = ""
    expr_for_checks: dict[str, Any] | None = None
    writes_state = False
    severity = Severity.MEDIUM
    confidence = "medium"

    if node_type == "Assignment":
        op = str(node.get("operator", ""))
        rhs = node.get("rightHandSide")
        lhs = node.get("leftHandSide")
        if op in _RISKY_ASSIGNMENT_OPS:
            kind = "compound_state_arithmetic"
            expr_for_checks = node
        elif isinstance(rhs, dict) and rhs.get("nodeType") == "BinaryOperation":
            rhs_op = str(rhs.get("operator", ""))
            if rhs_op in _RISKY_BINARY_OPS:
                op = rhs_op
                kind = "binary_assignment"
                expr_for_checks = rhs
        writes_state = _writes_state(lhs, state_vars)
    elif node_type == "UnaryOperation":
        op = str(node.get("operator", ""))
        if op in {"++", "--"}:
            kind = "unary_update"
            expr_for_checks = node
            writes_state = _writes_state(node.get("subExpression"), state_vars)
    elif node_type == "BinaryOperation":
        op = str(node.get("operator", ""))
        if op in _RISKY_BINARY_OPS:
            kind = "raw_binary"
            expr_for_checks = node
    else:
        return None

    if not kind or expr_for_checks is None:
        return None
    if _is_safe_math_expression(expr_for_checks):
        return None
    if _suppressed_by_version(source_version, ancestors):
        return None
    if _has_explicit_bound_guard(ancestors):
        return None

    if writes_state:
        severity = Severity.HIGH
        confidence = "high"
    elif _is_sensitive_context(ancestors):
        severity = Severity.HIGH
        confidence = "medium"
    elif source_version is None:
        confidence = "low"
    else:
        severity = Severity.MEDIUM
        confidence = "medium"

    location = _source_location_from_src(source_file, node.get("src"), line_map)
    title = "Potential integer overflow/underflow in arithmetic operation"
    description = (
        f"Arithmetic operation '{op}' may overflow/underflow in contract '{contract_name}' "
        f"function '{function_name}'. Solidity <0.8.0 arithmetic does not automatically "
        "revert on wraparound; this operation appears unchecked in a state- or value-"
        "sensitive context."
    )
    return Finding(
        detector=_DETECTOR_NAME,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        location=location,
        contract=contract_name,
        function=function_name,
        swc_id="SWC-101",
        remediation=(
            "Use Solidity >=0.8 checked arithmetic or add explicit bounds checks "
            "before arithmetic updates."
        ),
    )


def _find_nodes(root: Any, node_type: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def rec(x: Any) -> None:
        if isinstance(x, dict):
            if x.get("nodeType") == node_type:
                out.append(x)
            for v in x.values():
                rec(v)
        elif isinstance(x, list):
            for item in x:
                rec(item)

    rec(root)
    return out


def _walk_with_ancestors(root: dict[str, Any]) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    out: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []

    def rec(x: Any, ancestors: list[dict[str, Any]]) -> None:
        if isinstance(x, dict):
            node_type = x.get("nodeType")
            if isinstance(node_type, str):
                out.append((x, ancestors.copy()))
                next_anc = ancestors + [x]
            else:
                next_anc = ancestors
            for v in x.values():
                rec(v, next_anc)
        elif isinstance(x, list):
            for item in x:
                rec(item, ancestors)

    rec(root, [])
    return out


def _state_vars(contract_node: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for node in _find_nodes(contract_node, "VariableDeclaration"):
        if node.get("stateVariable") is True:
            name = node.get("name")
            if isinstance(name, str) and name:
                names.add(name)
    return names


def _function_name(fn_node: dict[str, Any]) -> str:
    name = fn_node.get("name")
    if isinstance(name, str) and name:
        return name
    kind = fn_node.get("kind")
    if isinstance(kind, str):
        return kind
    return ""


def _writes_state(expr: Any, state_vars: set[str]) -> bool:
    if not isinstance(expr, dict):
        return False
    nt = expr.get("nodeType")
    if nt == "Identifier":
        name = expr.get("name")
        return isinstance(name, str) and name in state_vars
    if nt == "IndexAccess":
        base = expr.get("baseExpression") or expr.get("base")
        return _writes_state(base, state_vars)
    if nt == "MemberAccess":
        inner = expr.get("expression")
        return _writes_state(inner, state_vars)
    return False


def _is_safe_math_expression(node: dict[str, Any]) -> bool:
    for n in _find_nodes(node, "MemberAccess"):
        member = n.get("memberName")
        if isinstance(member, str) and member in _SAFE_MATH_MEMBERS:
            return True
    return False


def _suppressed_by_version(
    version: tuple[int, int, int] | None, ancestors: list[dict[str, Any]]
) -> bool:
    if _inside_unchecked_block(ancestors):
        return False
    if version is None:
        return False
    return version >= (0, 8, 0)


def _inside_unchecked_block(ancestors: list[dict[str, Any]]) -> bool:
    for anc in ancestors:
        if anc.get("nodeType") == "UncheckedBlock":
            return True
    return False


def _has_explicit_bound_guard(ancestors: list[dict[str, Any]]) -> bool:
    for anc in reversed(ancestors):
        if anc.get("nodeType") != "FunctionDefinition":
            continue
        for fn_node, _ in _walk_with_ancestors(anc):
            if fn_node.get("nodeType") != "FunctionCall":
                continue
            expr = fn_node.get("expression", {})
            if not isinstance(expr, dict):
                continue
            callee = expr.get("name")
            if callee not in {"require", "assert"}:
                continue
            args = fn_node.get("arguments", [])
            if not args:
                continue
            cond = args[0]
            if not isinstance(cond, dict):
                continue
            for b in _find_nodes(cond, "BinaryOperation"):
                op = b.get("operator")
                if isinstance(op, str) and op in _RISKY_BINARY_OPS:
                    return True
        return False
    return False


def _is_sensitive_context(ancestors: list[dict[str, Any]]) -> bool:
    for anc in ancestors:
        if anc.get("nodeType") == "FunctionCall":
            expr = anc.get("expression", {})
            if isinstance(expr, dict):
                callee = str(expr.get("name", "")) or str(expr.get("memberName", ""))
                if _SENSITIVE_CALL_HINTS.search(callee):
                    return True
        if anc.get("nodeType") == "Identifier":
            name = anc.get("name")
            if isinstance(name, str) and _ACCOUNTING_HINTS.search(name):
                return True
    return False


def _source_location_from_src(
    source_file: str, src: Any, line_map: list[int] | None
) -> SourceLocation | None:
    if not isinstance(src, str):
        return None
    try:
        parts = src.split(":")
        if len(parts) < 2:
            return None
        offset = int(parts[0])
        length = int(parts[1])
    except (TypeError, ValueError):
        return None
    if line_map is None:
        return SourceLocation(file=source_file, line_start=offset)
    line_start, column_start, line_end, column_end = offset_to_line_col(offset, length, line_map)
    return SourceLocation(
        file=source_file,
        line_start=line_start,
        line_end=line_end,
        column_start=column_start,
        column_end=column_end,
    )


def _detect_version_tuple(source: str) -> tuple[int, int, int] | None:
    match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
    if not match:
        return None
    nums = re.findall(r"\d+\.\d+\.\d+", match.group(1))
    if not nums:
        return None
    # Conservative for v1: use the first explicit version literal.
    major, minor, patch = nums[0].split(".")
    return int(major), int(minor), int(patch)
