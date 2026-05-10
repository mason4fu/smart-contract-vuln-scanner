"""Reentrancy detector (AST + bytecode heuristics).

AST: flag functions where an external call (e.g. `call`, `delegatecall`,
`staticcall`, `send`, `transfer`) appears before a state-variable write.

Bytecode: if deployed runtime code contains a CALL-family opcode before a
later SSTORE, corroborate AST findings (raise confidence to high).
"""

from __future__ import annotations

from typing import Any

from scanner.bytecode.disasm import disassemble
from scanner.bytecode.loader import ContractBytecode, extract_bytecode
from scanner.detectors import BaseDetector, register_detector
from scanner.models.findings import Finding, Severity, SourceLocation
from scanner.models.ir import ContractInfo
from scanner.remediation import reentrancy_plan
from scanner.utils.source_map import build_line_map, offset_to_line_col

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
    sources = compiler_output.get("sources", {})

    for file_name, source_info in sources.items():
        ast_root = source_info.get("ast") or source_info.get("legacyAST") or {}
        if not isinstance(ast_root, dict) or not ast_root:
            continue
        source_text = source_info.get("content", "")
        line_map = build_line_map(source_text) if source_text else None

        for contract_node in _walk_solc_nodes(ast_root):
            if _node_kind(contract_node) != "ContractDefinition":
                continue

            contract_name = ""
            contract_name_val = _node_name(contract_node)
            if isinstance(contract_name_val, str):
                contract_name = contract_name_val
            state_vars = _extract_state_variable_names(contract_node)
            if not state_vars:
                continue
            function_nodes = [
                node for node in _direct_child_nodes(contract_node) if _node_kind(node) == "FunctionDefinition"
            ]
            modifier_nodes = [
                node for node in _direct_child_nodes(contract_node) if _node_kind(node) == "ModifierDefinition"
            ]
            helper_calls_with_external_interaction = _helper_functions_with_external_call(
                function_nodes
            )
            modifiers_with_external_interaction = _modifiers_with_external_call(modifier_nodes)

            for fn_node in function_nodes:
                function_name = _function_display_name(fn_node)
                if _function_has_nonreentrant_modifier(fn_node):
                    continue
                storage_aliases = _extract_storage_aliases(fn_node, state_vars)

                call_candidates: list[tuple[int, dict[str, Any]]] = []
                write_candidates: list[tuple[int, dict[str, Any]]] = []

                for node in _walk_solc_nodes(fn_node):
                    node_type = _node_kind(node)

                    if node_type == "FunctionCall" and (
                        _is_external_call(node)
                        or _is_internal_helper_call_with_external_call(
                            node,
                            helper_calls_with_external_interaction,
                            current_function=function_name,
                        )
                    ):
                        start = _parse_src_start(node.get("src"))
                        if start is not None:
                            call_candidates.append((start, node))
                    elif (
                        node_type == "Assignment"
                        and _assignment_writes_state(node, state_vars, storage_aliases)
                    ) or (
                        node_type == "UnaryOperation"
                        and _unary_op_writes_state(node, state_vars, storage_aliases)
                    ):
                        start = _parse_src_start(node.get("src"))
                        if start is not None:
                            write_candidates.append((start, node))

                for modifier_node in _modifier_invocations_with_external_call(
                    fn_node,
                    modifiers_with_external_interaction,
                ):
                    start = _parse_src_start(modifier_node.get("src"))
                    if start is not None:
                        call_candidates.append((start, modifier_node))

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
                location = _node_source_location(
                    file_name,
                    earliest_call_node,
                    line_map=line_map,
                )

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
                        **reentrancy_plan(bytecode=False),
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


def _bytecode_call_before_sstore_sequences(
    deployed_hex: str, *, window: int = 12
) -> list[tuple[int, int, str]]:
    """Return suspicious CALL-family -> SSTORE sequences as (call_pc, sstore_pc, mnemonic)."""
    raw = deployed_hex.strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not raw:
        return []
    try:
        instructions = disassemble(raw)
    except (OSError, ValueError):
        return []

    sequences: list[tuple[int, int, str]] = []
    for idx, instr in enumerate(instructions):
        mnemonic = _instruction_mnemonic(instr)
        if mnemonic not in _CALL_MNEMONICS:
            continue
        for next_instr in instructions[idx + 1 : idx + 1 + window]:
            if _instruction_mnemonic(next_instr) == "SSTORE":
                sequences.append((int(instr.pc), int(next_instr.pc), mnemonic))
                break
    return sequences


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


def _src_length(src: Any) -> int | None:
    if not isinstance(src, str):
        return None
    parts = src.split(":")
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
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
            legacy_name = x.get("name")
            if isinstance(node_type, str) or isinstance(legacy_name, str):
                out.append(x)
            for v in x.values():
                rec(v)
        elif isinstance(x, list):
            for item in x:
                rec(item)

    rec(root)
    return out


def _node_kind(node: dict[str, Any]) -> str:
    node_type = node.get("nodeType")
    if isinstance(node_type, str) and node_type:
        return node_type
    legacy_name = node.get("name")
    if isinstance(legacy_name, str):
        return legacy_name
    return ""


def _node_name(node: dict[str, Any]) -> str:
    direct = node.get("name")
    if isinstance(direct, str) and _node_kind(node) != direct:
        return direct
    attrs = node.get("attributes", {})
    if isinstance(attrs, dict):
        attr_name = attrs.get("name") or attrs.get("value")
        if isinstance(attr_name, str):
            return attr_name
    return ""


def _extract_state_variable_names(contract_node: dict[str, Any]) -> set[str]:
    state_vars: set[str] = set()
    for node in _direct_child_nodes(contract_node):
        if _node_kind(node) != "VariableDeclaration":
            continue
        if node.get("stateVariable") is not True and "attributes" not in node:
            continue
        name = _node_name(node)
        if isinstance(name, str) and name:
            state_vars.add(name)
    return state_vars


def _function_display_name(fn_node: dict[str, Any]) -> str:
    name = _node_name(fn_node)
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
    expr = _call_expression(fn_call_node)
    return _expression_contains_external_call(expr)


def _assignment_writes_state(
    assign_node: dict[str, Any],
    state_vars: set[str],
    storage_aliases: set[str],
) -> bool:
    lhs = assign_node.get("leftHandSide")
    if not isinstance(lhs, dict):
        children = _child_nodes(assign_node)
        lhs = children[0] if children else None
    return _expression_writes_state(lhs, state_vars, storage_aliases)


def _expression_writes_state(
    expr: Any,
    state_vars: set[str],
    storage_aliases: set[str],
) -> bool:
    """True if the expression is (or ends in) a write to a contract state variable."""
    if not isinstance(expr, dict):
        return False
    nt = _node_kind(expr)
    if nt == "Identifier":
        name = _node_name(expr)
        return isinstance(name, str) and (name in state_vars or name in storage_aliases)
    if nt == "MemberAccess":
        inner = expr.get("expression")
        if not isinstance(inner, dict):
            children = _child_nodes(expr)
            inner = children[0] if children else None
        return _expression_writes_state(inner, state_vars, storage_aliases)
    if nt == "IndexAccess":
        base = expr.get("baseExpression") or expr.get("base")
        if not isinstance(base, dict):
            children = _child_nodes(expr)
            base = children[0] if children else None
        return _expression_writes_state(base, state_vars, storage_aliases)
    return False


def _unary_op_writes_state(
    unary_node: dict[str, Any],
    state_vars: set[str],
    storage_aliases: set[str],
) -> bool:
    operator = unary_node.get("operator")
    if not isinstance(operator, str):
        attrs = unary_node.get("attributes", {})
        if isinstance(attrs, dict):
            operator = attrs.get("operator")
    if operator not in {"++", "--"}:
        return False
    subexpr = unary_node.get("subExpression")
    if not isinstance(subexpr, dict):
        children = _child_nodes(unary_node)
        subexpr = children[-1] if children else None
    return _expression_writes_state(subexpr, state_vars, storage_aliases)


def _node_source_location(
    file_name: str,
    node: dict[str, Any],
    *,
    line_map: list[int] | None = None,
) -> SourceLocation | None:
    if line_map is not None:
        offset = _parse_src_start(node.get("src"))
        length = _src_length(node.get("src"))
        if offset is not None and length is not None:
            line_start, column_start, line_end, column_end = offset_to_line_col(
                offset,
                length,
                line_map,
            )
            return SourceLocation(
                file=file_name,
                line_start=line_start,
                line_end=line_end,
                column_start=column_start,
                column_end=column_end,
            )

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


def _extract_storage_aliases(fn_node: dict[str, Any], state_vars: set[str]) -> set[str]:
    aliases: set[str] = set()
    for node in _walk_solc_nodes(fn_node):
        if _node_kind(node) != "VariableDeclarationStatement":
            continue

        initial_value = node.get("initialValue")
        if not isinstance(initial_value, dict):
            children = _child_nodes(node)
            initial_value = children[1] if len(children) >= 2 else None
        if not _expression_writes_state(initial_value, state_vars, aliases):
            continue

        for name in _declared_names(node):
            aliases.add(name)
    return aliases


def _declared_names(node: dict[str, Any]) -> list[str]:
    declarations = node.get("declarations")
    names: list[str] = []
    if isinstance(declarations, list):
        for decl in declarations:
            if isinstance(decl, dict):
                name = _node_name(decl)
                if name:
                    names.append(name)
    if names:
        return names

    children = _child_nodes(node)
    for child in children:
        if _node_kind(child) == "VariableDeclaration":
            name = _node_name(child)
            if name:
                names.append(name)
    return names


def _direct_child_nodes(node: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("nodes", "children"):
        value = node.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _child_nodes(node: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in node.get("children", []) if isinstance(item, dict)]


def _call_expression(fn_call_node: dict[str, Any]) -> Any:
    expr = fn_call_node.get("expression")
    if isinstance(expr, dict):
        return expr
    children = _child_nodes(fn_call_node)
    return children[0] if children else None


def _member_name(node: dict[str, Any]) -> str:
    member_name = node.get("memberName")
    if isinstance(member_name, str):
        return member_name
    attrs = node.get("attributes", {})
    if isinstance(attrs, dict):
        legacy_member = attrs.get("member_name")
        if isinstance(legacy_member, str):
            return legacy_member
    return ""


def _expression_contains_external_call(expr: Any) -> bool:
    if not isinstance(expr, dict):
        return False

    node_kind = _node_kind(expr)
    if node_kind == "FunctionCallOptions":
        return _expression_contains_external_call(expr.get("expression"))
    if node_kind == "FunctionCall":
        return _expression_contains_external_call(_call_expression(expr))
    if node_kind == "MemberAccess":
        member_name = _member_name(expr)
        if member_name in _EXTERNAL_CALL_MEMBER_NAMES:
            return True
        inner = expr.get("expression")
        if not isinstance(inner, dict):
            children = _child_nodes(expr)
            inner = children[0] if children else None
        if isinstance(inner, dict) and _node_kind(inner) == "FunctionCall":
            return True
        return _expression_contains_external_call(inner)
    return False


def _helper_functions_with_external_call(function_nodes: list[dict[str, Any]]) -> set[str]:
    helpers: set[str] = set()
    for fn_node in function_nodes:
        name = _function_display_name(fn_node)
        if not name:
            continue
        if any(
            _node_kind(node) == "FunctionCall" and _is_external_call(node)
            for node in _walk_solc_nodes(fn_node)
        ):
            helpers.add(name)
    return helpers


def _modifiers_with_external_call(modifier_nodes: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for modifier_node in modifier_nodes:
        name = _function_display_name(modifier_node)
        if not name:
            continue
        if any(
            _node_kind(node) == "FunctionCall" and _is_external_call(node)
            for node in _walk_solc_nodes(modifier_node)
        ):
            names.add(name)
    return names


def _is_internal_helper_call_with_external_call(
    fn_call_node: dict[str, Any],
    helper_names: set[str],
    *,
    current_function: str,
) -> bool:
    expr = _call_expression(fn_call_node)
    if not isinstance(expr, dict):
        return False
    if _node_kind(expr) != "Identifier":
        return False
    callee_name = _node_name(expr)
    if not callee_name or callee_name == current_function:
        return False
    return callee_name in helper_names


def _modifier_invocations_with_external_call(
    fn_node: dict[str, Any],
    modifier_names: set[str],
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    modifiers = fn_node.get("modifiers", [])
    if not isinstance(modifiers, list):
        return hits
    for modifier in modifiers:
        if not isinstance(modifier, dict):
            continue
        modifier_name = modifier.get("modifierName")
        if isinstance(modifier_name, dict):
            name = _node_name(modifier_name)
            if name in modifier_names:
                hits.append(modifier)
    return hits


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
        findings: list[Finding] = []
        for bytecode in bytecodes:
            findings.extend(detect_reentrancy_bytecode(bytecode))
        return findings

    def detect_from_compiler_output(self, compiler_output: dict[str, Any]) -> list[Finding]:
        return detect_reentrancy(compiler_output)


def detect_reentrancy_bytecode(bytecode: ContractBytecode) -> list[Finding]:
    """Bytecode-only fallback for reentrancy-like CALL-before-SSTORE ordering."""
    raw = (bytecode.deployed_bytecode or bytecode.creation_bytecode or "").strip()
    if not raw:
        return []
    sequences = _bytecode_call_before_sstore_sequences(raw)
    if not sequences:
        return []

    confidence = "medium" if len(sequences) >= 2 else "low"
    seq_preview = ", ".join(
        f"{mnemonic}@{call_pc}->SSTORE@{sstore_pc}"
        for call_pc, sstore_pc, mnemonic in sequences[:3]
    )
    return [
        Finding(
            detector="reentrancy",
            title="Potential reentrancy pattern (bytecode)",
            description=(
                f"Runtime bytecode for contract '{bytecode.contract_name}' contains "
                f"CALL-family instruction(s) before later SSTORE writes: {seq_preview}. "
                "This ordering is a bytecode-only heuristic for checks-effects-interactions "
                "violations and should be verified against source code or source maps."
            ),
            severity=Severity.MEDIUM,
            confidence=confidence,
            contract=bytecode.contract_name,
            swc_id="SWC-107",
            **reentrancy_plan(bytecode=True),
        )
    ]
