"""Source-level extraction for unchecked low-level external calls."""

from __future__ import annotations

from typing import Any

from scanner.ast.loader import extract_ast
from scanner.models.findings import SourceLocation
from scanner.models.unchecked_calls import (
    CallKind,
    CallResultStatus,
    CallResultUsage,
    ExternalCallSite,
    FollowupEffect,
)
from scanner.utils.source_map import build_line_map, offset_to_line_col

_LOW_LEVEL_MEMBERS = {
    "call": CallKind.CALL,
    "delegatecall": CallKind.DELEGATECALL,
    "staticcall": CallKind.STATICCALL,
    "send": CallKind.SEND,
    "callcode": CallKind.CALLCODE,
}
_LEGACY_CALL_OPTIONS = {"value", "gas"}
_CHECK_CALLEES = {"require", "assert"}
_FAILURE_TERMINATORS = {
    "RevertStatement",
    "Throw",
    "Return",
    "Break",
    "Continue",
}


def analyze_unchecked_external_calls(compiler_output: dict[str, Any]) -> list[ExternalCallSite]:
    """Extract and classify low-level call result handling from compiler output."""
    asts = extract_ast(compiler_output)
    sources = compiler_output.get("sources", {})
    results: list[ExternalCallSite] = []

    for source_file, ast_root in asts.items():
        source_text = sources.get(source_file, {}).get("content", "")
        line_map = build_line_map(source_text) if source_text else None
        parent_map = _build_parent_map(ast_root)

        for contract_node in _walk_nodes(ast_root):
            if contract_node.get("nodeType") != "ContractDefinition":
                continue
            contract_name = str(contract_node.get("name") or "")
            helper_checks = _helper_check_functions(contract_node)
            function_nodes = [
                node
                for node in contract_node.get("nodes", [])
                if isinstance(node, dict) and node.get("nodeType") == "FunctionDefinition"
            ]
            for fn_node in function_nodes:
                results.extend(
                    _analyze_function(
                        fn_node,
                        contract_name=contract_name,
                        source_file=source_file,
                        source_text=source_text,
                        line_map=line_map,
                        parent_map=parent_map,
                        helper_checks=helper_checks,
                    )
                )
    return results


def _analyze_function(
    fn_node: dict[str, Any],
    *,
    contract_name: str,
    source_file: str,
    source_text: str,
    line_map: list[int] | None,
    parent_map: dict[int, dict[str, Any]],
    helper_checks: set[str],
) -> list[ExternalCallSite]:
    function_name = _function_display_name(fn_node)
    all_nodes = _walk_nodes(fn_node.get("body", {})) if fn_node.get("body") else []
    call_nodes = _collect_call_nodes(all_nodes)
    results: list[ExternalCallSite] = []

    for call_node, call_kind in call_nodes:
        location = _source_loc(call_node, source_file, line_map=line_map)
        usage = _classify_call_usage(call_node, fn_node, parent_map, helper_checks)
        assigned_variables = [v for v in (usage.success_variable, usage.returndata_variable) if v]
        followup_effects = _followup_effects(call_node, fn_node, parent_map, line_map, source_file)
        site = ExternalCallSite(
            call_kind=call_kind,
            contract=contract_name,
            function=function_name,
            source_file=source_file,
            source_location=location,
            assigned_variables=assigned_variables,
            result_usage=usage,
            followup_effects=followup_effects,
            snippet=_source_snippet(source_text, call_node.get("src")),
        )
        results.append(site)
    return results


def _collect_call_nodes(nodes: list[dict[str, Any]]) -> list[tuple[dict[str, Any], CallKind]]:
    raw: list[tuple[dict[str, Any], CallKind, tuple[int, int]]] = []
    for node in nodes:
        if node.get("nodeType") != "FunctionCall":
            continue
        kind = _call_kind_from_function_call(node)
        if kind is None:
            continue
        span = _src_span(node.get("src"))
        if span is None:
            span = (0, 0)
        raw.append((node, kind, span))

    # Legacy chained calls expose nested FunctionCall nodes. Keep the widest
    # low-level call span and drop nested duplicates in the same expression.
    raw.sort(key=lambda item: item[2][1], reverse=True)
    selected: list[tuple[dict[str, Any], CallKind, tuple[int, int]]] = []
    for node, kind, span in raw:
        start, length = span
        end = start + length
        contained = False
        for _sel_node, sel_kind, sel_span in selected:
            sel_start, sel_len = sel_span
            sel_end = sel_start + sel_len
            if kind == sel_kind and sel_start <= start and end <= sel_end:
                contained = True
                break
        if not contained:
            selected.append((node, kind, span))

    selected.sort(key=lambda item: item[2][0])
    return [(node, kind) for node, kind, _span in selected]


def _classify_call_usage(
    call_node: dict[str, Any],
    fn_node: dict[str, Any],
    parent_map: dict[int, dict[str, Any]],
    helper_checks: set[str],
) -> CallResultUsage:
    if _is_directly_checked(call_node, parent_map):
        return CallResultUsage(
            status=CallResultStatus.CHECKED,
            success_checked=True,
            failure_handling_exists=True,
            evidence="call success is used directly in require/assert or failure branch",
        )

    if _is_returned_to_caller(call_node, parent_map):
        return CallResultUsage(
            status=CallResultStatus.DELEGATED,
            returned_to_caller=True,
            evidence="call success is returned to the caller",
        )

    success_var, returndata_var = _assigned_result_variables(call_node, parent_map)
    if not success_var:
        status = CallResultStatus.UNCHECKED
        evidence = "call executes as a standalone expression or omits the success return value"
        if returndata_var:
            status = CallResultStatus.PROBABLY_UNCHECKED
            evidence = "returndata is captured but the success return value is omitted"
        return CallResultUsage(
            status=status,
            returndata_variable=returndata_var,
            evidence=evidence,
        )

    later_nodes = _nodes_after_call(fn_node, call_node)
    used = False
    for later in later_nodes:
        if not _node_references_identifier(later, success_var):
            continue
        used = True
        if _node_checks_identifier(later, success_var, helper_checks):
            return CallResultUsage(
                status=CallResultStatus.CHECKED,
                success_variable=success_var,
                returndata_variable=returndata_var,
                success_checked=True,
                failure_handling_exists=True,
                evidence=f"success variable '{success_var}' gates execution after the call",
            )
        if later.get("nodeType") == "Return":
            return CallResultUsage(
                status=CallResultStatus.DELEGATED,
                success_variable=success_var,
                returndata_variable=returndata_var,
                returned_to_caller=True,
                evidence=f"success variable '{success_var}' is returned to the caller",
            )

    if not used:
        return CallResultUsage(
            status=CallResultStatus.UNCHECKED,
            success_variable=success_var,
            returndata_variable=returndata_var,
            evidence=f"success variable '{success_var}' is assigned but never used",
        )

    return CallResultUsage(
        status=CallResultStatus.PROBABLY_UNCHECKED,
        success_variable=success_var,
        returndata_variable=returndata_var,
        evidence=f"success variable '{success_var}' is used, but not as a failure gate",
    )


def _is_directly_checked(call_node: dict[str, Any], parent_map: dict[int, dict[str, Any]]) -> bool:
    for ancestor in _ancestors(call_node, parent_map):
        node_type = ancestor.get("nodeType")
        if node_type == "FunctionCall" and _callee_name(ancestor) in _CHECK_CALLEES:
            return True
        if node_type == "IfStatement":
            condition = ancestor.get("condition", {})
            if _contains_node(condition, call_node):
                return _if_has_failure_handling(ancestor) or True
        if node_type == "ExpressionStatement":
            break
        if node_type in ("VariableDeclarationStatement", "Assignment"):
            break
    return False


def _is_returned_to_caller(
    call_node: dict[str, Any], parent_map: dict[int, dict[str, Any]]
) -> bool:
    return any(
        ancestor.get("nodeType") == "Return" for ancestor in _ancestors(call_node, parent_map)
    )


def _assigned_result_variables(
    call_node: dict[str, Any], parent_map: dict[int, dict[str, Any]]
) -> tuple[str, str]:
    for ancestor in _ancestors(call_node, parent_map):
        node_type = ancestor.get("nodeType")
        if node_type == "VariableDeclarationStatement":
            if not _contains_node(ancestor.get("initialValue"), call_node):
                return "", ""
            declarations = ancestor.get("declarations", [])
            names = [_decl_name(decl) for decl in declarations if isinstance(decl, dict)]
            return _first_two_names(names)
        if node_type == "Assignment":
            if not _contains_node(ancestor.get("rightHandSide"), call_node):
                return "", ""
            names = _assignment_lhs_names(ancestor.get("leftHandSide"))
            return _first_two_names(names)
        if node_type in ("ExpressionStatement", "Return", "IfStatement"):
            return "", ""
    return "", ""


def _first_two_names(names: list[str]) -> tuple[str, str]:
    first = names[0] if names else ""
    second = names[1] if len(names) > 1 else ""
    return first, second


def _decl_name(node: dict[str, Any]) -> str:
    name = node.get("name")
    return name if isinstance(name, str) else ""


def _assignment_lhs_names(lhs: Any) -> list[str]:
    if not isinstance(lhs, dict):
        return []
    if lhs.get("nodeType") == "Identifier":
        return [str(lhs.get("name") or "")]
    if lhs.get("nodeType") == "TupleExpression":
        names: list[str] = []
        for component in lhs.get("components", []):
            if isinstance(component, dict):
                names.append(_decl_name(component))
            else:
                names.append("")
        return names
    return []


def _nodes_after_call(fn_node: dict[str, Any], call_node: dict[str, Any]) -> list[dict[str, Any]]:
    call_start = _src_start(call_node.get("src"))
    if call_start is None:
        return []
    nodes = _walk_nodes(fn_node.get("body", {})) if fn_node.get("body") else []
    later = [
        node
        for node in nodes
        if (node_start := _src_start(node.get("src"))) is not None and node_start > call_start
    ]
    later.sort(key=lambda node: _src_start(node.get("src")) or 0)
    return later


def _node_checks_identifier(
    node: dict[str, Any], success_var: str, helper_checks: set[str]
) -> bool:
    node_type = node.get("nodeType")
    if node_type == "FunctionCall":
        callee = _callee_name(node)
        if callee in _CHECK_CALLEES:
            return True
        if callee in helper_checks:
            return True
    if node_type == "IfStatement":
        condition = node.get("condition", {})
        if _node_references_identifier(condition, success_var):
            return _if_has_failure_handling(node)
    return False


def _if_has_failure_handling(if_node: dict[str, Any]) -> bool:
    return _body_has_failure_terminator(if_node.get("trueBody")) or _body_has_failure_terminator(
        if_node.get("falseBody")
    )


def _body_has_failure_terminator(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    for child in _walk_nodes(node):
        node_type = child.get("nodeType")
        if node_type in _FAILURE_TERMINATORS:
            return True
        if node_type == "FunctionCall" and _callee_name(child) == "revert":
            return True
    return False


def _helper_check_functions(contract_node: dict[str, Any]) -> set[str]:
    helper_names: set[str] = set()
    for node in contract_node.get("nodes", []):
        if not isinstance(node, dict) or node.get("nodeType") != "FunctionDefinition":
            continue
        if node.get("visibility") not in ("internal", "private"):
            continue
        name = _function_display_name(node)
        if not name:
            continue
        params = _parameter_names(node)
        if not params:
            continue
        body = node.get("body", {})
        for body_node in _walk_nodes(body):
            if (
                body_node.get("nodeType") == "FunctionCall"
                and _callee_name(body_node) in _CHECK_CALLEES
                and any(_node_references_identifier(body_node, param) for param in params)
            ):
                helper_names.add(name)
            if body_node.get("nodeType") == "IfStatement" and _if_has_failure_handling(body_node):
                condition = body_node.get("condition", {})
                if any(_node_references_identifier(condition, param) for param in params):
                    helper_names.add(name)
    return helper_names


def _parameter_names(fn_node: dict[str, Any]) -> set[str]:
    params = fn_node.get("parameters", {}).get("parameters", [])
    return {
        str(param.get("name"))
        for param in params
        if isinstance(param, dict) and isinstance(param.get("name"), str) and param.get("name")
    }


def _followup_effects(
    call_node: dict[str, Any],
    fn_node: dict[str, Any],
    parent_map: dict[int, dict[str, Any]],
    line_map: list[int] | None,
    source_file: str,
) -> list[FollowupEffect]:
    effects: list[FollowupEffect] = []
    success_var, _returndata_var = _assigned_result_variables(call_node, parent_map)
    for node in _nodes_after_call(fn_node, call_node):
        if success_var and _node_checks_identifier(node, success_var, set()):
            break
        node_type = node.get("nodeType")
        if node_type == "Assignment":
            effects.append(
                FollowupEffect(
                    kind="state_or_local_assignment",
                    description="assignment after low-level call",
                    source_location=_source_loc(node, source_file, line_map=line_map),
                )
            )
        elif node_type == "UnaryOperation" and node.get("operator") in ("++", "--"):
            effects.append(
                FollowupEffect(
                    kind="mutation",
                    description="increment/decrement after low-level call",
                    source_location=_source_loc(node, source_file, line_map=line_map),
                )
            )
        elif node_type == "EmitStatement":
            effects.append(
                FollowupEffect(
                    kind="event",
                    description="event emitted after low-level call",
                    source_location=_source_loc(node, source_file, line_map=line_map),
                )
            )
        elif node_type == "FunctionCall" and _callee_name(node) not in _CHECK_CALLEES:
            effects.append(
                FollowupEffect(
                    kind="call",
                    description=f"function call '{_callee_name(node)}' after low-level call",
                    source_location=_source_loc(node, source_file, line_map=line_map),
                )
            )
        if len(effects) >= 3:
            break
    return effects


def _call_kind_from_function_call(node: dict[str, Any]) -> CallKind | None:
    expr = node.get("expression")
    if not isinstance(expr, dict):
        return None
    return _call_kind_from_expression(expr)


def _call_kind_from_expression(expr: dict[str, Any]) -> CallKind | None:
    node_type = expr.get("nodeType")
    if node_type == "FunctionCallOptions":
        inner = expr.get("expression")
        return _call_kind_from_expression(inner) if isinstance(inner, dict) else None
    if node_type == "MemberAccess":
        member = expr.get("memberName")
        if isinstance(member, str) and member in _LOW_LEVEL_MEMBERS:
            return _LOW_LEVEL_MEMBERS[member]
        if isinstance(member, str) and member in _LEGACY_CALL_OPTIONS:
            inner = expr.get("expression")
            return _call_kind_from_expression(inner) if isinstance(inner, dict) else None
    if node_type == "FunctionCall":
        inner = expr.get("expression")
        return _call_kind_from_expression(inner) if isinstance(inner, dict) else None
    return None


def _callee_name(node: dict[str, Any]) -> str:
    expr = node.get("expression", {})
    if not isinstance(expr, dict):
        return ""
    if expr.get("nodeType") == "FunctionCallOptions":
        expr = expr.get("expression", {})
        if not isinstance(expr, dict):
            return ""
    return str(expr.get("name") or expr.get("memberName") or "")


def _node_references_identifier(node: Any, name: str) -> bool:
    if not name or not isinstance(node, dict):
        return False
    return any(
        child.get("nodeType") == "Identifier" and child.get("name") == name
        for child in _walk_nodes(node)
    )


def _contains_node(container: Any, needle: dict[str, Any]) -> bool:
    if not isinstance(container, dict):
        return False
    needle_id = id(needle)
    return any(id(child) == needle_id for child in _walk_nodes(container))


def _ancestors(node: dict[str, Any], parent_map: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    current = node
    while id(current) in parent_map:
        parent = parent_map[id(current)]
        out.append(parent)
        current = parent
    return out


def _build_parent_map(root: dict[str, Any]) -> dict[int, dict[str, Any]]:
    parent_map: dict[int, dict[str, Any]] = {}

    def visit(node: Any, parent: dict[str, Any] | None = None) -> None:
        if isinstance(node, dict):
            if parent is not None:
                parent_map[id(node)] = parent
            for value in node.values():
                visit(value, node)
        elif isinstance(node, list):
            for item in node:
                visit(item, parent)

    visit(root)
    return parent_map


def _walk_nodes(root: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("nodeType"), str):
                out.append(node)
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(root)
    return out


def _function_display_name(fn_node: dict[str, Any]) -> str:
    name = fn_node.get("name")
    if isinstance(name, str) and name:
        return name
    kind = fn_node.get("kind")
    return kind if isinstance(kind, str) else ""


def _src_start(src: Any) -> int | None:
    span = _src_span(src)
    return span[0] if span is not None else None


def _src_span(src: Any) -> tuple[int, int] | None:
    if not isinstance(src, str):
        return None
    parts = src.split(":")
    if len(parts) < 2:
        return None
    try:
        return int(parts[0]), int(parts[1])
    except ValueError:
        return None


def _source_loc(
    node: dict[str, Any], source_file: str, line_map: list[int] | None = None
) -> SourceLocation | None:
    span = _src_span(node.get("src"))
    if span is None:
        return None
    offset, length = span
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


def _source_snippet(source_text: str, src: Any) -> str:
    span = _src_span(src)
    if not source_text or span is None:
        return ""
    offset, length = span
    source_bytes = source_text.encode("utf-8")
    return source_bytes[offset : offset + length].decode("utf-8", errors="replace").strip()
