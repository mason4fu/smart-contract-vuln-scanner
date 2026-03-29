"""Tests for AST-level access control analysis."""

from __future__ import annotations

from scanner.ast.analysis import analyze_source
from scanner.ast.loader import extract_ast, walk_ast_filtered


def test_walk_ast_filtered_finds_contract_definitions(compiled_safe_contract):
    asts = extract_ast(compiled_safe_contract)
    for ast_root in asts.values():
        contracts = list(walk_ast_filtered(ast_root, {"ContractDefinition"}))
        assert len(contracts) >= 1
        assert all(c["nodeType"] == "ContractDefinition" for c in contracts)


def test_analyze_source_tx_origin_vuln(compiled_tx_origin_vuln):
    contracts = analyze_source(compiled_tx_origin_vuln)
    assert len(contracts) >= 1
    contract = contracts[0]
    assert contract.name == "TxOriginVuln"

    # Should have a withdraw function
    func_names = [f.name for f in contract.functions]
    assert "withdraw" in func_names

    withdraw = next(f for f in contract.functions if f.name == "withdraw")
    assert withdraw.visibility in ("external", "public")
    assert withdraw.uses_tx_origin


def test_analyze_source_safe_contract(compiled_safe_contract):
    contracts = analyze_source(compiled_safe_contract)
    contract = next(c for c in contracts if c.name == "SafeContract")

    # Should have onlyOwner modifier
    mod_names = [m.name for m in contract.modifiers]
    assert "onlyOwner" in mod_names

    only_owner = next(m for m in contract.modifiers if m.name == "onlyOwner")
    assert only_owner.has_auth_check

    # transferOwnership should have auth guard
    transfer = next(f for f in contract.functions if f.name == "transferOwnership")
    assert transfer.has_auth_guard


def test_analyze_source_missing_auth_vuln(compiled_missing_auth_vuln):
    contracts = analyze_source(compiled_missing_auth_vuln)
    contract = next(c for c in contracts if c.name == "MissingAuthVuln")

    change_owner = next(f for f in contract.functions if f.name == "changeOwner")
    assert change_owner.visibility in ("public", "external")
    assert not change_owner.has_auth_guard
    # Should detect sensitive action (owner assignment)
    assert len(change_owner.sensitive_actions) >= 1


def test_analyze_source_inline_auth_check(compiled_inline_auth_check):
    contracts = analyze_source(compiled_inline_auth_check)
    contract = next(c for c in contracts if c.name == "InlineAuthCheck")

    change_owner = next(f for f in contract.functions if f.name == "changeOwner")
    # Inline require(msg.sender == owner) should count as auth guard
    assert change_owner.has_auth_guard


def test_analyze_source_view_functions(compiled_view_functions):
    contracts = analyze_source(compiled_view_functions)
    contract = next(c for c in contracts if c.name == "ViewFunctions")

    for func in contract.functions:
        if func.name in ("getValue", "double", "getBalance"):
            assert func.state_mutability in ("view", "pure")


def test_state_variables_extracted(compiled_safe_contract):
    contracts = analyze_source(compiled_safe_contract)
    contract = next(c for c in contracts if c.name == "SafeContract")
    assert "owner" in contract.state_variables


def test_owner_pattern_detected(compiled_safe_contract):
    contracts = analyze_source(compiled_safe_contract)
    contract = next(c for c in contracts if c.name == "SafeContract")
    assert contract.has_owner_pattern


def test_line_numbers_not_byte_offsets(compiled_tx_origin_vuln):
    """Verify that line_start contains actual line numbers, not byte offsets."""
    contracts = analyze_source(compiled_tx_origin_vuln)
    assert contracts, "Should find at least one contract"
    contract = contracts[0]
    # Find the withdraw function (or any function with a source location)
    funcs_with_loc = [f for f in contract.functions if f.source_location and f.source_location.line_start > 0]
    assert funcs_with_loc, "Should find functions with source locations"
    for func in funcs_with_loc:
        # Line numbers should be small (< 100 for our small test fixtures)
        # not byte offsets (which would be hundreds or thousands)
        assert func.source_location.line_start < 100, (
            f"Function {func.name} has line_start={func.source_location.line_start}, "
            f"expected a real line number < 100, not a byte offset"
        )
