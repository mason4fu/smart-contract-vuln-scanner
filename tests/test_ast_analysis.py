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


def test_analyze_source_inverted_balance_check(compiled_balance_check_inverted):
    contracts = analyze_source(compiled_balance_check_inverted)
    contract = next(c for c in contracts if c.name == "BalanceCheckInverted")

    withdraw = next(f for f in contract.functions if f.name == "withdraw")
    assert withdraw.auth_checks, "Expected a detected inline check"

    auth_check = withdraw.auth_checks[0]
    assert auth_check.comparison_operator == ">="
    assert not auth_check.comparison_left_uses_sender_scoped_state
    assert auth_check.comparison_right_uses_sender_scoped_state


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
    funcs_with_loc = [
        f for f in contract.functions if f.source_location and f.source_location.line_start > 0
    ]
    assert funcs_with_loc, "Should find functions with source locations"
    for func in funcs_with_loc:
        # Line numbers should be small (< 100 for our small test fixtures)
        # not byte offsets (which would be hundreds or thousands)
        assert func.source_location.line_start < 100, (
            f"Function {func.name} has line_start={func.source_location.line_start}, "
            f"expected a real line number < 100, not a byte offset"
        )


def test_inherited_modifier_resolved(compiled_inherited_auth):
    """Derived contract should inherit onlyOwner from base Ownable."""
    contracts = analyze_source(compiled_inherited_auth)
    derived = next((c for c in contracts if c.name == "InheritedAuth"), None)
    assert derived is not None
    # The derived contract should have at least the inherited modifier available
    mod_names = {m.name for m in derived.modifiers}
    assert "onlyOwner" in mod_names, f"Expected onlyOwner inherited, got {mod_names}"
    # setValue should be guarded
    set_val = next((f for f in derived.functions if f.name == "setValue"), None)
    assert set_val is not None
    assert set_val.has_auth_guard, "setValue should be guarded via inherited onlyOwner"


def test_known_modifier_recognized(compiled_oz_ownable):
    """onlyOwner in _KNOWN_AUTH_MODIFIERS should be recognized as auth guard."""
    contracts = analyze_source(compiled_oz_ownable)
    assert contracts
    contract = contracts[0]
    sensitive = next((f for f in contract.functions if f.name == "sensitiveOperation"), None)
    assert sensitive is not None
    assert sensitive.has_auth_guard, "sensitiveOperation with onlyOwner should be guarded"


def test_constructor_candidate_tagged(compiled_wrong_constructor_name):
    contracts = analyze_source(compiled_wrong_constructor_name)
    contract = next(c for c in contracts if c.name == "WrongConstructorName")
    ctor_like = next(f for f in contract.functions if f.name == "Constructor")
    assert not ctor_like.is_constructor
    assert ctor_like.is_constructor_candidate


def test_config_surface_marks_treasury_as_config_set(compiled_config_surface):
    contracts = analyze_source(compiled_config_surface)
    contract = next(c for c in contracts if c.name == "ConfigSurface")

    set_treasury = next(f for f in contract.functions if f.name == "setTreasury")
    set_counter = next(f for f in contract.functions if f.name == "setCounter")
    set_treasury_safe = next(f for f in contract.functions if f.name == "setTreasurySafe")

    assert any(action.kind == "config_set" for action in set_treasury.sensitive_actions)
    assert not any(action.kind == "config_set" for action in set_counter.sensitive_actions)
    assert any(action.kind == "config_set" for action in set_treasury_safe.sensitive_actions)
