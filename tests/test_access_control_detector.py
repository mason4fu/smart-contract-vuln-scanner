"""Integration tests for the access control detector."""

from __future__ import annotations

from scanner.ast.analysis import analyze_source
from scanner.bytecode.loader import extract_bytecode
from scanner.detectors import DETECTOR_REGISTRY, get_all_detectors
from scanner.detectors.access_control import AccessControlDetector
from scanner.models.findings import Severity


def test_detector_registered():
    """AccessControlDetector must be importable and registered."""
    import scanner.detectors.access_control  # noqa: F401 - triggers registration

    assert "access-control" in DETECTOR_REGISTRY


def test_detector_is_instantiable():
    detector = AccessControlDetector()
    assert detector.name == "access-control"


# ---------------------------------------------------------------------------
# Source-level tests
# ---------------------------------------------------------------------------


def test_tx_origin_vuln_source_findings(compiled_tx_origin_vuln):
    contracts = analyze_source(compiled_tx_origin_vuln)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)

    tx_origin_findings = [f for f in findings if "tx.origin" in f.title.lower()]
    assert len(tx_origin_findings) >= 1

    f = tx_origin_findings[0]
    assert f.severity == Severity.HIGH
    assert f.contract == "TxOriginVuln"
    assert "withdraw" in f.function or "tx.origin" in f.description


def test_tx_origin_deduplicated_per_function(compiled_tx_origin_twice):
    contracts = analyze_source(compiled_tx_origin_twice)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    tx_origin_findings = [f for f in findings if "tx.origin" in f.title.lower()]
    assert len(tx_origin_findings) == 1


def test_missing_auth_vuln_source_findings(compiled_missing_auth_vuln):
    contracts = analyze_source(compiled_missing_auth_vuln)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)

    auth_findings = [
        f
        for f in findings
        if "missing" in f.title.lower()
        or "authorization" in f.title.lower()
        or "admin-surface" in f.title.lower()
    ]
    assert len(auth_findings) >= 1

    f = auth_findings[0]
    assert f.severity == Severity.HIGH
    assert f.contract == "MissingAuthVuln"


def test_safe_contract_no_source_findings(compiled_safe_contract):
    contracts = analyze_source(compiled_safe_contract)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    assert findings == [], f"Expected no findings for SafeContract, got: {findings}"


def test_inline_auth_check_no_findings(compiled_inline_auth_check):
    contracts = analyze_source(compiled_inline_auth_check)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    auth_findings = [f for f in findings if "missing" in f.title.lower()]
    assert len(auth_findings) == 0, f"InlineAuthCheck should not flag missing auth: {findings}"


def test_view_functions_no_findings(compiled_view_functions):
    contracts = analyze_source(compiled_view_functions)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    assert findings == [], f"View functions should not produce findings: {findings}"


def test_near_miss_no_tx_origin_findings(compiled_near_miss):
    contracts = analyze_source(compiled_near_miss)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    tx_origin_findings = [f for f in findings if "tx.origin" in f.title.lower()]
    assert not tx_origin_findings, (
        f"NearMiss should not flag tx.origin in a view function: {findings}"
    )


def test_sensitive_actions_partial_findings(compiled_sensitive_actions):
    contracts = analyze_source(compiled_sensitive_actions)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)

    # pause() is guarded - should not be flagged
    pause_findings = [f for f in findings if f.function == "pause"]
    assert len(pause_findings) == 0

    # destroy() is unguarded - should be flagged
    # setOwner() is unguarded - should be flagged
    unguarded = [f for f in findings if "missing" in f.title.lower()]
    assert len(unguarded) >= 1


def test_balance_check_not_auth_guard(compiled_balance_check_not_auth):
    contracts = analyze_source(compiled_balance_check_not_auth)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    missing_auth = [f for f in findings if "missing" in f.title.lower()]
    assert not missing_auth, (
        f"Sender-scoped user withdrawal should not be treated as missing auth: {findings}"
    )


def test_balance_check_inverted_detected(compiled_balance_check_inverted):
    contracts = analyze_source(compiled_balance_check_inverted)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)

    missing_auth = [f for f in findings if "missing" in f.title.lower()]
    assert missing_auth, f"Expected inverted balance guard to be reported: {findings}"
    assert missing_auth[0].severity == Severity.HIGH


def test_creator_pattern_detected(compiled_creator_pattern):
    contracts = analyze_source(compiled_creator_pattern)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    creator_findings = [
        f
        for f in findings
        if "owner" in f.title.lower()
        or "authorization" in f.title.lower()
        or "admin-surface" in f.title.lower()
    ]
    assert creator_findings, f"Expected creator-pattern finding, got: {[f.title for f in findings]}"


def test_interface_no_findings(compiled_interface_contract):
    contracts = analyze_source(compiled_interface_contract)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    assert findings == [], f"Interfaces should not produce findings: {findings}"


# ---------------------------------------------------------------------------
# Bytecode-level tests
# ---------------------------------------------------------------------------


def test_tx_origin_vuln_bytecode_findings(compiled_tx_origin_vuln):
    bytecodes = extract_bytecode(compiled_tx_origin_vuln)
    detector = AccessControlDetector()
    findings = detector.detect_from_bytecode(bytecodes)

    assert len(findings) >= 1
    assert findings[0].severity == Severity.MEDIUM
    assert "ORIGIN" in findings[0].title or "tx.origin" in findings[0].title.lower()


def test_safe_contract_no_bytecode_findings(compiled_safe_contract):
    bytecodes = extract_bytecode(compiled_safe_contract)
    detector = AccessControlDetector()
    findings = detector.detect_from_bytecode(bytecodes)
    assert findings == [], f"SafeContract bytecode should produce no ORIGIN findings: {findings}"


def test_get_all_detectors_includes_access_control():
    import scanner.detectors.access_control  # noqa: F401

    detectors = get_all_detectors()
    names = [d.name for d in detectors]
    assert "access-control" in names


def test_inherited_auth_no_findings(compiled_inherited_auth):
    """Contract with inherited onlyOwner should have no missing-auth findings."""
    from scanner.ast.analysis import analyze_source

    contracts = analyze_source(compiled_inherited_auth)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    missing_auth = [
        f for f in findings if "missing" in f.title.lower() or "unguarded" in f.title.lower()
    ]
    assert not missing_auth, (
        f"Unexpected findings for inherited auth: {[f.title for f in missing_auth]}"
    )


def test_oz_ownable_no_findings(compiled_oz_ownable):
    """Contract using well-known onlyOwner modifier should have no missing-auth findings."""
    from scanner.ast.analysis import analyze_source

    contracts = analyze_source(compiled_oz_ownable)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    missing_auth = [
        f for f in findings if "missing" in f.title.lower() or "unguarded" in f.title.lower()
    ]
    assert not missing_auth, (
        f"Unexpected findings for OZ-style contract: {[f.title for f in missing_auth]}"
    )


def test_uninitialized_owner_finding(compiled_uninitialized_owner):
    """UninitializedOwner.sol should produce a MEDIUM finding."""
    from scanner.ast.analysis import analyze_source

    contracts = analyze_source(compiled_uninitialized_owner)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    uninit = [
        f
        for f in findings
        if "uninitializ" in f.title.lower() or "uninitializ" in f.description.lower()
    ]
    assert uninit, f"Expected uninitialized owner finding, got: {[f.title for f in findings]}"
    assert uninit[0].severity == Severity.MEDIUM


def test_dangerous_renounce_finding(compiled_dangerous_renounce):
    """DangerousRenounce.sol should produce a LOW finding."""
    from scanner.ast.analysis import analyze_source

    contracts = analyze_source(compiled_dangerous_renounce)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    renounce = [
        f for f in findings if "renounce" in f.title.lower() or "renounce" in f.description.lower()
    ]
    assert renounce, f"Expected renounce finding, got: {[f.title for f in findings]}"
    assert renounce[0].severity == Severity.LOW


def test_unguarded_role_grant_finding(compiled_unguarded_role_grant):
    """UnguardedRoleGrant.sol should produce a HIGH finding."""
    from scanner.ast.analysis import analyze_source

    contracts = analyze_source(compiled_unguarded_role_grant)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    role_findings = [f for f in findings if "unguarded role grant" in f.title.lower()]
    assert role_findings, f"Expected role grant finding, got: {[f.title for f in findings]}"
    assert role_findings[0].severity == Severity.HIGH


def test_role_grant_preferred_over_generic_missing_auth(compiled_role_grant_overlap):
    contracts = analyze_source(compiled_role_grant_overlap)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)

    role_findings = [f for f in findings if "unguarded role grant" in f.title.lower()]
    missing_auth = [f for f in findings if "missing authorization" in f.title.lower()]

    assert len(role_findings) == 1
    assert len(missing_auth) == 0


def test_generic_indexed_write_not_flagged_as_access_control(compiled_generic_indexed_write):
    contracts = analyze_source(compiled_generic_indexed_write)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)

    set_raw = [f for f in findings if f.function == "setRaw"]
    set_owned = [f for f in findings if f.function == "setOwned"]

    assert not set_raw, "setRaw should not be flagged as access-control by itself"
    assert not set_owned, (
        "setOwned should not be flagged: indexed writes keyed by msg.sender are ignored"
    )


def test_config_surface_flags_unguarded_treasury_update(compiled_config_surface):
    contracts = analyze_source(compiled_config_surface)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)

    set_treasury = [f for f in findings if f.function == "setTreasury"]
    set_counter = [f for f in findings if f.function == "setCounter"]
    set_treasury_safe = [f for f in findings if f.function == "setTreasurySafe"]

    assert set_treasury, "setTreasury should be treated as a privileged config write"
    assert any("missing authorization" in f.title.lower() for f in set_treasury)
    assert set_treasury[0].severity == Severity.HIGH
    assert not set_counter, "Generic counter setters should not be promoted to access-control"
    assert not set_treasury_safe, "Owner-gated treasury updates should not be flagged"


def test_nested_helper_auth_is_detected(compiled_nested_auth_check):
    contracts = analyze_source(compiled_nested_auth_check)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)

    nested = next(c for c in contracts if c.name == "NestedAuthCheck")
    execute = next(f for f in nested.functions if f.name == "execute")
    assert execute.has_auth_guard, "Bounded helper-chain auth should guard execute()"

    missing_auth = [f for f in findings if "missing authorization" in f.title.lower()]
    assert not missing_auth, f"Nested helper auth should suppress missing-auth finding: {findings}"


def test_modifier_helper_auth_is_detected(compiled_modifier_helper_auth):
    contracts = analyze_source(compiled_modifier_helper_auth)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)

    contract = next(c for c in contracts if c.name == "ModifierHelperAuth")
    set_owner = next(f for f in contract.functions if f.name == "setOwner")
    assert set_owner.has_auth_guard, "Modifier helper auth should guard setOwner()"

    missing_auth = [f for f in findings if "missing authorization" in f.title.lower()]
    assert not missing_auth, (
        f"Modifier-helper auth should suppress missing-auth finding: {findings}"
    )


def test_wrong_constructor_surface_finding(compiled_wrong_constructor_name):
    contracts = analyze_source(compiled_wrong_constructor_name)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)

    wrong_constructor = [f for f in findings if "constructor-like" in f.title.lower()]
    assert wrong_constructor, (
        f"Expected wrong-constructor finding, got: {[f.title for f in findings]}"
    )
    assert wrong_constructor[0].swc_id == "SWC-118"


def test_safe_contract_no_uninitialized_owner(compiled_safe_contract):
    """SafeContract should not trigger uninitialized owner (it sets owner in constructor)."""
    from scanner.ast.analysis import analyze_source

    contracts = analyze_source(compiled_safe_contract)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    uninit = [f for f in findings if "uninitializ" in f.title.lower()]
    assert not uninit, "SafeContract should not have uninitialized owner finding"


def test_balance_check_missing_auth_low_confidence(compiled_balance_check_not_auth):
    contracts = analyze_source(compiled_balance_check_not_auth)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    missing_auth = [f for f in findings if "missing authorization" in f.title.lower()]
    assert not missing_auth, "Sender-scoped transfer flow should not produce missing-auth findings"


def test_bytecode_tx_origin_is_low_confidence(compiled_tx_origin_vuln):
    bytecodes = extract_bytecode(compiled_tx_origin_vuln)
    detector = AccessControlDetector()
    findings = detector.detect_from_bytecode(bytecodes)
    tx_origin = [f for f in findings if "bytecode" in f.title.lower()]
    assert tx_origin, "Expected bytecode tx.origin finding"
    assert tx_origin[0].confidence == "low"
