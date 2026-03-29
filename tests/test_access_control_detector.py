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


def test_missing_auth_vuln_source_findings(compiled_missing_auth_vuln):
    contracts = analyze_source(compiled_missing_auth_vuln)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)

    auth_findings = [
        f for f in findings if "missing" in f.title.lower() or "authorization" in f.title.lower()
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


# ---------------------------------------------------------------------------
# Bytecode-level tests
# ---------------------------------------------------------------------------


def test_tx_origin_vuln_bytecode_findings(compiled_tx_origin_vuln):
    bytecodes = extract_bytecode(compiled_tx_origin_vuln)
    detector = AccessControlDetector()
    findings = detector.detect_from_bytecode(bytecodes)

    assert len(findings) >= 1
    assert findings[0].severity == Severity.HIGH
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
    missing_auth = [f for f in findings if "missing" in f.title.lower() or "unguarded" in f.title.lower()]
    assert not missing_auth, f"Unexpected findings for inherited auth: {[f.title for f in missing_auth]}"


def test_oz_ownable_no_findings(compiled_oz_ownable):
    """Contract using well-known onlyOwner modifier should have no missing-auth findings."""
    from scanner.ast.analysis import analyze_source
    contracts = analyze_source(compiled_oz_ownable)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    missing_auth = [f for f in findings if "missing" in f.title.lower() or "unguarded" in f.title.lower()]
    assert not missing_auth, f"Unexpected findings for OZ-style contract: {[f.title for f in missing_auth]}"


def test_uninitialized_owner_finding(compiled_uninitialized_owner):
    """UninitializedOwner.sol should produce a MEDIUM finding."""
    from scanner.ast.analysis import analyze_source
    contracts = analyze_source(compiled_uninitialized_owner)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    uninit = [f for f in findings if "uninitializ" in f.title.lower() or "uninitializ" in f.description.lower()]
    assert uninit, f"Expected uninitialized owner finding, got: {[f.title for f in findings]}"
    assert uninit[0].severity == Severity.MEDIUM


def test_dangerous_renounce_finding(compiled_dangerous_renounce):
    """DangerousRenounce.sol should produce a LOW finding."""
    from scanner.ast.analysis import analyze_source
    contracts = analyze_source(compiled_dangerous_renounce)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    renounce = [f for f in findings if "renounce" in f.title.lower() or "renounce" in f.description.lower()]
    assert renounce, f"Expected renounce finding, got: {[f.title for f in findings]}"
    assert renounce[0].severity == Severity.LOW


def test_unguarded_role_grant_finding(compiled_unguarded_role_grant):
    """UnguardedRoleGrant.sol should produce a HIGH finding."""
    from scanner.ast.analysis import analyze_source
    contracts = analyze_source(compiled_unguarded_role_grant)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    role_findings = [f for f in findings if "role" in f.title.lower() or "grant" in f.title.lower() or "role" in f.description.lower()]
    assert role_findings, f"Expected role grant finding, got: {[f.title for f in findings]}"
    assert role_findings[0].severity == Severity.HIGH


def test_safe_contract_no_uninitialized_owner(compiled_safe_contract):
    """SafeContract should not trigger uninitialized owner (it sets owner in constructor)."""
    from scanner.ast.analysis import analyze_source
    contracts = analyze_source(compiled_safe_contract)
    detector = AccessControlDetector()
    findings = detector.detect_from_source(contracts)
    uninit = [f for f in findings if "uninitializ" in f.title.lower()]
    assert not uninit, f"SafeContract should not have uninitialized owner finding"
