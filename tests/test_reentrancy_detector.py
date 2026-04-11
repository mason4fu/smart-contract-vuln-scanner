"""Integration tests for the reentrancy detector."""

from __future__ import annotations

import pytest

from scanner.ast.analysis import analyze_source
from scanner.bytecode.loader import extract_bytecode
from scanner.detectors import DETECTOR_REGISTRY, get_all_detectors
from scanner.detectors.reentrancy import ReentrancyDetector, detect_reentrancy


def test_detector_registered():
    """ReentrancyDetector must be importable and registered."""
    import scanner.detectors.reentrancy  # noqa: F401 - triggers registration

    assert "reentrancy" in DETECTOR_REGISTRY


def test_detector_is_instantiable():
    detector = ReentrancyDetector()
    assert detector.name == "reentrancy"


def test_detect_from_compiler_output_matches_standalone(compiled_reentrancy_patterns):
    detector = ReentrancyDetector()
    via_class = detector.detect_from_compiler_output(compiled_reentrancy_patterns)
    via_fn = detect_reentrancy(compiled_reentrancy_patterns)
    assert len(via_class) == len(via_fn)
    keys = {(f.contract, f.function, f.title, f.swc_id) for f in via_class}
    assert keys == {(f.contract, f.function, f.title, f.swc_id) for f in via_fn}


def test_vulnerable_contract_source_findings(compiled_reentrancy_patterns):
    findings = detect_reentrancy(compiled_reentrancy_patterns)
    vuln = [
        f
        for f in findings
        if f.contract == "VulnerableReentrancy"
        and "external call before state" in f.title.lower()
    ]
    assert len(vuln) >= 1
    assert vuln[0].function == "withdraw"
    assert vuln[0].confidence in {"high", "medium"}
    assert vuln[0].swc_id == "SWC-107"


def test_safe_contract_no_findings_in_shared_file(compiled_reentrancy_patterns):
    findings = detect_reentrancy(compiled_reentrancy_patterns)
    safe_hits = [f for f in findings if f.contract == "SafeReentrancyCEI"]
    assert safe_hits == []


def test_safe_only_file_no_findings(compiled_reentrancy_safe_only):
    findings = detect_reentrancy(compiled_reentrancy_safe_only)
    assert findings == []


def test_detector_class_on_safe_only(compiled_reentrancy_safe_only):
    detector = ReentrancyDetector()
    assert detector.detect_from_compiler_output(compiled_reentrancy_safe_only) == []


def test_get_all_detectors_includes_reentrancy():
    import scanner.detectors.access_control  # noqa: F401
    import scanner.detectors.reentrancy  # noqa: F401

    names = [d.name for d in get_all_detectors()]
    assert "reentrancy" in names
    assert "access-control" in names


def test_detect_from_source_returns_empty(compiled_reentrancy_patterns):
    """Reentrancy uses full compiler JSON, not ContractInfo IR."""
    detector = ReentrancyDetector()
    contracts = analyze_source(compiled_reentrancy_patterns)
    assert detector.detect_from_source(contracts) == []


def test_detect_from_bytecode_returns_empty(compiled_reentrancy_patterns):
    """Bytecode corroboration is internal to detect_reentrancy, not a separate hook."""
    detector = ReentrancyDetector()
    bytecodes = extract_bytecode(compiled_reentrancy_patterns)
    assert detector.detect_from_bytecode(bytecodes) == []


def test_example_contract_under_contracts_src():
    """Regression: bundled example under contracts/ stays aligned with detector."""
    from scanner.compiler.solc import compile_source
    from scanner.utils.paths import project_root

    example = project_root() / "contracts" / "src" / "ReentrancyExample.sol"
    if not example.is_file():
        pytest.skip("ReentrancyExample.sol not present")

    out_example = compile_source(example)
    findings_ex = detect_reentrancy(out_example)
    vuln_ex = [f for f in findings_ex if f.contract == "VulnerableReentrancy"]
    assert len(vuln_ex) >= 1

    safe_ex = [f for f in findings_ex if f.contract == "SafeReentrancyCEI"]
    assert safe_ex == []
