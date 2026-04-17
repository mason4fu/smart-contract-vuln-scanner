"""Integration tests for arithmetic (SWC-101) detector."""

from __future__ import annotations

from typer.testing import CliRunner

from scanner.cli import app
from scanner.bytecode.loader import ContractBytecode
from scanner.detectors import DETECTOR_REGISTRY, get_all_detectors
from scanner.detectors.arithmetic import (
    ArithmeticDetector,
    detect_arithmetic,
    detect_arithmetic_bytecode,
)

runner = CliRunner()


def _finding_functions(findings):
    return {f.function for f in findings}


def test_detector_registered():
    import scanner.detectors.arithmetic  # noqa: F401

    assert "arithmetic" in DETECTOR_REGISTRY


def test_detector_instantiable():
    det = ArithmeticDetector()
    assert det.name == "arithmetic"


def test_detects_pre_08_unguarded_arithmetic(compiled_arithmetic_patterns):
    findings = detect_arithmetic(compiled_arithmetic_patterns)
    funcs = _finding_functions(findings)
    assert "unguardedAdd" in funcs
    assert "payout" in funcs
    assert all(f.swc_id == "SWC-101" for f in findings)


def test_suppresses_guarded_and_safemath_patterns(compiled_arithmetic_patterns):
    findings = detect_arithmetic(compiled_arithmetic_patterns)
    funcs = _finding_functions(findings)
    assert "guardedAdd" not in funcs
    assert "safeMathAdd" not in funcs


def test_suppresses_default_checked_arithmetic_in_solidity_08(compiled_arithmetic_safe_08):
    findings = detect_arithmetic(compiled_arithmetic_safe_08)
    assert findings == []


def test_reports_unchecked_block_in_solidity_08(compiled_arithmetic_unchecked_08):
    findings = detect_arithmetic(compiled_arithmetic_unchecked_08)
    funcs = _finding_functions(findings)
    assert "incrementUnchecked" in funcs


def test_cli_scan_detector_arithmetic_json(tmp_path):
    result = runner.invoke(
        app,
        [
            "scan",
            "tests/fixtures/ArithmeticPatterns.sol",
            "--detector",
            "arithmetic",
            "--format",
            "json",
            "--output",
            str(tmp_path),
            "--solc-version",
            "0.4.25",
        ],
    )
    assert result.exit_code == 0
    data = (tmp_path / "ArithmeticPatterns.json").read_text(encoding="utf-8")
    assert "SWC-101" in data


def test_get_all_detectors_includes_arithmetic():
    import scanner.detectors.arithmetic  # noqa: F401

    names = [d.name for d in get_all_detectors()]
    assert "arithmetic" in names


def test_bytecode_hint_reports_add_before_sstore():
    bc = ContractBytecode(
        contract_name="RawArithmetic",
        creation_bytecode="",
        deployed_bytecode="6001600201600055",
    )
    findings = detect_arithmetic_bytecode(bc)
    assert len(findings) == 1
    assert findings[0].swc_id == "SWC-101"
    assert findings[0].confidence == "low"
