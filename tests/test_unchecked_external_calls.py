"""Tests for unchecked low-level external call detection."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from scanner.ast.unchecked_calls import analyze_unchecked_external_calls
from scanner.bytecode.unchecked_calls import analyze_unchecked_call_bytecode
from scanner.cli import app
from scanner.compiler.solc import compile_source
from scanner.detectors.unchecked_external_calls import UncheckedExternalCallDetector
from scanner.models.unchecked_calls import CallResultStatus

FIXTURES_DIR = Path(__file__).parent / "fixtures"
runner = CliRunner()


def _finding_functions(findings):
    return {finding.function for finding in findings}


def test_source_extractor_classifies_checked_and_unchecked_calls():
    compiler_output = compile_source(FIXTURES_DIR / "UncheckedExternalCalls.sol")
    sites = analyze_unchecked_external_calls(compiler_output)

    by_function = {site.function: site.result_usage.status for site in sites}

    assert by_function["uncheckedCall"] == CallResultStatus.UNCHECKED
    assert by_function["uncheckedDelegate"] == CallResultStatus.UNCHECKED
    assert by_function["uncheckedStatic"] == CallResultStatus.UNCHECKED
    assert by_function["uncheckedSend"] == CallResultStatus.UNCHECKED
    assert by_function["tupleAssignedNeverChecked"] == CallResultStatus.UNCHECKED
    assert by_function["onlyReturndataCaptured"] == CallResultStatus.PROBABLY_UNCHECKED
    assert by_function["successOnlyLogged"] == CallResultStatus.PROBABLY_UNCHECKED
    assert by_function["uncheckedIfObserver"] == CallResultStatus.PROBABLY_UNCHECKED
    assert by_function["uncheckedIfOrObserver"] == CallResultStatus.PROBABLY_UNCHECKED
    assert by_function["aliasUncheckedLogged"] == CallResultStatus.PROBABLY_UNCHECKED
    assert by_function["nestedBranchFailureContinues"] == CallResultStatus.PROBABLY_UNCHECKED
    assert by_function["checkedRequire"] == CallResultStatus.CHECKED
    assert by_function["checkedAssert"] == CallResultStatus.CHECKED
    assert by_function["checkedIfRevert"] == CallResultStatus.CHECKED
    assert by_function["aliasChecked"] == CallResultStatus.CHECKED
    assert by_function["invertedAliasChecked"] == CallResultStatus.CHECKED
    assert by_function["checkedDirectIfReturn"] == CallResultStatus.CHECKED
    assert by_function["checkedDirectIfElseRevert"] == CallResultStatus.CHECKED
    assert by_function["nestedBranchFailureTerminates"] == CallResultStatus.CHECKED
    assert by_function["checkedHelper"] == CallResultStatus.CHECKED
    assert by_function["returnsSuccess"] == CallResultStatus.DELEGATED
    assert "transferOutOfScope" not in by_function


def test_detector_reports_only_unchecked_source_calls():
    compiler_output = compile_source(FIXTURES_DIR / "UncheckedExternalCalls.sol")
    findings = UncheckedExternalCallDetector().detect_from_compiler_output(compiler_output)
    functions = _finding_functions(findings)

    assert "uncheckedCall" in functions
    assert "uncheckedDelegate" in functions
    assert "uncheckedStatic" in functions
    assert "uncheckedSend" in functions
    assert "tupleAssignedNeverChecked" in functions
    assert "onlyReturndataCaptured" in functions
    assert "successOnlyLogged" in functions
    assert "uncheckedIfObserver" in functions
    assert "uncheckedIfOrObserver" in functions
    assert "aliasUncheckedLogged" in functions
    assert "nestedBranchFailureContinues" in functions
    assert "mixed" in functions
    assert "checkedRequire" not in functions
    assert "checkedAssert" not in functions
    assert "checkedIfRevert" not in functions
    assert "aliasChecked" not in functions
    assert "invertedAliasChecked" not in functions
    assert "checkedDirectIfReturn" not in functions
    assert "checkedDirectIfElseRevert" not in functions
    assert "nestedBranchFailureTerminates" not in functions
    assert "checkedHelper" not in functions
    assert "returnsSuccess" not in functions
    assert "transferOutOfScope" not in functions
    assert all(finding.swc_id == "SWC-104" for finding in findings)


def test_legacy_low_level_call_syntax_is_detected():
    compiler_output = compile_source(
        FIXTURES_DIR / "LegacyUncheckedExternalCalls.sol", version="0.4.25"
    )
    findings = UncheckedExternalCallDetector().detect_from_compiler_output(compiler_output)
    functions = _finding_functions(findings)

    assert "legacySend" in functions
    assert "legacyCallValue" in functions
    assert "legacyChecked" not in functions


def test_bytecode_call_pop_is_unchecked():
    sites = analyze_unchecked_call_bytecode("f150", contract_name="Raw")

    assert len(sites) == 1
    assert sites[0].result_usage.status == CallResultStatus.UNCHECKED


def test_bytecode_call_jumpi_is_checked():
    sites = analyze_unchecked_call_bytecode("f11560085760006000fd", contract_name="Raw")

    assert len(sites) == 1
    assert sites[0].result_usage.status == CallResultStatus.CHECKED


def test_bytecode_call_before_sstore_is_probably_unchecked():
    sites = analyze_unchecked_call_bytecode("f1600055", contract_name="Raw")

    assert len(sites) == 1
    assert sites[0].result_usage.status == CallResultStatus.PROBABLY_UNCHECKED


def test_cli_scan_unchecked_external_calls_json(tmp_path):
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "UncheckedExternalCalls.sol"),
            "--detector",
            "unchecked-external-calls",
            "--format",
            "json",
            "--output",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0
    report_file = tmp_path / "UncheckedExternalCalls.json"
    data = json.loads(report_file.read_text(encoding="utf-8"))
    assert any(item["swc_id"] == "SWC-104" for item in data)
    assert any(item["function"] == "uncheckedCall" for item in data)


def test_cli_scan_raw_bytecode(tmp_path):
    bytecode_file = tmp_path / "raw.bin"
    bytecode_file.write_text("f150", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            str(bytecode_file),
            "--detector",
            "unchecked-external-calls",
            "--bytecode-only",
            "--format",
            "json",
            "--output",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0
    data = json.loads((tmp_path / "raw.json").read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["title"] == "Unchecked external call result (bytecode)"
