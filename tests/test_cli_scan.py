"""CLI integration tests for the scan command."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from scanner.cli import app

runner = CliRunner()
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_cli_scan_sol_file_text():
    result = runner.invoke(
        app, ["scan", str(FIXTURES_DIR / "TxOriginVuln.sol"), "--format", "text"]
    )
    assert result.exit_code == 0
    output = result.stdout
    # Should find something
    assert "HIGH" in output or "tx.origin" in output.lower() or "Findings" in output


def test_cli_scan_sol_file_json(tmp_path):
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "TxOriginVuln.sol"),
            "--format",
            "json",
            "--output",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    # Report should be written
    report_files = list(tmp_path.glob("*.json"))
    assert len(report_files) >= 1
    import json

    data = json.loads(report_files[0].read_text())
    assert isinstance(data, list)


def test_cli_scan_sol_file_sarif(tmp_path):
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "TxOriginVuln.sol"),
            "--format",
            "sarif",
            "--output",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    report_files = list(tmp_path.glob("*.sarif"))
    assert len(report_files) == 1
    import json

    data = json.loads(report_files[0].read_text())
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    assert data["runs"][0]["results"]


def test_cli_scan_safe_contract(tmp_path):
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "SafeContract.sol"),
            "--format",
            "text",
            "--output",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0


def test_cli_scan_directory(tmp_path):
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES_DIR), "--format", "text", "--output", str(tmp_path)],
    )
    assert result.exit_code == 0
    assert "Project Summary" in result.stdout
    summary_files = list(tmp_path.glob("*.project-summary.json"))
    assert len(summary_files) == 1
    import json

    summary = json.loads(summary_files[0].read_text())
    assert summary["inputs"]["solidity_files"] >= 1
    assert "top_files" in summary
    assert "top_contracts" in summary


def test_cli_scan_missing_target():
    result = runner.invoke(app, ["scan", "nonexistent.sol"])
    assert result.exit_code != 0 or "not found" in result.stdout.lower() or result.exit_code == 1


def test_cli_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "scanner" in result.stdout


def test_cli_scan_strict_access_control_filters_low_confidence(tmp_path):
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "BalanceCheckNotAuth.sol"),
            "--format",
            "text",
            "--output",
            str(tmp_path),
            "--strict-access-control",
        ],
    )
    assert result.exit_code == 0
    assert "No findings" in result.stdout


def test_cli_scan_invalid_min_confidence():
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "TxOriginVuln.sol"),
            "--min-confidence",
            "invalid",
        ],
    )
    assert result.exit_code != 0
    assert "Invalid --min-confidence" in result.stdout


def test_cli_scan_suppresses_bytecode_duplicate_for_source_swc():
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "TxOriginVuln.sol"),
            "--format",
            "text",
        ],
    )
    assert result.exit_code == 0
    out = result.stdout.lower()
    assert "tx.origin used for authorization" in out
    assert "tx.origin used (bytecode)" not in out


def test_cli_scan_detector_reentrancy_finds_vulnerable_contract():
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "ReentrancyPatterns.sol"),
            "--detector",
            "reentrancy",
            "--format",
            "text",
        ],
    )
    assert result.exit_code == 0
    out = result.stdout
    assert "VulnerableReentrancy" in out
    assert "withdraw" in out.lower()


def test_cli_scan_detector_reentrancy_safe_contract_no_findings():
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "ReentrancySafeOnly.sol"),
            "--detector",
            "reentrancy",
            "--format",
            "text",
        ],
    )
    assert result.exit_code == 0
    assert "No findings" in result.stdout


def test_cli_scan_raw_bytecode_reentrancy(tmp_path):
    bytecode_file = tmp_path / "reentrant.bin"
    bytecode_file.write_text("f1600055", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            str(bytecode_file),
            "--detector",
            "reentrancy",
            "--bytecode-only",
            "--format",
            "json",
            "--output",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0
    import json

    data = json.loads((tmp_path / "reentrant.json").read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["swc_id"] == "SWC-107"
    assert "(bytecode)" in data[0]["title"].lower()


def test_cli_scan_unknown_detector_exits_error():
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES_DIR / "ReentrancyPatterns.sol"),
            "--detector",
            "not-a-real-detector",
            "--format",
            "text",
        ],
    )
    assert result.exit_code != 0
    assert "Unknown detector" in result.stdout
