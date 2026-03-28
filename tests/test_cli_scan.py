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


def test_cli_scan_missing_target():
    result = runner.invoke(app, ["scan", "nonexistent.sol"])
    assert result.exit_code != 0 or "not found" in result.stdout.lower() or result.exit_code == 1


def test_cli_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "scanner" in result.stdout
