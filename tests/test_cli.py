"""CLI smoke tests: verify the CLI entrypoint works."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from scanner.cli import app
from scanner.utils.paths import project_root

runner = CliRunner()


def test_cli_help():
    """CLI should display help text without errors."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Static analysis tool" in result.output


def test_cli_version():
    """CLI --version flag should print version and exit."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "scanner" in result.output


def test_cli_scan_help():
    """Scan sub-command should have help text."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "vulnerability scan" in result.output.lower() or "target" in result.output.lower()


def test_cli_scan_writes_report(tmp_path: Path):
    """scan should compile a fixture and write a JSON report."""
    fixture = project_root() / "contracts" / "src" / "ReentrancyExample.sol"
    if not fixture.is_file():
        pytest.skip("ReentrancyExample.sol not present")
    result = runner.invoke(
        app,
        ["scan", str(fixture), "--output", str(tmp_path), "--format", "json"],
    )
    assert result.exit_code == 0
    assert (tmp_path / f"{fixture.stem}.json").is_file()
    assert "Report written" in result.stdout
