"""CLI smoke tests: verify the CLI entrypoint works."""

from typer.testing import CliRunner

from scanner.cli import app

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
