"""Path and config tests: verify project paths resolve correctly."""

from pathlib import Path

from scanner.utils.paths import project_root, resolve_source
from scanner.config import load_config


def test_project_root_finds_pyproject():
    """project_root() should point to a directory containing pyproject.toml."""
    root = project_root()
    assert root.is_dir()
    assert (root / "pyproject.toml").exists()


def test_resolve_source_relative():
    """resolve_source() should resolve relative paths from project root."""
    resolved = resolve_source("contracts/src/SimpleStorage.sol")
    assert resolved.is_absolute()
    assert "SimpleStorage.sol" in resolved.name


def test_resolve_source_absolute():
    """resolve_source() should return absolute paths unchanged."""
    abs_path = Path("C:/some/absolute/path.sol")
    assert resolve_source(abs_path) == abs_path


def test_default_config():
    """Default config should load without errors."""
    cfg = load_config()
    assert cfg.solc_version == "0.8.28"
    assert cfg.output_dir == Path("reports")
    assert cfg.log_level == "INFO"
