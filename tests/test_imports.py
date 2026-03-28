"""Smoke tests: verify all package imports work."""

import importlib


def test_scanner_package_imports():
    """All scanner subpackages should be importable."""
    modules = [
        "scanner",
        "scanner.cli",
        "scanner.config",
        "scanner.compiler",
        "scanner.compiler.solc",
        "scanner.ast",
        "scanner.ast.loader",
        "scanner.bytecode",
        "scanner.bytecode.loader",
        "scanner.bytecode.disasm",
        "scanner.models",
        "scanner.models.findings",
        "scanner.output",
        "scanner.output.report",
        "scanner.detectors",
        "scanner.detectors.registry",
        "scanner.detectors.reentrancy",
        "scanner.utils",
        "scanner.utils.paths",
    ]
    for mod_name in modules:
        mod = importlib.import_module(mod_name)
        assert mod is not None, f"Failed to import {mod_name}"


def test_version_is_set():
    """Package version should be a non-empty string."""
    from scanner import __version__

    assert isinstance(__version__, str)
    assert len(__version__) > 0
