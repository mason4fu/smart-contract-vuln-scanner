"""Shared pytest fixtures for the access control scanner tests."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Return the path to the Solidity test fixtures directory."""
    return FIXTURES_DIR


def compile_sol_fixture(name: str):
    """Compile a Solidity fixture file and return compiler output.

    Installs solc 0.8.28 if needed. Uses session-level caching via
    the returned dict (callers can cache themselves).
    """
    from scanner.compiler.solc import compile_source

    path = FIXTURES_DIR / name
    return compile_source(path, version="0.8.28")


@pytest.fixture(scope="session")
def compiled_tx_origin_vuln():
    return compile_sol_fixture("TxOriginVuln.sol")


@pytest.fixture(scope="session")
def compiled_missing_auth_vuln():
    return compile_sol_fixture("MissingAuthVuln.sol")


@pytest.fixture(scope="session")
def compiled_safe_contract():
    return compile_sol_fixture("SafeContract.sol")


@pytest.fixture(scope="session")
def compiled_inline_auth_check():
    return compile_sol_fixture("InlineAuthCheck.sol")


@pytest.fixture(scope="session")
def compiled_view_functions():
    return compile_sol_fixture("ViewFunctions.sol")


@pytest.fixture(scope="session")
def compiled_sensitive_actions():
    return compile_sol_fixture("SensitiveActions.sol")
