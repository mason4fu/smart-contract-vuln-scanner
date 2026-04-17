"""Shared pytest fixtures for detector tests (access control, reentrancy, etc.)."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Return the path to the Solidity test fixtures directory."""
    return FIXTURES_DIR


def compile_sol_fixture(name: str, version: str = "0.8.28"):
    """Compile a Solidity fixture file and return compiler output.

    Installs solc 0.8.28 if needed. Uses session-level caching via
    the returned dict (callers can cache themselves).
    """
    from scanner.compiler.solc import compile_source

    path = FIXTURES_DIR / name
    return compile_source(path, version=version)


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


@pytest.fixture(scope="session")
def compiled_near_miss():
    return compile_sol_fixture("NearMiss.sol")


@pytest.fixture(scope="session")
def compiled_balance_check_not_auth():
    return compile_sol_fixture("BalanceCheckNotAuth.sol")


@pytest.fixture(scope="session")
def compiled_balance_check_inverted():
    return compile_sol_fixture("BalanceCheckInverted.sol")


@pytest.fixture(scope="session")
def compiled_creator_pattern():
    return compile_sol_fixture("CreatorPattern.sol")


@pytest.fixture(scope="session")
def compiled_interface_contract():
    return compile_sol_fixture("InterfaceContract.sol")


@pytest.fixture(scope="session")
def compiled_tx_origin_twice():
    return compile_sol_fixture("TxOriginTwice.sol")


@pytest.fixture(scope="session")
def compiled_role_grant_overlap():
    return compile_sol_fixture("RoleGrantOverlap.sol")


@pytest.fixture(scope="session")
def compiled_generic_indexed_write():
    return compile_sol_fixture("GenericIndexedWrite.sol")


@pytest.fixture(scope="session")
def compiled_nested_auth_check():
    return compile_sol_fixture("NestedAuthCheck.sol")


@pytest.fixture(scope="session")
def compiled_wrong_constructor_name():
    return compile_sol_fixture("WrongConstructorName.sol", version="0.4.24")


@pytest.fixture(scope="session")
def compiled_modifier_helper_auth():
    return compile_sol_fixture("ModifierHelperAuth.sol")


@pytest.fixture(scope="session")
def compiled_inherited_auth():
    return compile_sol_fixture("InheritedAuth.sol")


@pytest.fixture(scope="session")
def compiled_oz_ownable():
    return compile_sol_fixture("OZOwnable.sol")


@pytest.fixture(scope="session")
def compiled_uninitialized_owner():
    return compile_sol_fixture("UninitializedOwner.sol")


@pytest.fixture(scope="session")
def compiled_dangerous_renounce():
    return compile_sol_fixture("DangerousRenounce.sol")


@pytest.fixture(scope="session")
def compiled_unguarded_role_grant():
    return compile_sol_fixture("UnguardedRoleGrant.sol")


@pytest.fixture(scope="session")
def compiled_reentrancy_patterns():
    return compile_sol_fixture("ReentrancyPatterns.sol")


@pytest.fixture(scope="session")
def compiled_reentrancy_safe_only():
    return compile_sol_fixture("ReentrancySafeOnly.sol")


@pytest.fixture(scope="session")
def compiled_arithmetic_patterns():
    return compile_sol_fixture("ArithmeticPatterns.sol", version="0.4.25")


@pytest.fixture(scope="session")
def compiled_arithmetic_safe_08():
    return compile_sol_fixture("ArithmeticSafe08.sol")


@pytest.fixture(scope="session")
def compiled_arithmetic_unchecked_08():
    return compile_sol_fixture("ArithmeticUnchecked08.sol")
