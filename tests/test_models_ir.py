"""Tests for IR Pydantic models."""

from scanner.models.findings import SourceLocation
from scanner.models.ir import (
    AuthCheck,
    ContractInfo,
    FunctionInfo,
    ModifierInfo,
    SensitiveAction,
)


def test_auth_check_defaults():
    ac = AuthCheck()
    assert ac.kind == "require"
    assert not ac.uses_msg_sender
    assert not ac.uses_tx_origin


def test_auth_check_with_location():
    loc = SourceLocation(file="test.sol", line_start=10, line_end=10)
    ac = AuthCheck(kind="require", uses_msg_sender=True, source_location=loc)
    assert ac.source_location.file == "test.sol"
    assert ac.uses_msg_sender


def test_modifier_info():
    ac = AuthCheck(kind="require", uses_msg_sender=True)
    m = ModifierInfo(name="onlyOwner", has_auth_check=True, auth_checks=[ac])
    assert m.name == "onlyOwner"
    assert m.has_auth_check
    assert len(m.auth_checks) == 1


def test_sensitive_action():
    sa = SensitiveAction(kind="owner_change", description="sets new owner")
    assert sa.kind == "owner_change"


def test_function_info_defaults():
    f = FunctionInfo(name="foo")
    assert f.visibility == "internal"
    assert f.state_mutability == "nonpayable"
    assert not f.has_auth_guard
    assert not f.uses_tx_origin


def test_function_info_serialization():
    f = FunctionInfo(
        name="transfer",
        visibility="public",
        state_mutability="nonpayable",
        has_auth_guard=True,
    )
    d = f.model_dump()
    assert d["name"] == "transfer"
    assert d["visibility"] == "public"
    assert d["has_auth_guard"] is True


def test_contract_info():
    f = FunctionInfo(name="withdraw", visibility="external")
    c = ContractInfo(name="Vault", source_file="Vault.sol", functions=[f])
    assert c.name == "Vault"
    assert len(c.functions) == 1
    assert c.functions[0].name == "withdraw"


def test_contract_info_with_modifiers():
    m = ModifierInfo(name="onlyOwner", has_auth_check=True)
    c = ContractInfo(name="Token", modifiers=[m])
    assert c.modifiers[0].has_auth_check
