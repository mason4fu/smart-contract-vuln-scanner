"""Intermediate representation models for access-control analysis.

These Pydantic models bridge AST/bytecode analysis and detection logic.
Detectors never touch raw AST nodes or EVM instructions directly.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from scanner.models.findings import SourceLocation


class AuthCheck(BaseModel):
    """A detected authorization check within a function or modifier."""

    kind: Literal["require", "if_revert", "modifier", "assert"] = "require"
    uses_msg_sender: bool = False
    uses_tx_origin: bool = False
    references_owner: bool = False
    references_role: bool = False
    source_location: SourceLocation | None = None
    raw_expression: str = ""


class ModifierInfo(BaseModel):
    """A modifier defined on a contract."""

    name: str
    has_auth_check: bool = False
    auth_checks: list[AuthCheck] = Field(default_factory=list)
    source_location: SourceLocation | None = None


class SensitiveAction(BaseModel):
    """A sensitive operation detected in a function body."""

    kind: Literal[
        "owner_change",
        "role_grant",
        "role_revoke",
        "pause",
        "unpause",
        "upgrade",
        "config_set",
        "eth_transfer",
        "token_transfer",
        "selfdestruct",
        "delegatecall",
        "state_mutation",
    ]
    description: str = ""
    source_location: SourceLocation | None = None


class FunctionInfo(BaseModel):
    """Extracted info about a single function."""

    name: str
    selector: str = ""
    visibility: Literal["public", "external", "internal", "private"] = "internal"
    state_mutability: Literal["pure", "view", "nonpayable", "payable"] = "nonpayable"
    is_constructor: bool = False
    is_fallback: bool = False
    is_receive: bool = False
    modifiers: list[str] = Field(default_factory=list)
    auth_checks: list[AuthCheck] = Field(default_factory=list)
    sensitive_actions: list[SensitiveAction] = Field(default_factory=list)
    has_auth_guard: bool = False
    uses_tx_origin: bool = False
    source_location: SourceLocation | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class ContractInfo(BaseModel):
    """Full extracted info about a contract."""

    name: str
    source_file: str = ""
    kind: Literal["contract", "library", "interface", "abstract"] = "contract"
    base_contracts: list[str] = Field(default_factory=list)
    modifiers: list[ModifierInfo] = Field(default_factory=list)
    functions: list[FunctionInfo] = Field(default_factory=list)
    state_variables: list[str] = Field(default_factory=list)
    has_owner_pattern: bool = False
    owner_initialized_in_constructor: bool = False
    source_location: SourceLocation | None = None
