"""Intermediate models for unchecked external call analysis."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from scanner.models.findings import SourceLocation


class CallKind(StrEnum):
    """Low-level external call families that return success information."""

    CALL = "call"
    DELEGATECALL = "delegatecall"
    STATICCALL = "staticcall"
    SEND = "send"
    CALLCODE = "callcode"


class CallResultStatus(StrEnum):
    """How the success result from a low-level call is used."""

    UNCHECKED = "unchecked"
    PROBABLY_UNCHECKED = "probably_unchecked"
    CHECKED = "checked"
    DELEGATED = "delegated"
    AMBIGUOUS = "ambiguous"


class FollowupEffect(BaseModel):
    """State or control effect observed after a low-level call."""

    kind: str
    description: str = ""
    source_location: SourceLocation | None = None
    bytecode_pc: int | None = None


class CallResultUsage(BaseModel):
    """Summary of how a low-level call's returned values are handled."""

    status: CallResultStatus = CallResultStatus.AMBIGUOUS
    success_variable: str = ""
    returndata_variable: str = ""
    success_checked: bool = False
    returndata_checked: bool = False
    failure_handling_exists: bool = False
    returned_to_caller: bool = False
    evidence: str = ""


class ExternalCallSite(BaseModel):
    """A source or bytecode low-level external call site."""

    call_kind: CallKind
    contract: str = ""
    function: str = ""
    source_file: str = ""
    source_location: SourceLocation | None = None
    bytecode_pc: int | None = None
    assigned_variables: list[str] = Field(default_factory=list)
    result_usage: CallResultUsage = Field(default_factory=CallResultUsage)
    followup_effects: list[FollowupEffect] = Field(default_factory=list)
    snippet: str = ""
