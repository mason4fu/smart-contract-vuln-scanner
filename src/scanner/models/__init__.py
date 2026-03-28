"""Shared data models for the scanner."""

from scanner.models.findings import Finding, Severity, SourceLocation
from scanner.models.ir import (
    AuthCheck,
    ContractInfo,
    FunctionInfo,
    ModifierInfo,
    SensitiveAction,
)

__all__ = [
    "AuthCheck",
    "ContractInfo",
    "Finding",
    "FunctionInfo",
    "ModifierInfo",
    "SensitiveAction",
    "Severity",
    "SourceLocation",
]
