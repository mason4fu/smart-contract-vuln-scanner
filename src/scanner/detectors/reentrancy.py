"""Reentrancy detector (placeholder AST logic)."""

from __future__ import annotations

from typing import Any

from scanner.models.findings import Finding


def detect_reentrancy(compiler_output: dict[str, Any]) -> list[Finding]:
    """Detect potential reentrancy vulnerabilities (AST-based).

    This is currently a stub. The full heuristic implementation is added in a
    later step.
    """

    _ = compiler_output
    return []

