"""Common helpers used by evaluation and guardrail scripts."""

from __future__ import annotations

import re

_PRAGMA_RE = re.compile(r"pragma solidity\s+[\^~>=<]*(\d+\.\d+\.\d+)")
_RANGE_PRAGMA_RE = re.compile(r"pragma solidity\s+[\^~>=<]+(\d+)\.(\d+)\.(\d+)")


def detect_solc_version(source: str, *, resolve_ranges: bool = False) -> str:
    """Extract a solc version from pragma with a safe legacy fallback."""
    if resolve_ranges:
        range_match = _RANGE_PRAGMA_RE.search(source)
        if range_match:
            major = int(range_match.group(1))
            minor = int(range_match.group(2))
            if major == 0 and minor <= 4:
                return "0.4.25"
            if major == 0 and minor == 5:
                return "0.5.17"
            if major == 0 and minor == 6:
                return "0.6.12"
            if major == 0 and minor == 7:
                return "0.7.6"

    match = _PRAGMA_RE.search(source)
    if match:
        return match.group(1)
    return "0.4.25"


def compute_prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    """Return precision, recall, and F1 using the existing metric semantics."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }
