"""Common helpers used by evaluation and guardrail scripts."""

from __future__ import annotations

import re

_PRAGMA_RE = re.compile(r"pragma solidity\s+[\^~>=<]*(\d+\.\d+\.\d+)")
_PRAGMA_BODY_RE = re.compile(r"pragma solidity\s+([^;]+);")
_VERSION_CONSTRAINT_RE = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*(\d+\.\d+\.\d+)")
_EVAL_SOLC_VERSIONS = ("0.8.28", "0.7.6", "0.6.12", "0.5.17", "0.4.25", "0.4.11")


def detect_solc_version(source: str, *, resolve_ranges: bool = False) -> str:
    """Extract a solc version from pragma with a safe legacy fallback."""
    if resolve_ranges:
        body_match = _PRAGMA_BODY_RE.search(source)
        if body_match:
            resolved = _resolve_version_constraints(body_match.group(1))
            if resolved:
                return resolved

    match = _PRAGMA_RE.search(source)
    if match:
        return match.group(1)
    return "0.4.25"


def _resolve_version_constraints(body: str) -> str:
    constraints = [
        (match.group(1) or "", _version_tuple(match.group(2)))
        for match in _VERSION_CONSTRAINT_RE.finditer(body)
    ]
    if not constraints:
        return ""
    if len(constraints) == 1 and constraints[0][0] in ("", "="):
        return _version_str(constraints[0][1])

    for candidate in (_version_tuple(version) for version in _EVAL_SOLC_VERSIONS):
        if all(
            _satisfies_constraint(candidate, operator, version) for operator, version in constraints
        ):
            return _version_str(candidate)
    return _version_str(constraints[0][1])


def _satisfies_constraint(
    candidate: tuple[int, int, int], operator: str, version: tuple[int, int, int]
) -> bool:
    if operator in ("", "="):
        return candidate == version
    if operator == ">=":
        return candidate >= version
    if operator == ">":
        return candidate > version
    if operator == "<=":
        return candidate <= version
    if operator == "<":
        return candidate < version
    if operator == "^":
        return candidate >= version and candidate < _caret_upper_bound(version)
    if operator == "~":
        return candidate >= version and candidate < (version[0], version[1] + 1, 0)
    return False


def _caret_upper_bound(version: tuple[int, int, int]) -> tuple[int, int, int]:
    major, minor, patch = version
    if major > 0:
        return (major + 1, 0, 0)
    if minor > 0:
        return (0, minor + 1, 0)
    return (0, 0, patch + 1)


def _version_tuple(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


def _version_str(version: tuple[int, int, int]) -> str:
    return f"{version[0]}.{version[1]}.{version[2]}"


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
