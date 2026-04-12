"""Detector registry.

Provides a central place to discover and register available detectors.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from scanner.models.findings import Finding

DetectorFn = Callable[[dict[str, Any]], list[Finding]]


def get_detectors() -> dict[str, DetectorFn]:
    """Return the detector name -> detector function mapping."""
    # Import lazily so detector modules can evolve independently.
    from scanner.detectors.reentrancy import detect_reentrancy

    return {"reentrancy": detect_reentrancy}
