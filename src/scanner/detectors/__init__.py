"""Vulnerability detectors.

Each detector analyzes compiler output and returns a list of `Finding` objects.
"""

from scanner.detectors.registry import get_detectors

__all__ = ["get_detectors"]

