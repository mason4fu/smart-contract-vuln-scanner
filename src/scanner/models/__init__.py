"""Shared data models for the scanner.

Defines result objects, severity levels, finding structures,
and other shared types used across detectors and outputs.
"""

from scanner.models.findings import Finding, Severity

__all__ = ["Finding", "Severity"]
