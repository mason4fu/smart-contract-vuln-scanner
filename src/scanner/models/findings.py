"""Finding and severity models for scanner output.

These models represent individual vulnerability findings and their
metadata. All detectors will produce Finding objects.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity classification for a vulnerability finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SourceLocation(BaseModel):
    """Points to a specific location in a Solidity source file."""

    file: str = Field(description="Source file path.")
    line_start: int = Field(default=0, description="Starting line number.")
    line_end: int = Field(default=0, description="Ending line number.")
    column_start: int = Field(default=0)
    column_end: int = Field(default=0)


class Finding(BaseModel):
    """A single vulnerability finding produced by a detector."""

    detector: str = Field(description="Name of the detector that produced this finding.")
    title: str = Field(description="Short human-readable title.")
    description: str = Field(description="Detailed explanation of the issue.")
    severity: Severity = Field(description="Severity level.")
    confidence: str = Field(default="medium", description="Confidence: high, medium, low.")
    location: SourceLocation | None = Field(
        default=None, description="Source location if available."
    )
    contract: str = Field(default="", description="Contract name.")
    function: str = Field(default="", description="Function name if applicable.")

    # TODO: Add references, remediation suggestions, CWE IDs
