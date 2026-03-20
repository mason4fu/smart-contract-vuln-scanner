"""Report rendering utilities.

Converts a list of Finding objects into various output formats.
Future formats (SARIF, HTML) will be added here.
"""

from __future__ import annotations

import json
from pathlib import Path

from scanner.models.findings import Finding


def render_json(findings: list[Finding]) -> str:
    """Render findings as a JSON string.

    Args:
        findings: List of Finding objects.

    Returns:
        Pretty-printed JSON string.
    """
    return json.dumps([f.model_dump() for f in findings], indent=2)


def render_text(findings: list[Finding]) -> str:
    """Render findings as a plain-text summary.

    Args:
        findings: List of Finding objects.

    Returns:
        Human-readable text report.
    """
    if not findings:
        return "No findings."
    lines: list[str] = []
    for i, f in enumerate(findings, 1):
        lines.append(f"[{i}] {f.severity.value.upper()}: {f.title}")
        lines.append(f"    Detector: {f.detector}")
        if f.contract:
            lines.append(f"    Contract: {f.contract}")
        if f.location:
            lines.append(f"    Location: {f.location.file}:{f.location.line_start}")
        lines.append(f"    {f.description}")
        lines.append("")
    return "\n".join(lines)


def write_report(findings: list[Finding], dest: Path, fmt: str = "json") -> Path:
    """Write a report file to disk.

    Args:
        findings: List of Finding objects.
        dest: Output file path.
        fmt: Format - 'json' or 'text'.

    Returns:
        Path the report was written to.

    Raises:
        ValueError: If an unsupported format is given.
    """
    # TODO: Add SARIF, markdown, HTML formats
    if fmt == "json":
        content = render_json(findings)
    elif fmt == "text":
        content = render_text(findings)
    else:
        msg = f"Unsupported format: {fmt}"
        raise ValueError(msg)

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return dest
