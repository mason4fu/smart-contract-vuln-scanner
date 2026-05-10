"""Report rendering utilities.

Converts a list of Finding objects into various output formats.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from scanner.models.findings import Finding

_SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_json(findings: list[Finding]) -> str:
    """Render findings as a JSON string.

    Args:
        findings: List of Finding objects.

    Returns:
        Pretty-printed JSON string.
    """
    return json.dumps([f.model_dump() for f in findings], indent=2)


def render_sarif(findings: list[Finding]) -> str:
    """Render findings as a SARIF 2.1.0 JSON document."""
    rules = _sarif_rules(findings)
    results = [_sarif_result(finding) for finding in findings]
    payload = {
        "version": "2.1.0",
        "$schema": (
            "https://json.schemastore.org/sarif-2.1.0.json"
        ),
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "smart-contract-vuln-scanner",
                        "informationUri": "https://github.com/example/smart-contract-vuln-scanner",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


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
        fmt: Format - 'json', 'text', or 'sarif'.

    Returns:
        Path the report was written to.

    Raises:
        ValueError: If an unsupported format is given.
    """
    if fmt == "json":
        content = render_json(findings)
    elif fmt == "sarif":
        content = render_sarif(findings)
    elif fmt == "text":
        content = render_text(findings)
    else:
        msg = f"Unsupported format: {fmt}"
        raise ValueError(msg)

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return dest


def _sarif_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rule_id = _sarif_rule_id(finding)
        if rule_id in rules:
            continue
        short_desc = finding.title
        rules[rule_id] = {
            "id": rule_id,
            "name": short_desc,
            "shortDescription": {"text": short_desc},
            "fullDescription": {"text": finding.description},
            "help": {
                "text": finding.remediation or finding.description,
            },
            "properties": {
                "detector": finding.detector,
                "confidence": finding.confidence,
                "severity": finding.severity.value,
                "tags": [tag for tag in [finding.detector, finding.swc_id] if tag],
            },
        }
    return list(rules.values())


def _sarif_result(finding: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": _sarif_rule_id(finding),
        "level": _SARIF_LEVELS.get(finding.severity.value, "warning"),
        "message": {
            "text": finding.description,
        },
        "properties": {
            "detector": finding.detector,
            "confidence": finding.confidence,
            "severity": finding.severity.value,
            "contract": finding.contract,
            "function": finding.function,
            "swcId": finding.swc_id,
            "remediation": finding.remediation,
        },
    }
    if finding.location and finding.location.file:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.location.file,
                    },
                    "region": _sarif_region(finding),
                }
            }
        ]
    return result


def _sarif_region(finding: Finding) -> dict[str, int]:
    region: dict[str, int] = {}
    if finding.location is None:
        return region
    if finding.location.line_start > 0:
        region["startLine"] = finding.location.line_start
    if finding.location.line_end > 0:
        region["endLine"] = finding.location.line_end
    if finding.location.column_start > 0:
        region["startColumn"] = finding.location.column_start
    if finding.location.column_end > 0:
        region["endColumn"] = finding.location.column_end
    return region


def _sarif_rule_id(finding: Finding) -> str:
    base = finding.swc_id or finding.detector or "scanner-rule"
    title = _slugify(finding.title)
    return f"{base}:{title}" if title else base


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:80]
