"""Project-wide aggregation helpers for multi-file scans."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from scanner.models.findings import Finding

_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def build_project_summary(
    findings: list[Finding],
    *,
    target: Path,
    sol_files: list[Path],
    json_files: list[Path],
    bin_files: list[Path],
) -> dict[str, Any]:
    """Aggregate findings into a project-level summary structure."""
    severity_counts = Counter(f.severity.value for f in findings)
    detector_counts = Counter(f.detector for f in findings if f.detector)
    swc_counts = Counter(f.swc_id for f in findings if f.swc_id)

    file_buckets: dict[str, list[Finding]] = defaultdict(list)
    contract_buckets: dict[str, list[Finding]] = defaultdict(list)

    for finding in findings:
        file_key = ""
        if finding.location and finding.location.file:
            file_key = finding.location.file
        elif finding.contract:
            file_key = finding.contract
        if file_key:
            file_buckets[file_key].append(finding)
        if finding.contract:
            contract_buckets[finding.contract].append(finding)

    files = [
        _file_summary(path, bucket) for path, bucket in sorted(file_buckets.items(), key=_bucket_sort_key)
    ]
    contracts = [
        _contract_summary(name, bucket)
        for name, bucket in sorted(contract_buckets.items(), key=_bucket_sort_key)
    ]

    summary = {
        "target": str(target),
        "inputs": {
            "solidity_files": len(sol_files),
            "compiled_json_files": len(json_files),
            "bytecode_files": len(bin_files),
        },
        "totals": {
            "findings": len(findings),
            "files_with_findings": len(files),
            "contracts_with_findings": len(contracts),
        },
        "by_severity": dict(sorted(severity_counts.items())),
        "by_detector": dict(sorted(detector_counts.items())),
        "by_swc": dict(sorted(swc_counts.items())),
        "top_files": files[:10],
        "top_contracts": contracts[:10],
    }
    if files:
        summary["hottest_file"] = files[0]
    if contracts:
        summary["hottest_contract"] = contracts[0]
    return summary


def render_project_summary_text(summary: dict[str, Any]) -> str:
    """Render a compact human-readable summary for project scans."""
    totals = summary["totals"]
    lines = [
        "Project Summary",
        f"  Target: {summary['target']}",
        (
            "  Inputs: "
            f"{summary['inputs']['solidity_files']} Solidity, "
            f"{summary['inputs']['compiled_json_files']} compiled JSON, "
            f"{summary['inputs']['bytecode_files']} bytecode"
        ),
        (
            "  Findings: "
            f"{totals['findings']} across "
            f"{totals['files_with_findings']} file(s) and "
            f"{totals['contracts_with_findings']} contract(s)"
        ),
    ]
    if summary.get("by_detector"):
        detector_bits = ", ".join(f"{count} {name}" for name, count in summary["by_detector"].items())
        lines.append(f"  By detector: {detector_bits}")
    if summary.get("hottest_file"):
        hottest_file = summary["hottest_file"]
        lines.append(
            f"  Top file: {hottest_file['path']} ({hottest_file['finding_count']} findings)"
        )
    if summary.get("hottest_contract"):
        hottest_contract = summary["hottest_contract"]
        lines.append(
            "  Top contract: "
            f"{hottest_contract['name']} ({hottest_contract['finding_count']} findings)"
        )
    return "\n".join(lines)


def write_project_summary(summary: dict[str, Any], dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return dest


def _file_summary(path: str, findings: list[Finding]) -> dict[str, Any]:
    return {
        "path": path,
        "finding_count": len(findings),
        "highest_severity": _highest_severity(findings),
        "detectors": dict(sorted(Counter(f.detector for f in findings if f.detector).items())),
        "contracts": sorted({f.contract for f in findings if f.contract}),
        "swc_ids": sorted({f.swc_id for f in findings if f.swc_id}),
    }


def _contract_summary(name: str, findings: list[Finding]) -> dict[str, Any]:
    files = sorted(
        {
            f.location.file
            for f in findings
            if f.location and f.location.file
        }
    )
    return {
        "name": name,
        "finding_count": len(findings),
        "highest_severity": _highest_severity(findings),
        "detectors": dict(sorted(Counter(f.detector for f in findings if f.detector).items())),
        "files": files,
        "swc_ids": sorted({f.swc_id for f in findings if f.swc_id}),
    }


def _highest_severity(findings: list[Finding]) -> str:
    if not findings:
        return "info"
    return max(findings, key=lambda finding: _SEVERITY_RANK.get(finding.severity.value, 0)).severity.value


def _bucket_sort_key(item: tuple[str, list[Finding]]) -> tuple[int, int, str]:
    name, findings = item
    highest = max((_SEVERITY_RANK.get(f.severity.value, 0) for f in findings), default=0)
    return (-len(findings), -highest, name)
