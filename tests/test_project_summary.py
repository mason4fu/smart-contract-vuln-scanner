"""Tests for project-wide summary aggregation."""

from __future__ import annotations

from pathlib import Path

from scanner.models.findings import Finding, Severity, SourceLocation
from scanner.output.project_summary import build_project_summary, render_project_summary_text


def test_build_project_summary_groups_by_file_contract_detector_and_swc():
    findings = [
        Finding(
            detector="access-control",
            title="Missing authorization on sensitive function",
            description="desc",
            severity=Severity.HIGH,
            contract="Vault",
            function="setTreasury",
            swc_id="SWC-105",
            location=SourceLocation(file="Vault.sol", line_start=12),
        ),
        Finding(
            detector="reentrancy",
            title="Potential reentrancy: external call before state update",
            description="desc",
            severity=Severity.HIGH,
            contract="Vault",
            function="withdraw",
            swc_id="SWC-107",
            location=SourceLocation(file="Vault.sol", line_start=30),
        ),
        Finding(
            detector="unchecked-external-calls",
            title="Unchecked low-level call result",
            description="desc",
            severity=Severity.MEDIUM,
            contract="Payout",
            function="sendReward",
            swc_id="SWC-104",
            location=SourceLocation(file="Payout.sol", line_start=22),
        ),
    ]

    summary = build_project_summary(
        findings,
        target=Path("contracts"),
        sol_files=[Path("Vault.sol"), Path("Payout.sol")],
        json_files=[],
        bin_files=[],
    )

    assert summary["totals"]["findings"] == 3
    assert summary["totals"]["files_with_findings"] == 2
    assert summary["totals"]["contracts_with_findings"] == 2
    assert summary["by_detector"]["access-control"] == 1
    assert summary["by_detector"]["reentrancy"] == 1
    assert summary["by_swc"]["SWC-105"] == 1
    assert summary["hottest_file"]["path"] == "Vault.sol"
    assert summary["hottest_contract"]["name"] == "Vault"
    assert summary["top_files"][0]["finding_count"] == 2
    assert summary["top_contracts"][0]["finding_count"] == 2


def test_render_project_summary_text_mentions_hotspots():
    summary = {
        "target": "contracts",
        "inputs": {"solidity_files": 2, "compiled_json_files": 0, "bytecode_files": 0},
        "totals": {"findings": 3, "files_with_findings": 2, "contracts_with_findings": 2},
        "by_detector": {"access-control": 1, "reentrancy": 2},
        "hottest_file": {"path": "Vault.sol", "finding_count": 2},
        "hottest_contract": {"name": "Vault", "finding_count": 2},
    }

    text = render_project_summary_text(summary)

    assert "Project Summary" in text
    assert "Target: contracts" in text
    assert "Top file: Vault.sol (2 findings)" in text
    assert "Top contract: Vault (2 findings)" in text
