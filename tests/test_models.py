"""Model tests: verify Finding and related models work."""

import json

from scanner.models.findings import Finding, Severity, SourceLocation
from scanner.output.report import render_json, render_sarif, render_text


def test_finding_creation():
    """Should be able to create a Finding with required fields."""
    f = Finding(
        detector="test-detector",
        title="Test finding",
        description="This is a test.",
        severity=Severity.LOW,
    )
    assert f.detector == "test-detector"
    assert f.severity == Severity.LOW


def test_finding_with_location():
    """Finding with source location should serialize correctly."""
    loc = SourceLocation(file="Test.sol", line_start=10, line_end=15)
    f = Finding(
        detector="test",
        title="Test",
        description="Desc",
        severity=Severity.HIGH,
        location=loc,
        contract="TestContract",
    )
    data = f.model_dump()
    assert data["location"]["file"] == "Test.sol"
    assert data["contract"] == "TestContract"


def test_render_json_empty():
    """render_json with no findings should produce an empty JSON array."""
    result = render_json([])
    assert json.loads(result) == []


def test_render_text_empty():
    """render_text with no findings should report no findings."""
    result = render_text([])
    assert "No findings" in result


def test_render_text_includes_structured_remediation():
    finding = Finding(
        detector="test",
        title="Bug",
        description="A bug.",
        severity=Severity.MEDIUM,
        remediation="Do the fix.",
        remediation_steps=["Step one", "Step two"],
        secure_pattern="Guard privileged entrypoints",
        remediation_example="require(msg.sender == owner);",
    )

    result = render_text([finding])
    assert "Secure pattern: Guard privileged entrypoints" in result
    assert "Remediation: Do the fix." in result
    assert "- Step one" in result
    assert "Example fix: require(msg.sender == owner);" in result


def test_render_json_roundtrip():
    """Findings should survive JSON serialization."""
    f = Finding(
        detector="test",
        title="Bug",
        description="A bug.",
        severity=Severity.MEDIUM,
    )
    result = json.loads(render_json([f]))
    assert len(result) == 1
    assert result[0]["title"] == "Bug"


def test_render_sarif_empty():
    """render_sarif with no findings should still produce a valid SARIF shell."""
    result = json.loads(render_sarif([]))
    assert result["version"] == "2.1.0"
    assert len(result["runs"]) == 1
    assert result["runs"][0]["results"] == []


def test_render_sarif_includes_rules_results_and_locations():
    finding = Finding(
        detector="access-control",
        title="Missing authorization on sensitive function",
        description="Any caller can invoke this function.",
        severity=Severity.HIGH,
        confidence="high",
        contract="Vault",
        function="setTreasury",
        swc_id="SWC-105",
        remediation="Add an onlyOwner check.",
        remediation_steps=["Add onlyOwner to the entrypoint", "Re-test non-owner access"],
        secure_pattern="Guard privileged entrypoints before sensitive actions",
        remediation_example="function setTreasury(address next) external onlyOwner { treasury = next; }",
        location=SourceLocation(
            file="Vault.sol",
            line_start=12,
            line_end=12,
            column_start=5,
            column_end=22,
        ),
    )

    result = json.loads(render_sarif([finding]))
    run = result["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 1

    rule = run["tool"]["driver"]["rules"][0]
    sarif_result = run["results"][0]

    assert rule["id"].startswith("SWC-105:")
    assert rule["properties"]["detector"] == "access-control"
    assert sarif_result["level"] == "error"
    assert sarif_result["ruleId"] == rule["id"]
    assert sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "Vault.sol"
    assert sarif_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
    assert "Secure pattern" in rule["help"]["text"]
    assert sarif_result["properties"]["remediationSteps"]
