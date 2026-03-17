"""Model tests: verify Finding and related models work."""

import json

from scanner.models.findings import Finding, Severity, SourceLocation
from scanner.output.report import render_json, render_text


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
