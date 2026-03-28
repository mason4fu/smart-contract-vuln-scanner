"""Tests for the reentrancy detector."""

from __future__ import annotations

import pytest

from scanner.compiler.solc import compile_source
from scanner.detectors.reentrancy import detect_reentrancy
from scanner.utils.paths import project_root


@pytest.fixture
def reentrancy_fixture_path():
    p = project_root() / "contracts" / "src" / "ReentrancyExample.sol"
    if not p.is_file():
        pytest.skip("ReentrancyExample.sol fixture not found")
    return p


def test_reentrancy_flags_vulnerable_contract(reentrancy_fixture_path):
    out = compile_source(reentrancy_fixture_path)
    findings = detect_reentrancy(out)

    vuln = [
        f
        for f in findings
        if f.contract == "VulnerableReentrancy" and "external call before state" in f.title.lower()
    ]
    assert len(vuln) >= 1
    assert vuln[0].function == "withdraw"
    assert vuln[0].confidence in {"high", "medium"}


def test_reentrancy_skips_checks_effects_interactions_order(reentrancy_fixture_path):
    out = compile_source(reentrancy_fixture_path)
    findings = detect_reentrancy(out)

    safe = [f for f in findings if f.contract == "SafeReentrancyCEI"]
    assert safe == []
