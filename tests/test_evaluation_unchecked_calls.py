"""Tests for unchecked external call evaluation helpers."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from scanner.evaluation.common import detect_solc_version

EVALUATOR_PATH = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_unchecked_calls.py"
SPEC = importlib.util.spec_from_file_location("evaluate_unchecked_calls", EVALUATOR_PATH)
assert SPEC is not None
assert SPEC.loader is not None
evaluate_unchecked_calls = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluate_unchecked_calls)

compute_line_metrics = evaluate_unchecked_calls.compute_line_metrics
_is_primary_scope_result = evaluate_unchecked_calls._is_primary_scope_result


def test_range_pragma_uses_highest_supported_version_in_range():
    source = "pragma solidity >=0.4.22 <0.6.0;"

    assert detect_solc_version(source, resolve_ranges=True) == "0.5.17"


def test_exact_and_caret_pragmas_keep_expected_resolution():
    assert detect_solc_version("pragma solidity 0.4.21;", resolve_ranges=True) == "0.4.21"
    assert detect_solc_version("pragma solidity ^0.5.1;", resolve_ranges=True) == "0.5.17"


def test_line_matching_is_one_to_one():
    metrics = compute_line_metrics(
        [
            {
                "ground_truth_lines": [10, 11],
                "source_findings": [{"line_start": 10}],
            }
        ],
        tolerance=1,
    )

    assert metrics["tp"] == 1
    assert metrics["fp"] == 0
    assert metrics["fn"] == 1


def test_line_matching_uses_configured_tolerance():
    result = {
        "ground_truth_lines": [132],
        "source_findings": [{"line_start": 138}],
    }

    assert compute_line_metrics([result], tolerance=5)["tp"] == 0
    assert compute_line_metrics([result], tolerance=6)["tp"] == 1


def test_line_matching_prefers_maximum_matches_before_distance():
    metrics = compute_line_metrics(
        [
            {
                "ground_truth_lines": [26, 36, 46],
                "source_findings": [
                    {"line_start": 32},
                    {"line_start": 42},
                    {"line_start": 47},
                ],
            }
        ],
        tolerance=6,
    )

    assert metrics["tp"] == 3
    assert metrics["fp"] == 0
    assert metrics["fn"] == 0


def test_solidifi_unchecked_send_is_out_of_primary_scope():
    assert not _is_primary_scope_result({"dataset": "solidifi", "bug_type": "Unchecked-Send"})
    assert _is_primary_scope_result({"dataset": "solidifi", "bug_type": "Unhandled-Exceptions"})
    assert _is_primary_scope_result({"dataset": "smartbugs", "bug_type": ""})
