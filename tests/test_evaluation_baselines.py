"""Tests for baseline evaluation helpers."""

from __future__ import annotations

import importlib.util
from pathlib import Path

EVALUATOR_PATH = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_baselines.py"
SPEC = importlib.util.spec_from_file_location("evaluate_baselines", EVALUATOR_PATH)
assert SPEC is not None
assert SPEC.loader is not None
evaluate_baselines = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluate_baselines)

_extract_detector_lines = evaluate_baselines._extract_detector_lines
_match_line_findings = evaluate_baselines._match_line_findings
compute_line_metrics_from_rows = evaluate_baselines.compute_line_metrics_from_rows


def test_extract_detector_lines_prefers_reentrancy_external_call_nodes():
    detector = {
        "elements": [
            {
                "type": "node",
                "source_mapping": {"lines": [20]},
                "additional_fields": {"underlying_type": "state_variables_written"},
            },
            {
                "type": "node",
                "source_mapping": {"lines": [18]},
                "additional_fields": {"underlying_type": "external_calls"},
            },
        ]
    }

    assert _extract_detector_lines(detector) == [18]


def test_extract_detector_lines_falls_back_to_generic_node_lines():
    detector = {
        "elements": [
            {"type": "function", "source_mapping": {"lines": [10]}},
            {"type": "node", "source_mapping": {"lines": [14]}},
            {"type": "node", "source_mapping": {"lines": [14]}},
        ]
    }

    assert _extract_detector_lines(detector) == [14]


def test_match_line_findings_is_one_to_one():
    matched_truth, matched_findings = _match_line_findings(
        [26, 36],
        [31],
        tolerance=5,
    )

    assert len(matched_truth) == 1
    assert matched_findings == {0}


def test_compute_line_metrics_from_rows_skips_compile_errors():
    metrics = compute_line_metrics_from_rows(
        [
            {
                "ground_truth_lines": [20],
                "finding_lines": [20],
                "compile_error": None,
            },
            {
                "ground_truth_lines": [30],
                "finding_lines": [],
                "compile_error": "compile failed",
            },
        ],
        tolerance=0,
    )

    assert metrics["tp"] == 1
    assert metrics["fp"] == 0
    assert metrics["fn"] == 0
    assert metrics["compile_skipped"] == 1
