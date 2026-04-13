"""Evaluate unchecked external call detection on small public subsets."""

from __future__ import annotations

import argparse
import json
import re
import sys
from functools import cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.bytecode.loader import extract_bytecode  # noqa: E402
from scanner.compiler.solc import compile_source, ensure_solc  # noqa: E402
from scanner.detectors.unchecked_external_calls import (  # noqa: E402
    UncheckedExternalCallDetector,
)
from scanner.evaluation.common import compute_prf, detect_solc_version  # noqa: E402

DATASET_DIR = ROOT / "datasets" / "unchecked-external-calls"
GROUND_TRUTH = DATASET_DIR / "ground_truth.json"
OUT_OF_SCOPE_SOLIDIFI_BUG_TYPES = {"Unchecked-Send"}
OUT_OF_SCOPE_REASON = (
    "SolidiFI Unchecked-Send samples in this subset use .transfer(), which is "
    "outside the unchecked low-level-call detector scope."
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", "-o", help="Write JSON results to this path")
    parser.add_argument(
        "--tolerance",
        type=int,
        default=6,
        help="Line tolerance for matching findings to labels.",
    )
    args = parser.parse_args()

    if not GROUND_TRUTH.exists():
        print(f"Missing {GROUND_TRUTH}")
        print("Run: uv run python scripts/fetch_unchecked_call_datasets.py")
        return 1

    payload = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    detector = UncheckedExternalCallDetector()
    results = [evaluate_entry(entry, detector) for entry in payload["entries"]]
    metrics_by_dataset = {
        dataset: compute_line_metrics(
            [result for result in results if result["dataset"] == dataset],
            tolerance=args.tolerance,
        )
        for dataset in sorted({result["dataset"] for result in results})
    }
    aggregate = compute_line_metrics(results, tolerance=args.tolerance)
    scoped_results = [result for result in results if _is_primary_scope_result(result)]
    out_of_scope_results = [result for result in results if not _is_primary_scope_result(result)]
    scoped_metrics_by_dataset = {
        dataset: compute_line_metrics(
            [result for result in scoped_results if result["dataset"] == dataset],
            tolerance=args.tolerance,
        )
        for dataset in sorted({result["dataset"] for result in scoped_results})
    }
    scoped_aggregate = compute_line_metrics(scoped_results, tolerance=args.tolerance)
    out_of_scope = {
        "reason": OUT_OF_SCOPE_REASON,
        "metrics": compute_line_metrics(out_of_scope_results, tolerance=args.tolerance),
        "entries": [
            {
                "dataset": result["dataset"],
                "file": result["file"],
                "bug_type": result.get("bug_type", ""),
            }
            for result in out_of_scope_results
        ],
    }

    _print_report(
        results,
        metrics_by_dataset,
        aggregate,
        scoped_metrics_by_dataset,
        scoped_aggregate,
        out_of_scope,
        args.tolerance,
    )

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "ground_truth": payload,
                    "results": results,
                    "metrics_by_dataset": metrics_by_dataset,
                    "aggregate": aggregate,
                    "scoped_metrics_by_dataset": scoped_metrics_by_dataset,
                    "scoped_aggregate": scoped_aggregate,
                    "out_of_scope": out_of_scope,
                    "protocol": {
                        "granularity": "line-level",
                        "tolerance": args.tolerance,
                        "compile_errors": "excluded from precision/recall/F1",
                        "primary_scope": (
                            "SWC-104 low-level call findings; SolidiFI Unchecked-Send "
                            "transfer-only labels are reported separately."
                        ),
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nResults written to {out}")

    return 0


def evaluate_entry(
    entry: dict[str, Any], detector: UncheckedExternalCallDetector
) -> dict[str, Any]:
    source_path = DATASET_DIR / entry["file"]
    source = source_path.read_text(encoding="utf-8", errors="replace")
    solc_version = _coerce_solc_version(detect_solc_version(source, resolve_ranges=True))
    result: dict[str, Any] = {
        "dataset": entry["dataset"],
        "file": entry["file"],
        "label": entry["label"],
        "bug_type": entry.get("bug_type", ""),
        "ground_truth_lines": entry.get("lines", []),
        "solc_version": solc_version,
        "compile_error": None,
        "source_findings": [],
        "bytecode_findings": [],
    }

    try:
        ensure_solc(solc_version)
        compiler_output = compile_source(source_path, version=solc_version)
    except Exception as exc:
        result["compile_error"] = str(exc)
        return result

    source_findings = detector.detect_from_compiler_output(compiler_output)
    bytecode_findings = detector.detect_from_bytecode(extract_bytecode(compiler_output))
    result["source_findings"] = [_finding_payload(finding) for finding in source_findings]
    result["bytecode_findings"] = [_finding_payload(finding) for finding in bytecode_findings]
    return result


def compute_line_metrics(results: list[dict[str, Any]], *, tolerance: int) -> dict[str, Any]:
    tp = 0
    fp = 0
    fn = 0
    skipped = 0

    for result in results:
        if result.get("compile_error"):
            skipped += 1
            continue
        truth = set(int(line) for line in result.get("ground_truth_lines", []))
        finding_lines = [
            finding["line_start"]
            for finding in result.get("source_findings", [])
            if finding.get("line_start", 0) > 0
        ]
        matched_truth, matched_findings = _match_line_findings(
            sorted(truth),
            finding_lines,
            tolerance=tolerance,
        )

        tp += len(matched_truth)
        fn += len(truth) - len(matched_truth)
        fp += len(finding_lines) - len(matched_findings)

    metrics = compute_prf(tp=tp, fp=fp, fn=fn)
    metrics["compile_skipped"] = skipped
    return metrics


def _match_line_findings(
    truth_lines: list[int], finding_lines: list[int], *, tolerance: int
) -> tuple[set[int], set[int]]:
    indexed_findings = sorted(enumerate(finding_lines), key=lambda item: item[1])

    @cache
    def solve(
        truth_index: int, finding_order_index: int
    ) -> tuple[int, int, tuple[tuple[int, int], ...]]:
        if truth_index >= len(truth_lines) or finding_order_index >= len(indexed_findings):
            return 0, 0, ()

        best = solve(truth_index + 1, finding_order_index)
        best = _better_match(best, solve(truth_index, finding_order_index + 1))

        finding_index, finding_line = indexed_findings[finding_order_index]
        distance = abs(finding_line - truth_lines[truth_index])
        if distance <= tolerance:
            count, total_distance, pairs = solve(truth_index + 1, finding_order_index + 1)
            candidate = (
                count + 1,
                total_distance + distance,
                ((truth_index, finding_index), *pairs),
            )
            best = _better_match(best, candidate)

        return best

    _count, _total_distance, pairs = solve(0, 0)
    return {truth_index for truth_index, _finding_index in pairs}, {
        finding_index for _truth_index, finding_index in pairs
    }


def _better_match(
    left: tuple[int, int, tuple[tuple[int, int], ...]],
    right: tuple[int, int, tuple[tuple[int, int], ...]],
) -> tuple[int, int, tuple[tuple[int, int], ...]]:
    if right[0] > left[0]:
        return right
    if right[0] == left[0] and right[1] < left[1]:
        return right
    return left


def _is_primary_scope_result(result: dict[str, Any]) -> bool:
    return not (
        result.get("dataset") == "solidifi"
        and result.get("bug_type") in OUT_OF_SCOPE_SOLIDIFI_BUG_TYPES
    )


def _finding_payload(finding: Any) -> dict[str, Any]:
    return {
        "title": finding.title,
        "contract": finding.contract,
        "function": finding.function,
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "swc_id": finding.swc_id,
        "line_start": finding.location.line_start if finding.location else 0,
    }


def _coerce_solc_version(version: str) -> str:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version)
    if not match:
        return version
    major, minor, patch = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    if major == 0 and minor == 4 and patch < 11:
        return "0.4.11"
    return version


def _print_report(
    results: list[dict[str, Any]],
    metrics_by_dataset: dict[str, dict[str, Any]],
    aggregate: dict[str, Any],
    scoped_metrics_by_dataset: dict[str, dict[str, Any]],
    scoped_aggregate: dict[str, Any],
    out_of_scope: dict[str, Any],
    tolerance: int,
) -> None:
    print("Unchecked external call evaluation")
    print(f"Protocol: line-level matching, tolerance=+/-{tolerance}")
    print("-" * 60)
    print("Primary scoped metrics")
    for dataset, metrics in scoped_metrics_by_dataset.items():
        total = sum(
            1
            for result in results
            if result["dataset"] == dataset and _is_primary_scope_result(result)
        )
        compiled = total - int(metrics["compile_skipped"])
        print(dataset)
        print(f"  Compiled: {compiled}/{total}")
        print(f"  TP: {metrics['tp']}  FP: {metrics['fp']}  FN: {metrics['fn']}")
        print(f"  Precision: {metrics['precision']:.3f}")
        print(f"  Recall:    {metrics['recall']:.3f}")
        print(f"  F1:        {metrics['f1']:.3f}")
    print("Primary scoped aggregate")
    print(
        f"  TP: {scoped_aggregate['tp']}  "
        f"FP: {scoped_aggregate['fp']}  FN: {scoped_aggregate['fn']}"
    )
    print(f"  Precision: {scoped_aggregate['precision']:.3f}")
    print(f"  Recall:    {scoped_aggregate['recall']:.3f}")
    print(f"  F1:        {scoped_aggregate['f1']:.3f}")
    print("-" * 60)
    print("Out-of-scope diagnostics")
    print(f"  Reason: {out_of_scope['reason']}")
    out_metrics = out_of_scope["metrics"]
    print(f"  TP: {out_metrics['tp']}  FP: {out_metrics['fp']}  FN: {out_metrics['fn']}")
    print("-" * 60)
    print("Raw all-label diagnostics")
    for dataset, metrics in metrics_by_dataset.items():
        total = sum(1 for result in results if result["dataset"] == dataset)
        compiled = total - int(metrics["compile_skipped"])
        print(dataset)
        print(f"  Compiled: {compiled}/{total}")
        print(f"  TP: {metrics['tp']}  FP: {metrics['fp']}  FN: {metrics['fn']}")
        print(f"  Precision: {metrics['precision']:.3f}")
        print(f"  Recall:    {metrics['recall']:.3f}")
        print(f"  F1:        {metrics['f1']:.3f}")
    print("-" * 60)
    print("Aggregate micro-average")
    print(f"  TP: {aggregate['tp']}  FP: {aggregate['fp']}  FN: {aggregate['fn']}")
    print(f"  Precision: {aggregate['precision']:.3f}")
    print(f"  Recall:    {aggregate['recall']:.3f}")
    print(f"  F1:        {aggregate['f1']:.3f}")


if __name__ == "__main__":
    raise SystemExit(main())
