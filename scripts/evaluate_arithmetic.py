"""Evaluate SWC-101 arithmetic detector on SmartBugs curated arithmetic subset."""

from __future__ import annotations

import argparse
import json
import sys
from functools import cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.compiler.solc import compile_source, ensure_solc  # noqa: E402
from scanner.detectors.arithmetic import ArithmeticDetector  # noqa: E402
from scanner.evaluation.common import compute_prf, detect_solc_version  # noqa: E402

DATASET_DIR = ROOT
GROUND_TRUTH = ROOT / "datasets" / "arithmetic" / "ground_truth.json"


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
        return 1

    payload = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    detector = ArithmeticDetector()
    results = [evaluate_entry(entry, detector) for entry in payload["entries"]]
    aggregate = compute_line_metrics(results, tolerance=args.tolerance)
    _print_report(results, aggregate, args.tolerance)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "ground_truth": payload,
                    "results": results,
                    "aggregate": aggregate,
                    "protocol": {
                        "granularity": "line-level",
                        "tolerance": args.tolerance,
                        "compile_errors": "excluded from precision/recall/F1",
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nResults written to {out}")
    return 0


def evaluate_entry(entry: dict[str, Any], detector: ArithmeticDetector) -> dict[str, Any]:
    source_path = DATASET_DIR / entry["file"]
    source = source_path.read_text(encoding="utf-8", errors="replace")
    solc_version = _coerce_solc_version(detect_solc_version(source, resolve_ranges=True))
    result: dict[str, Any] = {
        "dataset": entry["dataset"],
        "file": entry["file"],
        "label": entry["label"],
        "ground_truth_lines": entry.get("lines", []),
        "solc_version": solc_version,
        "compile_error": None,
        "source_findings": [],
    }
    try:
        ensure_solc(solc_version)
        compiler_output = compile_source(source_path, version=solc_version)
    except Exception as exc:  # pragma: no cover - environment dependent
        result["compile_error"] = str(exc)
        return result

    source_findings = detector.detect_from_compiler_output(compiler_output)
    result["source_findings"] = [_finding_payload(finding) for finding in source_findings]
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
            sorted(truth), finding_lines, tolerance=tolerance
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
    return {truth_idx for truth_idx, _find_idx in pairs}, {
        find_idx for _truth_idx, find_idx in pairs
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
    parts = version.split(".")
    if len(parts) != 3:
        return version
    try:
        major, minor, patch = (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return version
    if major == 0 and minor == 4 and patch < 11:
        return "0.4.11"
    return version


def _print_report(results: list[dict[str, Any]], aggregate: dict[str, Any], tolerance: int) -> None:
    compiled = len([r for r in results if not r.get("compile_error")])
    total = len(results)
    print("Arithmetic SWC-101 Evaluation")
    print("=" * 34)
    print(f"Compiled: {compiled}/{total}")
    print(f"Tolerance: +/-{tolerance} lines")
    print(
        "TP={tp} FP={fp} FN={fn} Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f}".format(
            **aggregate
        )
    )
    if aggregate.get("compile_skipped", 0):
        print(f"Compile skipped: {aggregate['compile_skipped']}")


if __name__ == "__main__":
    raise SystemExit(main())
