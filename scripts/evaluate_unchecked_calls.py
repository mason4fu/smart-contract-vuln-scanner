"""Evaluate unchecked external call detection on small public subsets."""

from __future__ import annotations

import argparse
import json
import re
import sys
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", "-o", help="Write JSON results to this path")
    parser.add_argument(
        "--tolerance",
        type=int,
        default=5,
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

    _print_report(results, metrics_by_dataset, aggregate, args.tolerance)

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
        matched_truth: set[int] = set()
        matched_findings: set[int] = set()

        for truth_index, truth_line in enumerate(sorted(truth)):
            for finding_index, finding_line in enumerate(finding_lines):
                if abs(finding_line - truth_line) <= tolerance:
                    matched_truth.add(truth_index)
                    matched_findings.add(finding_index)

        tp += len(matched_truth)
        fn += len(truth) - len(matched_truth)
        fp += len(finding_lines) - len(matched_findings)

    metrics = compute_prf(tp=tp, fp=fp, fn=fn)
    metrics["compile_skipped"] = skipped
    return metrics


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
    tolerance: int,
) -> None:
    print("Unchecked external call evaluation")
    print(f"Protocol: line-level matching, tolerance=+/-{tolerance}")
    print("-" * 60)
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
