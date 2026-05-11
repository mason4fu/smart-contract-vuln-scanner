"""Evaluate arithmetic detector on Not-So-Smart-Contracts arithmetic subset."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.compiler.solc import compile_source, ensure_solc  # noqa: E402
from scanner.detectors.arithmetic import ArithmeticDetector  # noqa: E402
from scanner.evaluation.common import detect_solc_version  # noqa: E402

from evaluate_arithmetic import compute_line_metrics  # type: ignore  # noqa: E402

DATASET_DIR = ROOT / "datasets" / "not-so-smart-contracts"
GROUND_TRUTH = {
    "integer_overflow/integer_overflow_1.sol": {
        "label": "vulnerable",
        "lines": [7],
    }
}


def evaluate_entry(relative_path: str, detector: ArithmeticDetector) -> dict[str, Any]:
    source_path = DATASET_DIR / relative_path
    source = source_path.read_text(encoding="utf-8", errors="replace")
    solc_version = detect_solc_version(source, resolve_ranges=True)
    result: dict[str, Any] = {
        "dataset": "not-so-smart-contracts",
        "file": relative_path,
        "label": GROUND_TRUTH[relative_path]["label"],
        "ground_truth_lines": GROUND_TRUTH[relative_path]["lines"],
        "solc_version": solc_version,
        "compile_error": None,
        "source_findings": [],
    }
    try:
        ensure_solc(solc_version)
        compiler_output = compile_source(source_path, version=solc_version)
    except Exception as exc:
        result["compile_error"] = str(exc)
        return result

    findings = detector.detect_from_compiler_output(compiler_output)
    result["source_findings"] = [
        {
            "title": finding.title,
            "contract": finding.contract,
            "function": finding.function,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "swc_id": finding.swc_id,
            "line_start": finding.location.line_start if finding.location else 0,
        }
        for finding in findings
    ]
    return result


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

    missing = [path for path in GROUND_TRUTH if not (DATASET_DIR / path).exists()]
    if missing:
        print("Missing NSSC arithmetic files:")
        for path in missing:
            print(f"  - {path}")
        print("Run: ./.venv/bin/python scripts/fetch_nssc.py")
        return 1

    detector = ArithmeticDetector()
    results = [evaluate_entry(path, detector) for path in sorted(GROUND_TRUTH)]
    aggregate = compute_line_metrics(results, tolerance=args.tolerance)

    compiled = len([result for result in results if not result.get("compile_error")])
    print("Arithmetic NSSC Evaluation")
    print("=" * 26)
    print(f"Entries: {len(results)}")
    print(f"Compiled: {compiled}/{len(results)}")
    print(f"Tolerance: +/-{args.tolerance} lines")
    print(
        "TP={tp} FP={fp} FN={fn} Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f}".format(
            **aggregate
        )
    )

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "ground_truth": GROUND_TRUTH,
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


if __name__ == "__main__":
    raise SystemExit(main())
