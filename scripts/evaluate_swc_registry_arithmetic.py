"""Evaluate arithmetic detector on pinned SWC Registry subset."""

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

DATASET_DIR = ROOT / "datasets" / "swc-registry"
GROUND_TRUTH = DATASET_DIR / "ground_truth.json"
TARGET_SWC = "SWC-101"


def _load_entries() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not GROUND_TRUTH.exists():
        raise FileNotFoundError(
            f"Ground truth not found at {GROUND_TRUTH}. "
            "Run: ./.venv/bin/python scripts/fetch_swc_registry.py"
        )
    payload = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    entries = [entry for entry in payload.get("entries", []) if entry.get("swc_id") == TARGET_SWC]
    return payload, entries


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


def evaluate_entry(entry: dict[str, Any], detector: ArithmeticDetector) -> dict[str, Any]:
    source_path = DATASET_DIR / entry["file"]
    source = source_path.read_text(encoding="utf-8", errors="replace")
    solc_version = detect_solc_version(source, resolve_ranges=True)
    result: dict[str, Any] = {
        "dataset": "swc-registry",
        "file": entry["file"],
        "label": entry["label"],
        "swc_id": entry["swc_id"],
        "ground_truth_lines": entry.get("lines", []),
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

    source_findings = detector.detect_from_compiler_output(compiler_output)
    result["source_findings"] = [_finding_payload(finding) for finding in source_findings]
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

    payload, entries = _load_entries()
    detector = ArithmeticDetector()
    results = [evaluate_entry(entry, detector) for entry in entries]
    aggregate = compute_line_metrics(results, tolerance=args.tolerance)

    compiled = len([result for result in results if not result.get("compile_error")])
    print("Arithmetic SWC Registry Evaluation")
    print("=" * 33)
    print(f"Pinned source: {payload['repo']}@{payload['commit']}")
    print(f"Entries: {len(entries)}")
    print(f"Compiled: {compiled}/{len(entries)}")
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
                    "ground_truth": {
                        "repo": payload["repo"],
                        "commit": payload["commit"],
                        "entries": entries,
                    },
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
