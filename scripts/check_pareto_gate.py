#!/usr/bin/env python3
"""Pareto gate for detector quality: no precision drop when recall rises.

Compares current metrics against a baseline JSON file.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from evaluate_nssc import DATASET_DIR as NSSC_DIR
from evaluate_nssc import (
    compute_function_metrics,
)
from evaluate_nssc import (
    evaluate_contract as eval_nssc_contract,
)
from evaluate_smartbugs import DATASET_DIR as SMARTBUGS_DIR
from evaluate_smartbugs import (
    compute_line_metrics,
)
from evaluate_smartbugs import (
    evaluate_contract as eval_sb_contract,
)
from evaluate_swc_registry import (
    _load_ground_truth as load_swc_ground_truth,
)
from evaluate_swc_registry import (
    compute_contract_metrics as compute_swc_metrics,
)
from evaluate_swc_registry import (
    evaluate_entry as eval_swc_entry,
)

import scanner.detectors.access_control  # noqa: F401
from scanner.ast.analysis import analyze_source
from scanner.compiler.solc import compile_source, ensure_solc
from scanner.detectors.access_control import AccessControlDetector
from scanner.evaluation.common import detect_solc_version

_OOD_DATASET_ROOT = Path(__file__).parent.parent / "smartbugs-curated" / "dataset"


def _compute_current_metrics() -> dict[str, float]:
    detector = AccessControlDetector()

    sb_results = [eval_sb_contract(p, detector) for p in sorted(SMARTBUGS_DIR.glob("*.sol"))]
    sb_metrics = compute_line_metrics(sb_results, tolerance=5)

    nssc_results = [eval_nssc_contract(p, detector) for p in sorted(NSSC_DIR.rglob("*.sol"))]
    nssc_metrics = compute_function_metrics(nssc_results)

    swc_ground_truth = load_swc_ground_truth()
    swc_results = [eval_swc_entry(entry, detector) for entry in swc_ground_truth["entries"]]
    swc_metrics = compute_swc_metrics(swc_results)

    return {
        "smartbugs_precision": sb_metrics["precision"],
        "smartbugs_recall": sb_metrics["recall"],
        "nssc_precision": nssc_metrics["precision"],
        "nssc_recall": nssc_metrics["recall"],
        "swc_precision": swc_metrics["precision"],
        "swc_recall": swc_metrics["recall"],
    }


def _compute_ood_source_hit_rate() -> float:
    detector = AccessControlDetector()
    compiled = 0
    hits = 0
    for category_dir in sorted(p for p in _OOD_DATASET_ROOT.iterdir() if p.is_dir()):
        if category_dir.name == "access_control":
            continue
        for sol_file in sorted(category_dir.glob("*.sol")):
            source = sol_file.read_text(encoding="utf-8", errors="replace")
            version = detect_solc_version(source)
            try:
                ensure_solc(version)
                compiler_output = compile_source(sol_file, version=version)
            except Exception:
                continue
            compiled += 1
            try:
                findings = detector.detect_from_source(analyze_source(compiler_output))
            except Exception:
                findings = []
            if findings:
                hits += 1
    return (hits / compiled) if compiled else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description="Pareto gate for access-control detector metrics")
    parser.add_argument(
        "--baseline",
        required=True,
        help="Path to baseline metrics JSON.",
    )
    parser.add_argument(
        "--max-ood-hit-rate",
        type=float,
        default=0.60,
        help="Maximum allowed OOD source hit-rate.",
    )
    args = parser.parse_args()

    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    current = _compute_current_metrics()
    epsilon = 1e-6

    failures: list[str] = []

    sb_p0 = baseline["smartbugs_precision"]
    sb_r0 = baseline["smartbugs_recall"]
    sb_p1 = current["smartbugs_precision"]
    sb_r1 = current["smartbugs_recall"]

    nssc_p0 = baseline["nssc_precision"]
    nssc_p1 = current["nssc_precision"]

    if sb_r1 > (sb_r0 + epsilon) and sb_p1 < (sb_p0 - epsilon):
        failures.append("Pareto violation: SmartBugs recall increased while precision decreased")

    if sb_p1 < (sb_p0 - epsilon):
        failures.append("SmartBugs precision dropped below baseline")

    if nssc_p1 < (nssc_p0 - epsilon):
        failures.append("NSSC precision dropped below baseline")

    if "swc_precision" in baseline:
        swc_p0 = baseline["swc_precision"]
        swc_p1 = current["swc_precision"]
        if swc_p1 < (swc_p0 - epsilon):
            failures.append("SWC precision dropped below baseline")

    if "swc_recall" in baseline:
        swc_r0 = baseline["swc_recall"]
        swc_r1 = current["swc_recall"]
        if swc_r1 < (swc_r0 - epsilon):
            failures.append("SWC recall dropped below baseline")

    print("Baseline:", baseline)
    print("Current:", current)

    ood_hit_rate = _compute_ood_source_hit_rate()
    print("OOD source hit-rate:", ood_hit_rate)
    if ood_hit_rate > args.max_ood_hit_rate:
        failures.append("OOD guardrail failed")

    if failures:
        print("FAIL")
        for failure in failures:
            print(" -", failure)
        return 1

    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
