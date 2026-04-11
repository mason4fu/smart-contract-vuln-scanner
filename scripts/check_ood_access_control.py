#!/usr/bin/env python3
"""Guardrail check for access-control detector drift on non-access-control datasets.

Fails with non-zero exit when source-level hit-rate on compiled non-access-control
SmartBugs contracts exceeds the configured threshold.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import scanner.detectors.access_control  # noqa: F401 - register detector
from scanner.ast.analysis import analyze_source
from scanner.compiler.solc import compile_source, ensure_solc
from scanner.detectors.access_control import AccessControlDetector
from scanner.evaluation.common import detect_solc_version

_DATASET_ROOT = Path(__file__).parent.parent / "smartbugs-curated" / "dataset"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check OOD access-control source hit-rate")
    parser.add_argument(
        "--max-hit-rate",
        type=float,
        default=0.60,
        help="Maximum allowed source hit-rate on compiled non-access-control contracts.",
    )
    args = parser.parse_args()

    detector = AccessControlDetector()

    compiled = 0
    source_hits = 0
    category_stats: dict[str, tuple[int, int]] = {}

    for category_dir in sorted(p for p in _DATASET_ROOT.iterdir() if p.is_dir()):
        if category_dir.name == "access_control":
            continue

        cat_compiled = 0
        cat_hits = 0
        for sol_file in sorted(category_dir.glob("*.sol")):
            source = sol_file.read_text(encoding="utf-8", errors="replace")
            version = detect_solc_version(source)
            try:
                ensure_solc(version)
                compiler_output = compile_source(sol_file, version=version)
            except Exception:
                continue

            cat_compiled += 1
            compiled += 1

            try:
                contracts = analyze_source(compiler_output)
                findings = detector.detect_from_source(contracts)
            except Exception:
                findings = []

            if findings:
                cat_hits += 1
                source_hits += 1

        category_stats[category_dir.name] = (cat_compiled, cat_hits)

    hit_rate = (source_hits / compiled) if compiled else 0.0

    print("OOD Access-Control Guardrail")
    print(f"Compiled contracts: {compiled}")
    print(f"Contracts with source findings: {source_hits}")
    print(f"Source hit-rate: {hit_rate:.3f}")
    print(f"Threshold (max): {args.max_hit_rate:.3f}")

    print("Per-category:")
    for category, (cat_compiled, cat_hits) in category_stats.items():
        cat_rate = (cat_hits / cat_compiled) if cat_compiled else 0.0
        print(f"  {category}: compiled={cat_compiled} hits={cat_hits} rate={cat_rate:.3f}")

    if hit_rate > args.max_hit_rate:
        print("FAIL: OOD source hit-rate exceeds threshold")
        return 1

    print("PASS: OOD source hit-rate within threshold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
