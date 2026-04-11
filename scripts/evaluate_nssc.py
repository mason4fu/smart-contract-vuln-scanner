"""Evaluate access control detector against Not-So-Smart-Contracts dataset."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scanner.ast.analysis import analyze_source
from scanner.compiler.solc import compile_source, ensure_solc
from scanner.detectors.access_control import AccessControlDetector
from scanner.evaluation.common import compute_prf, detect_solc_version

DATASET_DIR = Path(__file__).parent.parent / "datasets" / "not-so-smart-contracts"

# Ground truth: known vulnerable functions per file
GROUND_TRUTH: dict[str, dict] = {
    "Unprotected.sol": {
        "vuln_functions": ["changeOwner"],
        "vuln_type": "missing_auth",
    },
    "incorrect_constructor.sol": {
        "vuln_functions": ["IamMissing"],
        "vuln_type": "wrong_constructor",
    },
    "Rubixi.sol": {
        "vuln_functions": ["DynamicPyramid"],
        "vuln_type": "wrong_constructor",
    },
}


def evaluate_contract(sol_file: Path, detector: AccessControlDetector) -> dict:
    """Evaluate a single contract file."""
    source = sol_file.read_text(encoding="utf-8")
    solc_version = detect_solc_version(source, resolve_ranges=True)
    result: dict = {
        "file": sol_file.name,
        "solc_version": solc_version,
        "ground_truth": GROUND_TRUTH.get(sol_file.name, {}),
        "findings": [],
        "compile_error": None,
    }

    try:
        ensure_solc(solc_version)
        compiled = compile_source(sol_file, version=solc_version)
        contracts = analyze_source(compiled)
        findings = detector.detect_from_source(contracts)
        result["findings"] = [
            {
                "title": f.title,
                "severity": f.severity.value,
                "contract": f.contract,
                "function": f.function,
                "description": f.description,
            }
            for f in findings
        ]
    except Exception as e:
        result["compile_error"] = str(e)

    return result


def compute_function_metrics(results: list[dict]) -> dict:
    """Compute TP/FP/FN by matching findings to known vulnerable functions."""
    tp = 0
    fp = 0
    fn = 0

    for r in results:
        if r.get("compile_error"):
            continue

        gt = r.get("ground_truth", {})
        vuln_funcs = set(gt.get("vuln_functions", []))
        found_funcs = {f["function"] for f in r.get("findings", []) if f.get("function")}

        if not vuln_funcs and not found_funcs:
            continue

        matched = vuln_funcs & found_funcs
        tp += len(matched)
        fn += len(vuln_funcs - matched)
        fp += len(found_funcs - vuln_funcs)

    return compute_prf(tp=tp, fp=fp, fn=fn)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate detector on Not-So-Smart-Contracts")
    parser.add_argument("--output", "-o", help="Write JSON results to file")
    args = parser.parse_args()

    if not DATASET_DIR.exists():
        print(f"Dataset not found at {DATASET_DIR}")
        print("Run: uv run python scripts/fetch_nssc.py")
        sys.exit(1)

    sol_files = list(DATASET_DIR.rglob("*.sol"))
    if not sol_files:
        print("No .sol files found. Run: uv run python scripts/fetch_nssc.py")
        sys.exit(1)

    detector = AccessControlDetector()
    results = []

    print(f"Evaluating {len(sol_files)} contract(s) from Not-So-Smart-Contracts dataset")
    print()

    for sol_file in sorted(sol_files):
        rel = sol_file.relative_to(DATASET_DIR)
        print(f"  {rel}...", end=" ")
        r = evaluate_contract(sol_file, detector)
        results.append(r)
        if r.get("compile_error"):
            print("COMPILE ERROR")
        else:
            print(f"OK - {len(r['findings'])} finding(s)")

    print()
    print("-" * 60)

    compiled = [r for r in results if not r.get("compile_error")]
    print("Results:")
    print(f"  Compiled successfully: {len(compiled)}/{len(results)}")
    print(f"  Total findings: {sum(len(r['findings']) for r in compiled)}")

    metrics = compute_function_metrics(results)
    print()
    print("Function-level matching:")
    print(f"  True Positives:  {metrics['tp']}")
    print(f"  False Positives: {metrics['fp']}")
    print(f"  False Negatives: {metrics['fn']}")
    print(f"  Precision: {metrics['precision']:.0%}")
    print(f"  Recall:    {metrics['recall']:.0%}")
    print(f"  F1:        {metrics['f1']:.3f}")

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(
            json.dumps({"results": results, "metrics": metrics}, indent=2),
            encoding="utf-8",
        )
        print(f"\nResults written to {output_path}")


if __name__ == "__main__":
    main()
