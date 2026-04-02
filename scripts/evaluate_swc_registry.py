"""Evaluate access-control detector on cached SWC Registry subset."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Add src to path when running as a script
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import scanner.detectors.access_control  # noqa: F401 - register detector
from scanner.ast.analysis import analyze_source
from scanner.compiler.solc import compile_source, ensure_solc
from scanner.detectors.access_control import AccessControlDetector
from scanner.evaluation.common import compute_prf, detect_solc_version

DATASET_DIR = Path(__file__).parent.parent / "datasets" / "swc-registry"
GROUND_TRUTH_FILE = DATASET_DIR / "ground_truth.json"


def _load_ground_truth() -> dict[str, Any]:
    if not GROUND_TRUTH_FILE.exists():
        raise FileNotFoundError(
            f"Ground truth not found at {GROUND_TRUTH_FILE}. "
            "Run: uv run python scripts/fetch_swc_registry.py"
        )
    return json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))


def evaluate_entry(entry: dict[str, Any], detector: AccessControlDetector) -> dict[str, Any]:
    rel_path = Path(entry["file"])
    sol_file = DATASET_DIR / rel_path

    result: dict[str, Any] = {
        "file": rel_path.as_posix(),
        "label": entry["label"],
        "swc_id": entry["swc_id"],
        "vuln_functions": entry.get("vuln_functions", []),
        "findings": [],
        "compile_error": None,
    }

    source = sol_file.read_text(encoding="utf-8", errors="replace")
    version = detect_solc_version(source)
    result["solc_version"] = version

    try:
        ensure_solc(version)
        compiler_output = compile_source(sol_file, version=version)
        contracts = analyze_source(compiler_output)
        findings = detector.detect_from_source(contracts)
    except Exception as exc:
        result["compile_error"] = str(exc)
        return result

    result["findings"] = [
        {
            "title": f.title,
            "swc_id": f.swc_id,
            "contract": f.contract,
            "function": f.function,
            "severity": f.severity.value,
            "confidence": f.confidence,
        }
        for f in findings
    ]
    return result


def compute_contract_metrics(results: list[dict[str, Any]]) -> dict[str, float]:
    """Compute contract-level precision/recall for vulnerable-vs-safe labels."""
    tp = 0
    fp = 0
    fn = 0
    tn = 0

    for r in results:
        if r.get("compile_error"):
            continue

        label = r["label"]
        findings = r.get("findings", [])
        expected_funcs = set(r.get("vuln_functions", []))
        found_funcs = {f.get("function", "") for f in findings if f.get("function")}

        if label == "vulnerable":
            if expected_funcs:
                if expected_funcs & found_funcs:
                    tp += 1
                else:
                    fn += 1
            else:
                if findings:
                    tp += 1
                else:
                    fn += 1
        else:  # safe
            if findings:
                fp += 1
            else:
                tn += 1

    metrics = compute_prf(tp=tp, fp=fp, fn=fn)
    metrics["tn"] = tn
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate detector on SWC registry subset")
    parser.add_argument("--output", "-o", help="Write JSON results to file")
    args = parser.parse_args()

    gt = _load_ground_truth()
    entries = gt["entries"]

    detector = AccessControlDetector()
    results: list[dict[str, Any]] = []

    print("Dataset: SWC Registry subset")
    print(f"Source: {gt['repo']}@{gt['commit']}")
    print(f"Contracts to evaluate: {len(entries)}")
    print("-" * 60)

    compiled = 0
    errors = 0
    total_findings = 0

    for entry in entries:
        print(f"  {entry['file']}... ", end="", flush=True)
        r = evaluate_entry(entry, detector)
        results.append(r)

        if r.get("compile_error"):
            print(f"COMPILE ERROR: {r['compile_error'][:80]}")
            errors += 1
        else:
            n = len(r["findings"])
            total_findings += n
            compiled += 1
            print(f"OK - {n} finding(s)")

    print("-" * 60)
    print("Results:")
    print(f"  Compiled successfully: {compiled}/{len(entries)}")
    print(f"  Compile errors: {errors}")
    print(f"  Total findings: {total_findings}")

    metrics = compute_contract_metrics(results)
    print("\nContract-level matching:")
    print(f"  True Positives:  {metrics['tp']}")
    print(f"  False Positives: {metrics['fp']}")
    print(f"  False Negatives: {metrics['fn']}")
    print(f"  True Negatives:  {metrics['tn']}")
    print(f"  Precision: {metrics['precision']:.0%}")
    print(f"  Recall:    {metrics['recall']:.0%}")
    print(f"  F1:        {metrics['f1']:.3f}")

    if args.output:
        out = Path(args.output)
        out.write_text(
            json.dumps({"ground_truth": gt, "results": results, "metrics": metrics}, indent=2),
            encoding="utf-8",
        )
        print(f"\nResults written to {out}")


if __name__ == "__main__":
    main()
