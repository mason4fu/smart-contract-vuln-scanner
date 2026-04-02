#!/usr/bin/env python3
"""Evaluate the access control detector against the SmartBugs curated dataset.

Dataset: SmartBugs Curated (https://github.com/smartbugs/smartbugs-curated)
Already present at: smartbugs-curated/dataset/access_control/

Usage:
    uv run python scripts/evaluate_smartbugs.py
    uv run python scripts/evaluate_smartbugs.py --output results.json
    uv run python scripts/evaluate_smartbugs.py --bytecode-only
    uv run python scripts/evaluate_smartbugs.py --tolerance 3
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Add src to path when running as a script
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import scanner.detectors.access_control  # noqa: F401 - register detector
from scanner.ast.analysis import analyze_source
from scanner.bytecode.loader import extract_bytecode
from scanner.compiler.solc import compile_source, ensure_solc
from scanner.detectors.access_control import AccessControlDetector
from scanner.evaluation.common import compute_prf, detect_solc_version
from scanner.models.findings import Finding

DATASET_DIR = Path(__file__).parent.parent / "smartbugs-curated" / "dataset" / "access_control"

_VULN_LINES_RE = re.compile(r"@vulnerable_at_lines\s+([\d,\s]+)")
_INLINE_MARKER_RE = re.compile(r"//\s*<yes>\s*(?:<report>\s*)?ACCESS_CONTROL")


def parse_vulnerable_lines(source: str) -> list[int]:
    """Parse @vulnerable_at_lines annotation from contract header."""
    m = _VULN_LINES_RE.search(source)
    if not m:
        return []
    return [int(x.strip()) for x in m.group(1).split(",") if x.strip().isdigit()]


def parse_inline_markers(source: str) -> list[int]:
    """Parse // <yes> <report> ACCESS_CONTROL and // <yes> ACCESS_CONTROL inline markers.

    Returns list of line numbers (1-based) where these markers appear.
    These serve as additional ground truth annotations at the exact vulnerable line.
    """
    lines = source.splitlines()
    result = []
    for lineno, line in enumerate(lines, start=1):
        if _INLINE_MARKER_RE.search(line):
            result.append(lineno)
    return result


def evaluate_contract(
    sol_file: Path,
    detector: AccessControlDetector,
    bytecode_only: bool = False,
) -> dict:
    source = sol_file.read_text(encoding="utf-8", errors="replace")
    version = detect_solc_version(source)
    vuln_lines = parse_vulnerable_lines(source)
    inline_marker_lines = parse_inline_markers(source)

    result = {
        "file": sol_file.name,
        "solc_version": version,
        "vulnerable_lines": vuln_lines,
        "inline_marker_lines": inline_marker_lines,
        "findings": [],
        "compile_error": None,
        "source_findings": 0,
        "bytecode_findings": 0,
    }

    try:
        ensure_solc(version)
        compiler_output = compile_source(sol_file, version=version)
    except Exception as exc:
        result["compile_error"] = str(exc)
        return result

    source_findings: list[Finding] = []
    bytecode_findings: list[Finding] = []

    if not bytecode_only:
        try:
            contracts = analyze_source(compiler_output)
            source_findings = detector.detect_from_source(contracts)
        except Exception:
            pass

    try:
        bytecodes = extract_bytecode(compiler_output)
        bytecode_findings = detector.detect_from_bytecode(bytecodes)
    except Exception:
        pass

    all_findings = source_findings + bytecode_findings
    result["source_findings"] = len(source_findings)
    result["bytecode_findings"] = len(bytecode_findings)
    result["findings"] = [
        {
            "title": f.title,
            "severity": f.severity.value,
            "contract": f.contract,
            "function": f.function,
            "confidence": f.confidence,
            "location": {
                "line_start": f.location.line_start if f.location else 0,
            },
        }
        for f in all_findings
    ]

    return result


def compute_line_metrics(results: list[dict], tolerance: int = 5) -> dict:
    """Compute TP/FP/FN/precision/recall/F1 across all results."""
    tp = 0
    fp = 0
    fn = 0

    for r in results:
        if r.get("compile_error"):
            continue

        # Combine vulnerable_lines from both annotation styles
        vuln_lines = set(r.get("vulnerable_lines", []))
        vuln_lines.update(r.get("inline_marker_lines", []))

        finding_lines = [
            f["location"]["line_start"]
            for f in r.get("findings", [])
            if f.get("location") and f["location"].get("line_start", 0) > 0
        ]

        if not vuln_lines and not finding_lines:
            continue

        if not vuln_lines:
            # All findings are FP
            fp += len(finding_lines)
            continue

        # For each annotated line, check if any finding is within tolerance
        matched_vuln = set()
        matched_findings = set()

        for vi, vl in enumerate(sorted(vuln_lines)):
            for fi, fl in enumerate(finding_lines):
                if abs(fl - vl) <= tolerance:
                    matched_vuln.add(vi)
                    matched_findings.add(fi)

        tp += len(matched_vuln)
        fn += len(vuln_lines) - len(matched_vuln)
        fp += len(finding_lines) - len(matched_findings)

    return compute_prf(tp=tp, fp=fp, fn=fn)


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate access control detector on SmartBugs dataset"
    )
    parser.add_argument("--output", "-o", help="Write results to JSON file")
    parser.add_argument("--bytecode-only", action="store_true", help="Use bytecode analysis only")
    parser.add_argument(
        "--tolerance",
        type=int,
        default=5,
        help="Line tolerance for matching findings to annotated vulnerable lines (default: 5)",
    )
    args = parser.parse_args()

    sol_files = sorted(DATASET_DIR.glob("*.sol"))
    if not sol_files:
        print(f"No .sol files found in {DATASET_DIR}", file=sys.stderr)
        sys.exit(1)

    print("Dataset: SmartBugs Curated - access_control")
    print(f"Contracts to evaluate: {len(sol_files)}")
    print(f"Mode: {'bytecode-only' if args.bytecode_only else 'source + bytecode'}")
    print("-" * 60)

    detector = AccessControlDetector()
    results = []
    compiled_ok = 0
    compile_errors = 0
    total_findings = 0

    for sol_file in sol_files:
        print(f"  {sol_file.name}... ", end="", flush=True)
        result = evaluate_contract(sol_file, detector, bytecode_only=args.bytecode_only)
        results.append(result)

        if result["compile_error"]:
            print(f"COMPILE ERROR: {result['compile_error'][:80]}")
            compile_errors += 1
        else:
            n = len(result["findings"])
            total_findings += n
            compiled_ok += 1
            print(
                f"OK - {n} finding(s) "
                f"[src:{result['source_findings']} bc:{result['bytecode_findings']}]"
            )

    print("-" * 60)
    print("Results:")
    print(f"  Compiled successfully: {compiled_ok}/{len(sol_files)}")
    print(f"  Compile errors: {compile_errors}")
    print(f"  Total findings: {total_findings}")

    # Precision/recall where we have ground truth
    files_with_truth = [r for r in results if r["vulnerable_lines"] and not r["compile_error"]]
    if files_with_truth:
        tp = sum(1 for r in files_with_truth if r["findings"])
        fn = sum(1 for r in files_with_truth if not r["findings"])
        recall = tp / len(files_with_truth) if files_with_truth else 0.0
        print(f"\nGround-truth evaluation ({len(files_with_truth)} annotated contracts):")
        print(f"  True Positives (flagged known-vuln): {tp}")
        print(f"  False Negatives (missed known-vuln): {fn}")
        print(f"  Recall: {recall:.0%}")

    # Line-level matching metrics
    line_metrics = compute_line_metrics(results, tolerance=args.tolerance)
    print(f"\nLine-level matching (tolerance={args.tolerance}):")
    print(f"  True Positives:  {line_metrics['tp']}")
    print(f"  False Positives: {line_metrics['fp']}")
    print(f"  False Negatives: {line_metrics['fn']}")
    print(f"  Precision: {line_metrics['precision']:.0%}")
    print(f"  Recall:    {line_metrics['recall']:.0%}")
    print(f"  F1:        {line_metrics['f1']:.3f}")

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nResults written to {output_path}")


if __name__ == "__main__":
    main()
