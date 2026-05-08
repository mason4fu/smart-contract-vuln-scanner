"""Evaluate external and heuristic baselines on the shared benchmark subsets."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from functools import cache
from pathlib import Path
from typing import Any

import solcx

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SCRIPTS = ROOT / "scripts"
for path in (SRC, SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from eval_smartbugs_reentrancy import (  # noqa: E402
    _coerce_solc_version as coerce_reentrancy_solc_version,
)
from eval_smartbugs_reentrancy import (  # noqa: E402
    _expected_reentrancy_lines,
    _load_reentrancy_entries,
)
from evaluate_smartbugs import (  # noqa: E402
    compute_line_metrics as compute_access_control_metrics,
)
from evaluate_smartbugs import parse_inline_markers, parse_vulnerable_lines  # noqa: E402
from evaluate_unchecked_calls import (  # noqa: E402
    _is_primary_scope_result,
    compute_line_metrics as compute_unchecked_metrics,
)
from scanner.compiler.solc import ensure_solc  # noqa: E402
from scanner.evaluation.common import compute_prf, detect_solc_version  # noqa: E402

SLITHER_BIN = ROOT / ".venv" / "bin" / "slither"
SLITHER_HOME = Path("/private/tmp/codex-slither-home")
SMARTBUGS_ROOT = ROOT / "smartbugs-curated"
SMARTBUGS_ACCESS_CONTROL_DIR = SMARTBUGS_ROOT / "dataset" / "access_control"
UNCHECKED_GROUND_TRUTH = ROOT / "datasets" / "unchecked-external-calls" / "ground_truth.json"

SLITHER_ACCESS_CONTROL_DETECTORS = (
    "tx-origin",
    "protected-vars",
    "suicidal",
    "unprotected-upgrade",
    "arbitrary-send-eth",
    "controlled-delegatecall",
)
SLITHER_REENTRANCY_DETECTORS = (
    "reentrancy-eth",
    "reentrancy-no-eth",
    "reentrancy-benign",
    "reentrancy-events",
    "reentrancy-unlimited-gas",
)
SLITHER_UNCHECKED_DETECTORS = ("unchecked-lowlevel", "unchecked-send")

_UNCHECKED_PATTERN_RE = re.compile(
    r"\.\s*(?:call|callcode|delegatecall)\b|\.\s*send\s*\(",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", "-o", help="Write JSON results to this path")
    parser.add_argument(
        "--unchecked-tolerance",
        type=int,
        default=6,
        help="Line tolerance for unchecked-call benchmark matching.",
    )
    parser.add_argument(
        "--access-control-tolerance",
        type=int,
        default=5,
        help="Line tolerance for SmartBugs access-control matching.",
    )
    parser.add_argument(
        "--reentrancy-tolerance",
        type=int,
        default=3,
        help="Line tolerance for SmartBugs reentrancy overlap checks.",
    )
    args = parser.parse_args()

    if not SLITHER_BIN.exists():
        print(f"Missing Slither executable at {SLITHER_BIN}", file=sys.stderr)
        return 1
    if not UNCHECKED_GROUND_TRUTH.exists():
        print(f"Missing {UNCHECKED_GROUND_TRUTH}", file=sys.stderr)
        return 1

    payload = {
        "tool": "slither",
        "slither_version": _slither_version(),
        "slither": {
            "access_control": evaluate_slither_access_control(
                tolerance=args.access_control_tolerance
            ),
            "unchecked_external_calls": evaluate_slither_unchecked_calls(
                tolerance=args.unchecked_tolerance
            ),
            "reentrancy": evaluate_slither_reentrancy(tolerance=args.reentrancy_tolerance),
        },
        "heuristics": {
            "unchecked_pattern_baseline": evaluate_unchecked_pattern_baseline(
                tolerance=args.unchecked_tolerance
            ),
        },
    }

    _print_summary(payload)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nResults written to {out}")
    return 0


def evaluate_slither_access_control(*, tolerance: int) -> dict[str, Any]:
    results = []
    for source_path in sorted(SMARTBUGS_ACCESS_CONTROL_DIR.glob("*.sol")):
        source = source_path.read_text(encoding="utf-8", errors="replace")
        solc_version = _coerce_slither_solc_version(detect_solc_version(source))
        truth_lines = sorted(
            set(parse_vulnerable_lines(source)).union(parse_inline_markers(source))
        )
        findings = _run_slither(
            source_path,
            solc_version=solc_version,
            detectors=SLITHER_ACCESS_CONTROL_DETECTORS,
        )
        results.append(
            {
                "file": source_path.name,
                "solc_version": solc_version,
                "ground_truth_lines": truth_lines,
                "finding_lines": findings["finding_lines"],
                "findings": findings["findings"],
                "compile_error": findings["compile_error"],
            }
        )

    aggregate = compute_line_metrics_from_rows(results, tolerance=tolerance)
    compiled = sum(1 for row in results if not row.get("compile_error"))
    return {
        "detectors": list(SLITHER_ACCESS_CONTROL_DETECTORS),
        "scope_note": (
            "Slither does not expose a single SWC-105-equivalent detector, so this baseline "
            "uses the closest access-control-related rules rather than claiming category parity."
        ),
        "results": results,
        "aggregate": aggregate,
        "compiled": f"{compiled}/{len(results)}",
        "protocol": {
            "granularity": "line-level",
            "tolerance": tolerance,
        },
    }


def evaluate_slither_unchecked_calls(*, tolerance: int) -> dict[str, Any]:
    payload = json.loads(UNCHECKED_GROUND_TRUTH.read_text(encoding="utf-8"))
    results = []
    for entry in payload["entries"]:
        source_path = ROOT / "datasets" / "unchecked-external-calls" / entry["file"]
        source = source_path.read_text(encoding="utf-8", errors="replace")
        solc_version = _coerce_slither_solc_version(
            detect_solc_version(source, resolve_ranges=True)
        )
        findings = _run_slither(
            source_path,
            solc_version=solc_version,
            detectors=SLITHER_UNCHECKED_DETECTORS,
        )
        results.append(
            {
                "dataset": entry["dataset"],
                "file": entry["file"],
                "label": entry["label"],
                "bug_type": entry.get("bug_type", ""),
                "ground_truth_lines": entry.get("lines", []),
                "solc_version": solc_version,
                "finding_lines": findings["finding_lines"],
                "findings": findings["findings"],
                "compile_error": findings["compile_error"],
            }
        )

    metrics_by_dataset = {
        dataset: compute_line_metrics_from_rows(
            [row for row in results if row["dataset"] == dataset],
            tolerance=tolerance,
        )
        for dataset in sorted({row["dataset"] for row in results})
    }
    scoped_results = [row for row in results if _is_primary_scope_result(row)]
    scoped_metrics_by_dataset = {
        dataset: compute_line_metrics_from_rows(
            [row for row in scoped_results if row["dataset"] == dataset],
            tolerance=tolerance,
        )
        for dataset in sorted({row["dataset"] for row in scoped_results})
    }
    compiled = sum(1 for row in scoped_results if not row.get("compile_error"))
    return {
        "detectors": list(SLITHER_UNCHECKED_DETECTORS),
        "results": results,
        "metrics_by_dataset": metrics_by_dataset,
        "aggregate": compute_line_metrics_from_rows(results, tolerance=tolerance),
        "scoped_metrics_by_dataset": scoped_metrics_by_dataset,
        "scoped_aggregate": compute_line_metrics_from_rows(scoped_results, tolerance=tolerance),
        "compiled_primary_scope": f"{compiled}/{len(scoped_results)}",
        "protocol": {
            "granularity": "line-level",
            "tolerance": tolerance,
            "primary_scope": "Same SWC-104 scope split used by our unchecked-call evaluator.",
        },
    }


def evaluate_slither_reentrancy(*, tolerance: int) -> dict[str, Any]:
    vuln_json = SMARTBUGS_ROOT / "vulnerabilities.json"
    entries = _load_reentrancy_entries(vuln_json)
    results = []
    for entry in entries:
        rel_path = entry["path"]
        source_path = SMARTBUGS_ROOT / rel_path
        solc_version = coerce_reentrancy_solc_version(str(entry.get("pragma", "0.4.26")))
        findings = _run_slither(
            source_path,
            solc_version=solc_version,
            detectors=SLITHER_REENTRANCY_DETECTORS,
        )
        expected_lines = _expected_reentrancy_lines(entry)
        finding_lines = findings["finding_lines"]
        matched_truth, matched_findings = _match_line_findings(
            expected_lines,
            finding_lines,
            tolerance=tolerance,
        )
        results.append(
            {
                "name": entry.get("name", Path(rel_path).name),
                "path": rel_path,
                "solc_version": solc_version,
                "ground_truth_lines": expected_lines,
                "expected_lines": expected_lines,
                "finding_lines": finding_lines,
                "findings": findings["findings"],
                "compile_error": findings["compile_error"],
                "detected": bool(finding_lines),
                "line_hit": bool(matched_truth),
                "tp": len(matched_truth),
                "fp": len(finding_lines) - len(matched_findings),
                "fn": len(expected_lines) - len(matched_truth),
            }
        )

    compiled = [row for row in results if not row.get("compile_error")]
    detected = sum(1 for row in compiled if row["detected"])
    line_hits = sum(1 for row in compiled if row["line_hit"])
    line_metrics = compute_line_metrics_from_rows(compiled, tolerance=tolerance)
    return {
        "detectors": list(SLITHER_REENTRANCY_DETECTORS),
        "results": results,
        "summary": {
            "compiled": f"{len(compiled)}/{len(results)}",
            "detected_contracts": detected,
            "detected_recall": detected / len(compiled) if compiled else 0.0,
            "line_hits": line_hits,
            "line_recall": line_hits / len(compiled) if compiled else 0.0,
            **line_metrics,
        },
        "protocol": {
            "granularity": "contract hit-rate and line overlap",
            "tolerance": tolerance,
        },
    }


def evaluate_unchecked_pattern_baseline(*, tolerance: int) -> dict[str, Any]:
    payload = json.loads(UNCHECKED_GROUND_TRUTH.read_text(encoding="utf-8"))
    results = []
    for entry in payload["entries"]:
        source_path = ROOT / "datasets" / "unchecked-external-calls" / entry["file"]
        source = source_path.read_text(encoding="utf-8", errors="replace")
        finding_lines = [
            index
            for index, line in enumerate(source.splitlines(), start=1)
            if _UNCHECKED_PATTERN_RE.search(line)
        ]
        results.append(
            {
                "dataset": entry["dataset"],
                "file": entry["file"],
                "label": entry["label"],
                "bug_type": entry.get("bug_type", ""),
                "ground_truth_lines": entry.get("lines", []),
                "finding_lines": finding_lines,
                "compile_error": None,
            }
        )

    scoped_results = [row for row in results if _is_primary_scope_result(row)]
    scoped_metrics_by_dataset = {
        dataset: compute_line_metrics_from_rows(
            [row for row in scoped_results if row["dataset"] == dataset],
            tolerance=tolerance,
        )
        for dataset in sorted({row["dataset"] for row in scoped_results})
    }
    return {
        "description": (
            "Naive syntax baseline that flags any low-level call or send occurrence without "
            "checking whether the return value actually gates failure."
        ),
        "results": results,
        "scoped_metrics_by_dataset": scoped_metrics_by_dataset,
        "scoped_aggregate": compute_line_metrics_from_rows(scoped_results, tolerance=tolerance),
        "protocol": {
            "granularity": "line-level",
            "tolerance": tolerance,
        },
    }


def _run_slither(
    source_path: Path,
    *,
    solc_version: str,
    detectors: tuple[str, ...],
) -> dict[str, Any]:
    solc_path = _resolve_solc_binary(solc_version)
    SLITHER_HOME.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="slither-baseline-") as temp_dir:
        temp_root = Path(temp_dir)
        copied_path = temp_root / source_path.name
        shutil.copy2(source_path, copied_path)
        json_path = temp_root / "results.json"
        command = [
            str(SLITHER_BIN),
            copied_path.name,
            "--solc",
            str(solc_path),
            "--detect",
            ",".join(detectors),
            "--json",
            json_path.name,
        ]
        env = os.environ.copy()
        env["HOME"] = str(SLITHER_HOME)
        completed = subprocess.run(
            command,
            cwd=temp_root,
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
            check=False,
        )
        payload = _load_slither_json(json_path)
        if payload is None:
            error = completed.stderr.strip() or completed.stdout.strip() or "Slither run failed"
            return {
                "finding_lines": [],
                "findings": [],
                "compile_error": error[:1200],
            }
        return {
            "finding_lines": _extract_finding_lines(payload),
            "findings": _extract_findings(payload),
            "compile_error": None if payload.get("success", False) else payload.get("error", ""),
        }


def _load_slither_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _extract_finding_lines(payload: dict[str, Any]) -> list[int]:
    finding_lines: list[int] = []
    for detector in payload.get("results", {}).get("detectors", []):
        lines = _extract_detector_lines(detector)
        finding_lines.extend(lines)
    return sorted(finding_lines)


def _extract_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for detector in payload.get("results", {}).get("detectors", []):
        lines = _extract_detector_lines(detector)
        findings.append(
            {
                "check": detector.get("check", ""),
                "impact": detector.get("impact", ""),
                "confidence": detector.get("confidence", ""),
                "description": detector.get("description", "").strip(),
                "lines": lines,
            }
        )
    return findings


def _extract_detector_lines(detector: dict[str, Any]) -> list[int]:
    elements = detector.get("elements", [])
    reentrancy_lines = _collect_element_lines(
        elements,
        predicate=lambda element: (
            element.get("type") == "node"
            and element.get("additional_fields", {}).get("underlying_type") == "external_calls"
        ),
    )
    if reentrancy_lines:
        return reentrancy_lines
    node_lines = _collect_element_lines(
        elements,
        predicate=lambda element: element.get("type") == "node",
    )
    if node_lines:
        return node_lines
    return _collect_element_lines(elements, predicate=lambda _element: True)


def _collect_element_lines(
    elements: list[dict[str, Any]],
    *,
    predicate: Any,
) -> list[int]:
    lines = []
    for element in elements:
        if not predicate(element):
            continue
        mapping = element.get("source_mapping") or {}
        raw_lines = mapping.get("lines") or []
        if raw_lines:
            line = raw_lines[0]
            if isinstance(line, int):
                lines.append(line)
    return sorted(dict.fromkeys(lines))


def _resolve_solc_binary(version: str) -> Path:
    ensure_solc(version)
    candidate = Path(solcx.get_solcx_install_folder()) / f"solc-v{version}"
    if not candidate.exists():
        raise FileNotFoundError(f"Missing solc binary for {version}: {candidate}")
    return candidate


def _coerce_slither_solc_version(version: str) -> str:
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


def _slither_version() -> str:
    completed = subprocess.run(
        [str(SLITHER_BIN), "--version"],
        capture_output=True,
        text=True,
        env={**os.environ, "HOME": str(SLITHER_HOME)},
        timeout=30,
        check=False,
    )
    return (completed.stdout or completed.stderr).strip()


def compute_line_metrics_from_rows(
    results: list[dict[str, Any]],
    *,
    tolerance: int,
) -> dict[str, Any]:
    tp = 0
    fp = 0
    fn = 0
    skipped = 0

    for result in results:
        if result.get("compile_error"):
            skipped += 1
            continue
        truth_lines = [int(line) for line in result.get("ground_truth_lines", [])]
        finding_lines = [int(line) for line in result.get("finding_lines", []) if int(line) > 0]
        matched_truth, matched_findings = _match_line_findings(
            truth_lines,
            finding_lines,
            tolerance=tolerance,
        )
        tp += len(matched_truth)
        fn += len(truth_lines) - len(matched_truth)
        fp += len(finding_lines) - len(matched_findings)

    metrics = compute_prf(tp=tp, fp=fp, fn=fn)
    metrics["compile_skipped"] = skipped
    return metrics


def _match_line_findings(
    truth_lines: list[int],
    finding_lines: list[int],
    *,
    tolerance: int,
) -> tuple[set[int], set[int]]:
    indexed_findings = sorted(enumerate(finding_lines), key=lambda item: item[1])

    @cache
    def solve(
        truth_index: int,
        finding_order_index: int,
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

    _count, _distance, pairs = solve(0, 0)
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


def _print_summary(payload: dict[str, Any]) -> None:
    slither = payload["slither"]
    pattern = payload["heuristics"]["unchecked_pattern_baseline"]
    print("Baseline Comparison Summary")
    print("=" * 28)
    print(f"Slither version: {payload['slither_version']}")
    print("")
    print("Slither / Access control / SmartBugs")
    print(
        "  Compiled {compiled} | TP={tp} FP={fp} FN={fn} | P={precision:.3f} R={recall:.3f} F1={f1:.3f}".format(
            compiled=slither["access_control"]["compiled"],
            **slither["access_control"]["aggregate"],
        )
    )
    print("Slither / Unchecked external calls / primary scope")
    print(
        "  TP={tp} FP={fp} FN={fn} | P={precision:.3f} R={recall:.3f} F1={f1:.3f}".format(
            **slither["unchecked_external_calls"]["scoped_aggregate"]
        )
    )
    print("Slither / Reentrancy / SmartBugs")
    print(
        "  Compiled {compiled} | contract recall={detected_recall:.3f} | line recall={line_recall:.3f}".format(
            **slither["reentrancy"]["summary"]
        )
    )
    print("Naive unchecked-call pattern baseline / primary scope")
    print(
        "  TP={tp} FP={fp} FN={fn} | P={precision:.3f} R={recall:.3f} F1={f1:.3f}".format(
            **pattern["scoped_aggregate"]
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
