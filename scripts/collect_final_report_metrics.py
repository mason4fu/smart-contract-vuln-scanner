"""Collect report-ready benchmark summaries into JSON and Markdown artifacts."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SCRIPTS = ROOT / "scripts"
for path in (SRC, SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from evaluate_smartbugs import compute_line_metrics as compute_access_control_smartbugs_metrics

REPORT_DIR = ROOT / "reports" / "final-report"
SUMMARY_JSON = REPORT_DIR / "summary.json"
SUMMARY_MD = REPORT_DIR / "summary.md"


def main() -> int:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    summary = {
        "generated_from": {
            "access_control_smartbugs": "reports/final-report/access-control-smartbugs.json",
            "access_control_nssc": "reports/final-report/access-control-nssc.json",
            "access_control_swc_registry": (
                "reports/final-report/access-control-swc-registry.json"
            ),
            "arithmetic_smartbugs": "reports/final-report/arithmetic-smartbugs.json",
            "unchecked_calls": "reports/final-report/unchecked-calls.json",
            "reentrancy_smartbugs": "reports/final-report/reentrancy-smartbugs.csv",
        },
        "detectors": {
            "access_control": _access_control_summary(),
            "unchecked_external_calls": _unchecked_call_summary(),
            "arithmetic": _arithmetic_summary(),
            "reentrancy": _reentrancy_summary(),
        },
        "notes": {
            "stored_but_not_used": (
                "Unchecked-call classification distinguishes a stored success bool that never "
                "gates failure from a success bool that is checked with require/assert/if-revert."
            ),
            "threat_model_expansion": (
                "Access-control detection now treats treasury-style configuration writes as "
                "privileged config surfaces and includes regression coverage for setTreasury."
            ),
        },
    }

    SUMMARY_JSON.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    SUMMARY_MD.write_text(_render_markdown(summary), encoding="utf-8")
    print(f"Wrote {SUMMARY_JSON}")
    print(f"Wrote {SUMMARY_MD}")
    return 0


def _load_json(rel_path: str) -> Any:
    return json.loads((ROOT / rel_path).read_text(encoding="utf-8"))


def _access_control_summary() -> dict[str, Any]:
    smartbugs_results = _load_json("reports/final-report/access-control-smartbugs.json")
    smartbugs_metrics = compute_access_control_smartbugs_metrics(smartbugs_results, tolerance=5)
    smartbugs_compiled = sum(1 for row in smartbugs_results if not row.get("compile_error"))

    nssc = _load_json("reports/final-report/access-control-nssc.json")
    nssc_results = nssc["results"]
    nssc_compiled = sum(1 for row in nssc_results if not row.get("compile_error"))

    swc = _load_json("reports/final-report/access-control-swc-registry.json")
    swc_results = swc["results"]
    swc_compiled = sum(1 for row in swc_results if not row.get("compile_error"))

    return {
        "benchmarks": [
            {
                "benchmark": "SmartBugs Curated",
                "artifact": "reports/final-report/access-control-smartbugs.json",
                "granularity": "line-level (+/-5 lines)",
                "compiled": f"{smartbugs_compiled}/{len(smartbugs_results)}",
                **smartbugs_metrics,
            },
            {
                "benchmark": "Not-So-Smart-Contracts",
                "artifact": "reports/final-report/access-control-nssc.json",
                "granularity": "function-level",
                "compiled": f"{nssc_compiled}/{len(nssc_results)}",
                **nssc["metrics"],
            },
            {
                "benchmark": "SWC Registry",
                "artifact": "reports/final-report/access-control-swc-registry.json",
                "granularity": "contract-level",
                "compiled": f"{swc_compiled}/{len(swc_results)}",
                **swc["metrics"],
            },
        ]
    }


def _unchecked_call_summary() -> dict[str, Any]:
    data = _load_json("reports/final-report/unchecked-calls.json")
    results = data["results"]

    def compiled_count(dataset: str, *, primary_scope: bool) -> tuple[int, int]:
        filtered = [row for row in results if row["dataset"] == dataset]
        if primary_scope and dataset == "solidifi":
            filtered = [row for row in filtered if row.get("bug_type") != "Unchecked-Send"]
        compiled = sum(1 for row in filtered if not row.get("compile_error"))
        return compiled, len(filtered)

    benchmark_rows = []
    for dataset_key, label in (
        ("smartbugs", "SmartBugs Curated"),
        ("not-so-smart-contracts", "Not-So-Smart-Contracts"),
        ("solidifi", "SolidiFI (supplemental)"),
    ):
        compiled, total = compiled_count(dataset_key, primary_scope=True)
        metrics = data["scoped_metrics_by_dataset"][dataset_key]
        benchmark_rows.append(
            {
                "benchmark": label,
                "artifact": "reports/final-report/unchecked-calls.json",
                "granularity": "line-level (+/-6 lines)",
                "compiled": f"{compiled}/{total}",
                **metrics,
            }
        )

    benchmark_rows.append(
        {
            "benchmark": "SWC Registry",
            "artifact": "",
            "granularity": "not evaluated",
            "compiled": "n/a",
            "tp": None,
            "fp": None,
            "fn": None,
            "precision": None,
            "recall": None,
            "f1": None,
            "note": "No pinned SWC-104 subset is cached in this repository.",
        }
    )

    return {
        "benchmarks": benchmark_rows,
        "scoped_aggregate": data["scoped_aggregate"],
        "out_of_scope_diagnostics": data["out_of_scope"],
    }


def _arithmetic_summary() -> dict[str, Any]:
    data = _load_json("reports/final-report/arithmetic-smartbugs.json")
    total = len(data["results"])
    compiled = sum(1 for row in data["results"] if not row.get("compile_error"))
    smartbugs_row = {
        "benchmark": "SmartBugs Curated",
        "artifact": "reports/final-report/arithmetic-smartbugs.json",
        "granularity": "line-level (+/-6 lines)",
        "compiled": f"{compiled}/{total}",
        **data["aggregate"],
    }
    not_evaluated = {
        "artifact": "",
        "granularity": "not evaluated",
        "compiled": "n/a",
        "tp": None,
        "fp": None,
        "fn": None,
        "precision": None,
        "recall": None,
        "f1": None,
    }
    return {
        "benchmarks": [
            smartbugs_row,
            {
                "benchmark": "Not-So-Smart-Contracts",
                **not_evaluated,
                "note": "No curated SWC-101 NSSC subset is scripted in this repository.",
            },
            {
                "benchmark": "SWC Registry",
                **not_evaluated,
                "note": "No pinned SWC-101 SWC Registry subset is scripted in this repository.",
            },
        ]
    }


def _reentrancy_summary() -> dict[str, Any]:
    path = ROOT / "reports" / "final-report" / "reentrancy-smartbugs.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    total = len(rows)
    compiled = sum(row["compiled"] == "True" for row in rows)
    detected = sum(row["detected"] == "True" for row in rows)
    line_hits = sum(row["line_hit"] == "True" for row in rows)
    recall = detected / compiled if compiled else 0.0
    line_recall = line_hits / compiled if compiled else 0.0

    return {
        "benchmarks": [
            {
                "benchmark": "SmartBugs Curated",
                "artifact": "reports/final-report/reentrancy-smartbugs.csv",
                "granularity": "contract hit-rate and exact-line overlap",
                "compiled": f"{compiled}/{total}",
                "detected_contracts": detected,
                "detected_recall": recall,
                "line_hits": line_hits,
                "line_recall": line_recall,
                "note": (
                    "Exploratory only: current detector misses most legacy 0.4.x patterns in "
                    "the SmartBugs reentrancy bucket."
                ),
            },
            {
                "benchmark": "Not-So-Smart-Contracts",
                "artifact": "",
                "granularity": "not evaluated",
                "compiled": "n/a",
                "note": "No NSSC reentrancy evaluator is scripted in this repository.",
            },
            {
                "benchmark": "SWC Registry",
                "artifact": "",
                "granularity": "not evaluated",
                "compiled": "n/a",
                "note": "No pinned SWC-107 SWC Registry subset is scripted in this repository.",
            },
        ]
    }


def _fmt_metric(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def _table(rows: list[dict[str, Any]], *, include_detector: str | None = None) -> list[str]:
    lines = [
        "| Detector | Benchmark | Compiled | Granularity | TP | FP | FN | Precision | Recall | F1 | Notes |",
        "|---|---|---|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        detector = include_detector or ""
        lines.append(
            "| "
            + " | ".join(
                [
                    detector,
                    row["benchmark"],
                    row["compiled"],
                    row["granularity"],
                    _fmt_metric(row.get("tp")),
                    _fmt_metric(row.get("fp")),
                    _fmt_metric(row.get("fn")),
                    _fmt_metric(row.get("precision")),
                    _fmt_metric(row.get("recall")),
                    _fmt_metric(row.get("f1")),
                    row.get("note", ""),
                ]
            )
            + " |"
        )
    return lines


def _render_markdown(summary: dict[str, Any]) -> str:
    access_rows = summary["detectors"]["access_control"]["benchmarks"]
    unchecked_rows = summary["detectors"]["unchecked_external_calls"]["benchmarks"]
    arithmetic_rows = summary["detectors"]["arithmetic"]["benchmarks"]

    lines = [
        "# Final Report Benchmark Summary",
        "",
        "Generated from the saved evaluation artifacts under `reports/final-report/`.",
        "",
        "## Benchmark Matrix",
        "",
    ]
    lines.extend(_table(access_rows, include_detector="Access control"))
    lines.append("")
    lines.extend(_table(unchecked_rows, include_detector="Unchecked external calls"))
    lines.append("")
    lines.extend(_table(arithmetic_rows, include_detector="Arithmetic"))
    lines.append("")
    lines.append("## Reentrancy Status")
    lines.append("")
    lines.append(
        "- SmartBugs Curated exploratory run: "
        f"{summary['detectors']['reentrancy']['benchmarks'][0]['compiled']} compiled, "
        f"{summary['detectors']['reentrancy']['benchmarks'][0]['detected_contracts']} with >=1 "
        "finding, "
        f"detected recall {summary['detectors']['reentrancy']['benchmarks'][0]['detected_recall']:.3f}, "
        f"line overlap recall {summary['detectors']['reentrancy']['benchmarks'][0]['line_recall']:.3f}."
    )
    lines.append(
        "- Interpretation: keep reentrancy framed as a demonstrated detector with tests and "
        "examples, not as a benchmark-strong result on legacy SmartBugs contracts."
    )
    lines.append("")
    lines.append("## Feedback-Specific Notes")
    lines.append("")
    lines.append(
        "- `stored but not used`: the unchecked-call detector distinguishes a success bool that "
        "is merely assigned from one that actually gates failure with `require`, `assert`, or "
        "`if (!success) revert`. That distinction is implemented in "
        "`src/scanner/ast/unchecked_calls.py` and exercised by "
        "`tests/test_unchecked_external_calls.py`."
    )
    lines.append(
        "- `setTreasury` threat-model expansion: access-control analysis now classifies "
        "treasury-style configuration writes as privileged config surfaces. Regression coverage "
        "lives in `tests/fixtures/ConfigSurface.sol`, `tests/test_ast_analysis.py`, and "
        "`tests/test_access_control_detector.py`."
    )
    lines.append(
        "- Supplemental unchecked-call pressure test: `SolidiFI` is included separately from the "
        "main three benchmark families because it is useful for stress testing SWC-104 but not "
        "directly comparable to the hand-curated benchmark subsets."
    )
    lines.append("")
    lines.append("## Artifacts")
    lines.append("")
    for key, path in summary["generated_from"].items():
        lines.append(f"- `{key}`: `{path}`")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
