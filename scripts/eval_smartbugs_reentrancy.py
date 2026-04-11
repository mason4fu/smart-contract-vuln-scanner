#!/usr/bin/env python3
"""Evaluate the reentrancy detector against SmartBugs Curated (reentrancy subset).

Reads smartbugs-curated/vulnerabilities.json, compiles each labeled contract with the
pinned pragma version via py-solc-x, runs detect_reentrancy, and prints a summary.

Usage (from repo root)::

    uv run python scripts/eval_smartbugs_reentrancy.py

Or::

    PYTHONPATH=src python scripts/eval_smartbugs_reentrancy.py

Requires network the first time each solc version is downloaded.

Note: Many curated contracts use Solidity 0.4.x low-level calls
(``.call.value(...)()``), which the current AST detector does not model the
same way as 0.8.x ``call{value: ...}("")``. Expect low recall until those
patterns are added; this script is still useful for regression tracking.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Repo root (parent of scripts/)
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import solcx  # noqa: E402

from scanner.detectors.reentrancy import detect_reentrancy  # noqa: E402


DEFAULT_OUTPUT_SELECTION: dict[str, Any] = {
    "*": {
        "*": [
            "abi",
            "evm.bytecode.object",
            "evm.bytecode.sourceMap",
            "evm.deployedBytecode.object",
            "evm.deployedBytecode.sourceMap",
            "metadata",
            "storageLayout",
        ],
        "": ["ast"],
    },
}


@dataclass
class RowResult:
    name: str
    rel_path: str
    pragma_json: str
    pragma: str
    compiled: bool
    compile_error: str
    finding_count: int
    expected_lines: list[int]
    line_hit: bool
    detected: bool


@dataclass
class Summary:
    total: int = 0
    compiled: int = 0
    compile_failed: int = 0
    detected: int = 0
    missed: int = 0
    line_hits: int = 0
    rows: list[RowResult] = field(default_factory=list)


def _project_root() -> Path:
    return _ROOT


def _load_reentrancy_entries(vuln_json: Path) -> list[dict[str, Any]]:
    data = json.loads(vuln_json.read_text(encoding="utf-8"))
    out: list[dict[str, Any]] = []
    for entry in data:
        vulns = entry.get("vulnerabilities", [])
        if any(v.get("category") == "reentrancy" for v in vulns):
            out.append(entry)
    return out


_MIN_INSTALLABLE_SOLC = "0.4.11"


def _coerce_solc_version(pragma_field: str) -> str:
    """py-solc-x cannot install <0.4.11; bump pragma pins so evaluation can run."""
    raw = pragma_field.strip()
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", raw)
    if not m:
        return raw
    major, minor, patch = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    if major == 0 and minor == 4 and patch < 11:
        return _MIN_INSTALLABLE_SOLC
    return raw


def _expected_reentrancy_lines(entry: dict[str, Any]) -> list[int]:
    lines: list[int] = []
    for v in entry.get("vulnerabilities", []):
        if v.get("category") != "reentrancy":
            continue
        for ln in v.get("lines", []):
            if isinstance(ln, int):
                lines.append(ln)
    return sorted(set(lines))


def _compile_standard_file(source_path: Path, solc_version: str) -> tuple[dict[str, Any] | None, str]:
    """Return (compiler_output, error_message). error_message empty on success."""
    try:
        installed = {str(v) for v in solcx.get_installed_solc_versions()}
        if solc_version not in installed:
            solcx.install_solc(solc_version)
        solcx.set_solc_version(solc_version)
    except Exception as exc:  # noqa: BLE001
        return None, f"solc install/set failed: {exc}"

    text = source_path.read_text(encoding="utf-8")
    standard_input: dict[str, Any] = {
        "language": "Solidity",
        "sources": {source_path.name: {"content": text}},
        "settings": {
            "outputSelection": DEFAULT_OUTPUT_SELECTION,
            "optimizer": {"enabled": True, "runs": 200},
        },
    }

    try:
        output = solcx.compile_standard(standard_input, solc_version=solc_version)
    except Exception as exc:  # noqa: BLE001
        return None, f"compile_standard: {exc}"

    errors = output.get("errors") or []
    hard = [e for e in errors if isinstance(e, dict) and e.get("severity") == "error"]
    if hard:
        msgs = "; ".join(str(e.get("formattedMessage", e)) for e in hard[:3])
        return None, msgs

    return output, ""


def _finding_line_hit(findings: list[Any], expected: list[int]) -> bool:
    if not expected:
        return False
    exp = set(expected)
    for f in findings:
        loc = getattr(f, "location", None)
        if loc is None:
            continue
        ls = getattr(loc, "line_start", 0)
        if ls in exp:
            return True
    return False


def run_evaluation(
    *,
    smartbugs_root: Path,
    write_csv: Path | None,
) -> Summary:
    vuln_json = smartbugs_root / "vulnerabilities.json"
    if not vuln_json.is_file():
        raise FileNotFoundError(f"Missing {vuln_json}")

    entries = _load_reentrancy_entries(vuln_json)
    summary = Summary(total=len(entries))

    for entry in entries:
        rel = entry["path"]
        name = entry.get("name", Path(rel).name)
        pragma_raw = str(entry.get("pragma", "0.4.26"))
        pragma_effective = _coerce_solc_version(pragma_raw)
        source_path = smartbugs_root / rel
        expected_lines = _expected_reentrancy_lines(entry)

        if not source_path.is_file():
            summary.rows.append(
                RowResult(
                    name=name,
                    rel_path=rel,
                    pragma_json=pragma_raw,
                    pragma=pragma_effective,
                    compiled=False,
                    compile_error="file not found",
                    finding_count=0,
                    expected_lines=expected_lines,
                    line_hit=False,
                    detected=False,
                )
            )
            summary.compile_failed += 1
            continue

        out, err = _compile_standard_file(source_path, pragma_effective)
        if out is None:
            summary.compile_failed += 1
            summary.rows.append(
                RowResult(
                    name=name,
                    rel_path=rel,
                    pragma_json=pragma_raw,
                    pragma=pragma_effective,
                    compiled=False,
                    compile_error=err[:500],
                    finding_count=0,
                    expected_lines=expected_lines,
                    line_hit=False,
                    detected=False,
                )
            )
            continue

        summary.compiled += 1
        findings = detect_reentrancy(out)
        n = len(findings)
        detected = n > 0
        line_hit = _finding_line_hit(findings, expected_lines)

        if detected:
            summary.detected += 1
        else:
            summary.missed += 1
        if line_hit:
            summary.line_hits += 1

        summary.rows.append(
            RowResult(
                name=name,
                rel_path=rel,
                pragma_json=pragma_raw,
                pragma=pragma_effective,
                compiled=True,
                compile_error="",
                finding_count=n,
                expected_lines=expected_lines,
                line_hit=line_hit,
                detected=detected,
            )
        )

    if write_csv:
        write_csv.parent.mkdir(parents=True, exist_ok=True)
        with write_csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "name",
                    "path",
                    "pragma_json",
                    "solc_used",
                    "compiled",
                    "compile_error",
                    "findings",
                    "expected_lines",
                    "line_hit",
                    "detected",
                ]
            )
            for r in summary.rows:
                w.writerow(
                    [
                        r.name,
                        r.rel_path,
                        r.pragma_json,
                        r.pragma,
                        r.compiled,
                        r.compile_error.replace("\n", " ")[:200],
                        r.finding_count,
                        " ".join(str(x) for x in r.expected_lines),
                        r.line_hit,
                        r.detected,
                    ]
                )

    return summary


def _print_report(s: Summary) -> None:
    print("SmartBugs Curated — reentrancy subset")
    print(f"  Entries (labeled reentrancy): {s.total}")
    print(f"  Compiled OK:                 {s.compiled}")
    print(f"  Compile failed / missing:    {s.compile_failed}")
    if s.compiled:
        recall = s.detected / s.compiled
        line_recall = s.line_hits / s.compiled
        print(f"  Recall (≥1 finding):         {s.detected}/{s.compiled} ({recall:.1%})")
        print(f"  Line overlap (any expected): {s.line_hits}/{s.compiled} ({line_recall:.1%})")
    hits = [r.name for r in s.rows if r.detected]
    if hits:
        print(f"  With ≥1 finding:             {', '.join(hits)}")
    print()
    print("Per-file (compile failures and misses):")
    for r in s.rows:
        if not r.compiled or not r.detected:
            status = "SKIP" if not r.compiled else "MISS"
            err = f" | {r.compile_error[:120]}..." if len(r.compile_error) > 120 else (
                f" | {r.compile_error}" if r.compile_error else ""
            )
            print(f"  [{status}] {r.name} (pragma {r.pragma}) findings={r.finding_count}{err}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--smartbugs-root",
        type=Path,
        default=_project_root() / "smartbugs-curated",
        help="Path to smartbugs-curated directory",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help="Write detailed results CSV to this path",
    )
    args = parser.parse_args()

    try:
        summary = run_evaluation(smartbugs_root=args.smartbugs_root.resolve(), write_csv=args.csv)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1

    _print_report(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
