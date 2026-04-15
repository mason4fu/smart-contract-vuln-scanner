#!/usr/bin/env python3
"""Regenerate datasets/arithmetic/ground_truth.json from SmartBugs vulnerabilities.json.

Run from repo root:
  python3 scripts/generate_arithmetic_ground_truth.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VULN_PATH = ROOT / "smartbugs-curated" / "vulnerabilities.json"
OUT_PATH = ROOT / "datasets" / "arithmetic" / "ground_truth.json"


def main() -> int:
    if not VULN_PATH.is_file():
        print(f"Missing {VULN_PATH}", file=sys.stderr)
        return 1

    data = json.loads(VULN_PATH.read_text(encoding="utf-8"))
    entries: list[dict[str, object]] = []
    for item in data:
        path = item.get("path", "")
        if not str(path).startswith("dataset/arithmetic/"):
            continue
        lines_set: set[int] = set()
        for v in item.get("vulnerabilities", []):
            if v.get("category") == "arithmetic":
                for line in v.get("lines", []):
                    lines_set.add(int(line))
        entries.append(
            {
                "dataset": "smartbugs-curated-arithmetic",
                "file": f"smartbugs-curated/{path}",
                "label": "vulnerable",
                "swc_id": "SWC-101",
                "pragma": item.get("pragma", ""),
                "lines": sorted(lines_set),
                "source_meta": item.get("source", ""),
            }
        )

    entries.sort(key=lambda e: str(e["file"]))
    payload = {
        "repo": "smart-contract-vuln-scanner",
        "protocol": {
            "granularity": "line-level",
            "default_line_tolerance": 6,
            "source_contract_paths_relative_to_repo_root": True,
            "description": "Ground truth for SmartBugs Curated arithmetic (SWC-101) bucket.",
        },
        "entries": entries,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUT_PATH} ({len(entries)} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
