"""Fetch small unchecked external call evaluation subsets."""

from __future__ import annotations

import csv
import json
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "datasets" / "unchecked-external-calls"
GROUND_TRUTH = OUTPUT_DIR / "ground_truth.json"

SMARTBUGS_REPO = "smartbugs/smartbugs-curated"
SMARTBUGS_COMMIT = "230e649123477eff332742a59a1c7cc6dc286cab"
SMARTBUGS_FILES = [
    "dataset/unchecked_low_level_calls/unchecked_return_value.sol",
    "dataset/unchecked_low_level_calls/mishandled.sol",
    "dataset/unchecked_low_level_calls/lotto.sol",
    "dataset/unchecked_low_level_calls/king_of_the_ether_throne.sol",
    "dataset/unchecked_low_level_calls/etherpot_lotto.sol",
]

SOLIDIFI_REPO = "DependableSystemsLab/SolidiFI-benchmark"
SOLIDIFI_COMMIT = "4b0573e1b3f7031396de6f48f7f3e7380222ad3a"
SOLIDIFI_CATEGORIES = ["Unchecked-Send", "Unhandled-Exceptions"]
SOLIDIFI_SAMPLE_IDS = [1, 2, 3]

NSSC_REPO = "crytic/not-so-smart-contracts"
NSSC_COMMIT = "020dbdbde3e0c2e8de5f3944e7455e438b0995d5"
NSSC_CONTRACT = "unchecked_external_call/KotET_source_code/KingOfTheEtherThrone.sol"
NSSC_README = "unchecked_external_call/README.md"
NSSC_LINES = [100, 107, 120, 161]


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    entries.extend(_fetch_smartbugs())
    entries.extend(_fetch_solidifi())
    entries.extend(_fetch_nssc())

    payload = {
        "datasets": {
            "smartbugs": {
                "repo": SMARTBUGS_REPO,
                "commit": SMARTBUGS_COMMIT,
                "description": "SmartBugs Curated unchecked_low_level_calls subset",
            },
            "solidifi": {
                "repo": SOLIDIFI_REPO,
                "commit": SOLIDIFI_COMMIT,
                "description": "SolidiFI injected Unchecked-Send and Unhandled-Exceptions subset",
            },
            "not-so-smart-contracts": {
                "repo": NSSC_REPO,
                "commit": NSSC_COMMIT,
                "description": "Not-So-Smart-Contracts unchecked_external_call example",
            },
        },
        "entries": entries,
    }
    GROUND_TRUTH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote {len(entries)} entries to {GROUND_TRUTH}")


def _fetch_smartbugs() -> list[dict[str, Any]]:
    vulnerabilities = _fetch_json(
        _raw_url(SMARTBUGS_REPO, SMARTBUGS_COMMIT, "vulnerabilities.json")
    )
    by_path = {entry["path"]: entry for entry in vulnerabilities}
    entries: list[dict[str, Any]] = []

    for rel_path in SMARTBUGS_FILES:
        out_path = OUTPUT_DIR / "smartbugs" / Path(rel_path).name
        _download(_raw_url(SMARTBUGS_REPO, SMARTBUGS_COMMIT, rel_path), out_path)
        vuln_entry = by_path.get(rel_path, {})
        lines = _category_lines(vuln_entry, "unchecked_low_level_calls")
        entries.append(
            {
                "dataset": "smartbugs",
                "file": out_path.relative_to(OUTPUT_DIR).as_posix(),
                "label": "vulnerable",
                "lines": lines,
                "source_path": rel_path,
            }
        )
    return entries


def _fetch_solidifi() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for category in SOLIDIFI_CATEGORIES:
        for sample_id in SOLIDIFI_SAMPLE_IDS:
            base = f"buggy_contracts/{category}"
            sol_rel = f"{base}/buggy_{sample_id}.sol"
            log_rel = f"{base}/BugLog_{sample_id}.csv"
            sol_out = OUTPUT_DIR / "solidifi" / category / f"buggy_{sample_id}.sol"
            log_out = OUTPUT_DIR / "solidifi" / category / f"BugLog_{sample_id}.csv"
            _download(_raw_url(SOLIDIFI_REPO, SOLIDIFI_COMMIT, sol_rel), sol_out)
            _download(_raw_url(SOLIDIFI_REPO, SOLIDIFI_COMMIT, log_rel), log_out)
            entries.append(
                {
                    "dataset": "solidifi",
                    "file": sol_out.relative_to(OUTPUT_DIR).as_posix(),
                    "label": "vulnerable",
                    "lines": _solidifi_lines(log_out),
                    "bug_type": category,
                    "source_path": sol_rel,
                    "bug_log": log_out.relative_to(OUTPUT_DIR).as_posix(),
                }
            )
    return entries


def _fetch_nssc() -> list[dict[str, Any]]:
    contract_out = OUTPUT_DIR / "not-so-smart-contracts" / "KingOfTheEtherThrone.sol"
    readme_out = OUTPUT_DIR / "not-so-smart-contracts" / "README.md"
    _download(_raw_url(NSSC_REPO, NSSC_COMMIT, NSSC_CONTRACT), contract_out)
    _download(_raw_url(NSSC_REPO, NSSC_COMMIT, NSSC_README), readme_out)
    return [
        {
            "dataset": "not-so-smart-contracts",
            "file": contract_out.relative_to(OUTPUT_DIR).as_posix(),
            "label": "vulnerable",
            "lines": NSSC_LINES,
            "source_path": NSSC_CONTRACT,
        }
    ]


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Fetching {url}")
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
        dest.write_bytes(response.read())


def _fetch_json(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def _raw_url(repo: str, commit: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"


def _category_lines(entry: dict[str, Any], category: str) -> list[int]:
    lines: list[int] = []
    for vuln in entry.get("vulnerabilities", []):
        if vuln.get("category") != category:
            continue
        lines.extend(int(line) for line in vuln.get("lines", []) if isinstance(line, int))
    return sorted(set(lines))


def _solidifi_lines(path: Path) -> list[int]:
    lines: list[int] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            try:
                lines.append(int(row["loc"]))
            except (KeyError, TypeError, ValueError):
                continue
    return sorted(set(lines))


if __name__ == "__main__":
    main()
