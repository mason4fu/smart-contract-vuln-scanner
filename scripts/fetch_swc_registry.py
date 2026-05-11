"""Fetch a pinned SWC Registry subset and cache extracted Solidity snippets.

The SWC registry stores samples in markdown. This script extracts selected
```solidity``` snippets listed in scripts/swc_registry_manifest.json and writes
cached .sol files plus ground truth metadata under datasets/swc-registry/.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

MANIFEST_PATH = Path(__file__).parent / "swc_registry_manifest.json"
OUTPUT_DIR = Path(__file__).parent.parent / "datasets" / "swc-registry"
GROUND_TRUTH_PATH = OUTPUT_DIR / "ground_truth.json"

_SNIPPET_RE = re.compile(
    r"###\s+([^\n]+\.sol)\s*\r?\n\r?\n```solidity\r?\n(.*?)\r?\n```",
    re.DOTALL,
)


def _load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _fetch_doc(repo: str, commit: str, base_path: str, doc_name: str) -> str:
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{base_path}/{doc_name}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} fetching {url}") from exc
    except Exception as exc:  # pragma: no cover - defensive network handling
        raise RuntimeError(f"Error fetching {url}: {exc}") from exc


def _extract_snippets(markdown: str) -> dict[str, str]:
    snippets: dict[str, str] = {}
    for name, code in _SNIPPET_RE.findall(markdown):
        snippets[name.strip()] = code.rstrip() + "\n"
    return snippets


def main() -> None:
    manifest = _load_manifest()
    repo = manifest["repo"]
    commit = manifest["commit"]
    base_path = manifest.get("base_path", "entries/docs")
    entries = manifest["entries"]

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Fetch each markdown doc once.
    doc_cache: dict[str, dict[str, str]] = {}
    for doc_name in sorted({e["doc"] for e in entries}):
        print(f"Fetching {doc_name}...")
        markdown = _fetch_doc(repo, commit, base_path, doc_name)
        doc_cache[doc_name] = _extract_snippets(markdown)

    ground_truth_entries: list[dict[str, Any]] = []
    written = 0

    for entry in entries:
        swc_id = entry["swc_id"]
        doc_name = entry["doc"]
        snippet_name = entry["snippet"]
        label = entry["label"]

        snippets = doc_cache.get(doc_name, {})
        if snippet_name not in snippets:
            raise RuntimeError(f"Snippet '{snippet_name}' not found in '{doc_name}'")

        rel_path = Path(swc_id) / snippet_name
        out_path = OUTPUT_DIR / rel_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(snippets[snippet_name], encoding="utf-8")
        written += 1

        gt_entry: dict[str, Any] = {
            "file": rel_path.as_posix(),
            "label": label,
            "swc_id": swc_id,
            "doc": doc_name,
            "snippet": snippet_name,
        }
        for key, value in entry.items():
            if key in {"swc_id", "doc", "snippet", "label"}:
                continue
            gt_entry[key] = value
        ground_truth_entries.append(gt_entry)

    payload = {
        "repo": repo,
        "commit": commit,
        "entries": ground_truth_entries,
    }
    GROUND_TRUTH_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print()
    print(f"Cached snippets: {written}")
    print(f"Ground truth: {GROUND_TRUTH_PATH}")


if __name__ == "__main__":
    main()
