"""Fetch Not-So-Smart-Contracts access control samples from GitHub."""

from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

BASE_URL = "https://raw.githubusercontent.com/crytic/not-so-smart-contracts/master"

# Access-control-relevant files to fetch
FILES_TO_FETCH = [
    "unprotected_function/Unprotected.sol",
    "wrong_constructor_name/incorrect_constructor.sol",
    "wrong_constructor_name/Rubixi_source_code/Rubixi.sol",
    "unprotected_function/README.md",
    "wrong_constructor_name/README.md",
]

OUTPUT_DIR = Path(__file__).parent.parent / "datasets" / "not-so-smart-contracts"


def fetch_file(path: str) -> str | None:
    """Fetch a single file from the not-so-smart-contracts repo."""
    url = f"{BASE_URL}/{path}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code} for {url}")
        return None
    except Exception as e:
        print(f"  Error fetching {url}: {e}")
        return None


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Fetching Not-So-Smart-Contracts to {OUTPUT_DIR}/")
    print()

    fetched = 0
    failed = 0

    for file_path in FILES_TO_FETCH:
        dest = OUTPUT_DIR / file_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        print(f"  Fetching {file_path}...", end=" ")
        content = fetch_file(file_path)
        if content is not None:
            dest.write_text(content, encoding="utf-8")
            print("OK")
            fetched += 1
        else:
            print("FAILED")
            failed += 1

    print()
    print(f"Done. {fetched} files fetched, {failed} failed.")


if __name__ == "__main__":
    main()
