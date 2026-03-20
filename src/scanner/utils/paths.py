"""Path resolution utilities.

Provides helpers for finding the project root directory and
resolving source file paths consistently across platforms.
"""

from __future__ import annotations

import re
from pathlib import Path


def project_root() -> Path:
    """Return the project root directory.

    Walks up from this file's location to find the directory
    containing pyproject.toml.

    Returns:
        Absolute path to the project root.

    Raises:
        FileNotFoundError: If pyproject.toml cannot be found.
    """
    current = Path(__file__).resolve().parent
    for parent in [current, *current.parents]:
        if (parent / "pyproject.toml").exists():
            return parent
    msg = "Could not find project root (no pyproject.toml found)"
    raise FileNotFoundError(msg)


def resolve_source(target: str | Path) -> Path:
    """Resolve a source path relative to the project root.

    If the path is already absolute, returns it directly.
    Otherwise, resolves it relative to the project root.

    Args:
        target: Source file path (absolute or relative).

    Returns:
        Resolved absolute path.
    """
    # `Path.is_absolute()` is OS-dependent. In GitHub Actions (Linux),
    # `Path("C:/...")` is not considered absolute, even though users may
    # provide Windows-style absolute paths. Detect those explicitly.
    s = str(target)
    p = Path(s)

    # Unix-style absolute paths (Linux/macOS): `/home/...`
    if p.is_absolute():
        return p

    # Windows drive-letter absolute paths: `C:/...` or `C:\...`
    # Regex checks the *string form* so it works even when running on Linux.
    if re.match(r"^[A-Za-z]:[\\/].*$", s):
        return p

    # Otherwise treat as relative to the project root.
    return project_root() / p
