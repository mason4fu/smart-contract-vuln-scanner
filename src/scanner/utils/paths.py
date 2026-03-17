"""Path resolution utilities.

Provides helpers for finding the project root directory and
resolving source file paths consistently across platforms.
"""

from __future__ import annotations

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
    p = Path(target)
    if p.is_absolute():
        return p
    return project_root() / p
