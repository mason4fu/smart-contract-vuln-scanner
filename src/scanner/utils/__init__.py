"""Shared utility functions.

General-purpose helpers used across the scanner: path resolution,
hashing, logging setup, etc.
"""

from scanner.utils.paths import project_root, resolve_source

__all__ = ["project_root", "resolve_source"]
