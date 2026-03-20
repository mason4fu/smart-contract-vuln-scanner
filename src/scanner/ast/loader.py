"""AST extraction and loading utilities.

Extracts AST data from Solidity compiler output and provides
helpers for loading pre-saved ASTs from disk.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def extract_ast(compiler_output: dict[str, Any]) -> dict[str, Any]:
    """Extract the AST for each source file from compiler output.

    Args:
        compiler_output: Full standard JSON compiler output.

    Returns:
        A dict mapping source file names to their AST dictionaries.
    """
    sources = compiler_output.get("sources", {})
    return {name: info.get("ast", {}) for name, info in sources.items()}


def load_ast_from_file(path: Path) -> dict[str, Any]:
    """Load a previously saved AST JSON file.

    Args:
        path: Path to the JSON file containing an AST.

    Returns:
        Parsed AST dictionary.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def walk_ast(node: dict[str, Any]) -> list[dict[str, Any]]:
    """Recursively collect all nodes from an AST subtree.

    Performs a depth-first traversal. Future detectors will filter
    the returned list by nodeType, attributes, etc.

    Args:
        node: An AST node dictionary.

    Returns:
        Flat list of all AST nodes in the subtree.
    """
    # TODO: Add filtering by nodeType, visitor pattern, etc.
    result: list[dict[str, Any]] = [node]
    for child in node.get("nodes", []):
        result.extend(walk_ast(child))
    # Some node types nest children under different keys
    if "body" in node and isinstance(node["body"], dict):
        result.extend(walk_ast(node["body"]))
    if "statements" in node and isinstance(node["statements"], list):
        for stmt in node["statements"]:
            if isinstance(stmt, dict):
                result.extend(walk_ast(stmt))
    return result
