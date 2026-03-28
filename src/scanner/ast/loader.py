"""AST extraction and loading utilities.

Extracts AST data from Solidity compiler output and provides
helpers for loading pre-saved ASTs from disk.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path
from typing import Any

# All child-key names the Solidity AST uses at various node levels
_CHILD_KEYS = (
    "nodes",
    "body",
    "statements",
    "expression",
    "arguments",
    "trueBody",
    "falseBody",
    "condition",
    "rightHandSide",
    "leftHandSide",
    "parameters",
    "returnParameters",
    "modifiers",
    "baseContracts",
    "components",
    "subExpression",
    "initialValue",
    "declarations",
    "eventCall",
)


def extract_ast(compiler_output: dict[str, Any]) -> dict[str, Any]:
    """Extract the AST for each source file from compiler output."""
    sources = compiler_output.get("sources", {})
    return {name: info.get("ast", {}) for name, info in sources.items()}


def load_ast_from_file(path: Path) -> dict[str, Any]:
    """Load a previously saved AST JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))


def walk_ast(node: dict[str, Any]) -> list[dict[str, Any]]:
    """Recursively collect all nodes from an AST subtree (DFS)."""
    result: list[dict[str, Any]] = [node]
    for key in _CHILD_KEYS:
        val = node.get(key)
        if val is None:
            continue
        if isinstance(val, dict):
            result.extend(walk_ast(val))
        elif isinstance(val, list):
            for child in val:
                if isinstance(child, dict):
                    result.extend(walk_ast(child))
    return result


def walk_ast_filtered(
    node: dict[str, Any], node_types: set[str]
) -> Generator[dict[str, Any], None, None]:
    """Yield only nodes whose nodeType is in node_types (DFS)."""
    if node.get("nodeType") in node_types:
        yield node
    for key in _CHILD_KEYS:
        val = node.get(key)
        if val is None:
            continue
        if isinstance(val, dict):
            yield from walk_ast_filtered(val, node_types)
        elif isinstance(val, list):
            for child in val:
                if isinstance(child, dict):
                    yield from walk_ast_filtered(child, node_types)
