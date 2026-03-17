"""AST loading and traversal module.

Provides utilities for extracting Solidity ASTs from compiler
output and traversing/querying AST nodes. Future detectors will
use this module to inspect contract structure at the source level.
"""

from scanner.ast.loader import extract_ast, load_ast_from_file

__all__ = ["extract_ast", "load_ast_from_file"]
