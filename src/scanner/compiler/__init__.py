"""Compiler integration module.

Provides utilities for compiling Solidity sources via py-solc-x,
requesting AST, bytecode, source maps, and ABI outputs through
the Solidity standard JSON interface.
"""

from scanner.compiler.solc import compile_source, ensure_solc

__all__ = ["compile_source", "ensure_solc"]
