"""Bytecode loading and disassembly module.

Handles extraction of EVM bytecode from compiler output,
loading raw bytecode from files, and disassembly via pyevmasm.
"""

from scanner.bytecode.loader import extract_bytecode, load_bytecode_from_file
from scanner.bytecode.disasm import disassemble

__all__ = ["extract_bytecode", "load_bytecode_from_file", "disassemble"]
