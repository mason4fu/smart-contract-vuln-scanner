"""Bytecode loading and disassembly module.

Handles extraction of EVM bytecode from compiler output,
loading raw bytecode from files, and disassembly via pyevmasm.
"""

from scanner.bytecode.disasm import disassemble
from scanner.bytecode.loader import extract_bytecode, load_bytecode_from_file

__all__ = ["extract_bytecode", "load_bytecode_from_file", "disassemble"]
