"""EVM bytecode disassembly using pyevmasm.

Converts raw hex bytecode into a list of EVM instructions,
enabling bytecode-level analysis for future detectors.
"""

from __future__ import annotations

from pyevmasm import disassemble_hex, assemble_hex, Instruction


def disassemble(hex_bytecode: str) -> list[Instruction]:
    """Disassemble hex bytecode into a list of EVM instructions.

    Args:
        hex_bytecode: Hex-encoded bytecode (no 0x prefix).

    Returns:
        List of pyevmasm Instruction objects.
    """
    # TODO: Add caching, error handling for malformed bytecode
    return list(disassemble_hex(hex_bytecode))


def disassemble_to_text(hex_bytecode: str) -> str:
    """Disassemble hex bytecode into a human-readable text listing.

    Args:
        hex_bytecode: Hex-encoded bytecode (no 0x prefix).

    Returns:
        Multi-line string with one instruction per line.
    """
    return disassemble_hex(hex_bytecode)
