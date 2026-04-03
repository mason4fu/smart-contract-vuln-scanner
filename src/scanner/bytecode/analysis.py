"""Bytecode-level analysis for access-control patterns.

Analyzes EVM disassembly to detect ORIGIN opcode usage and
CALLER-based authorization gate patterns.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from scanner.bytecode.disasm import disassemble

# EVM opcode mnemonics
_ORIGIN = "ORIGIN"  # 0x32 - tx.origin
_CALLER = "CALLER"  # 0x33 - msg.sender
_EQ = "EQ"  # 0x14
_JUMPI = "JUMPI"  # 0x57
_SSTORE = "SSTORE"  # 0x55
_CALL = "CALL"  # 0xf1
_PUSH4 = "PUSH4"  # 0x63


class CallerCheckPattern(BaseModel):
    """A detected CALLER/ORIGIN comparison followed by conditional jump."""

    offset: int
    uses_origin: bool = False
    uses_caller: bool = False


class BytecodeAnalysis(BaseModel):
    """Results of bytecode-level access control analysis."""

    has_origin: bool = False
    origin_offsets: list[int] = Field(default_factory=list)
    caller_checks: list[CallerCheckPattern] = Field(default_factory=list)
    function_selectors: list[str] = Field(default_factory=list)


def analyze_bytecode(hex_bytecode: str) -> BytecodeAnalysis:
    """Disassemble bytecode and run all access-control pattern checks.

    Args:
        hex_bytecode: Hex-encoded bytecode without 0x prefix.

    Returns:
        BytecodeAnalysis with detected patterns.
    """
    if not hex_bytecode:
        return BytecodeAnalysis()

    try:
        instructions = disassemble(hex_bytecode)
    except Exception:
        return BytecodeAnalysis()

    origin_offsets = detect_origin_usage(instructions)
    caller_checks = detect_caller_checks(instructions)
    selectors = extract_function_selectors(instructions)

    return BytecodeAnalysis(
        has_origin=bool(origin_offsets),
        origin_offsets=origin_offsets,
        caller_checks=caller_checks,
        function_selectors=selectors,
    )


def detect_origin_usage(instructions: list) -> list[int]:
    """Find all offsets where ORIGIN opcode appears.

    Args:
        instructions: List of pyevmasm Instruction objects.

    Returns:
        List of PC offsets for ORIGIN opcodes.
    """
    return [int(insn.pc) for insn in instructions if insn.mnemonic == _ORIGIN]


def detect_caller_checks(instructions: list) -> list[CallerCheckPattern]:
    """Find CALLER/ORIGIN ... EQ ... JUMPI patterns.

    Looks within a sliding window of instructions for:
    CALLER (or ORIGIN) -> (some stack ops) -> EQ -> (maybe more ops) -> JUMPI

    Args:
        instructions: List of pyevmasm Instruction objects.

    Returns:
        List of detected caller check patterns.
    """
    patterns: list[CallerCheckPattern] = []
    insns = list(instructions)
    window = 12  # opcodes to look ahead after CALLER/ORIGIN

    for i, insn in enumerate(insns):
        if insn.mnemonic not in (_CALLER, _ORIGIN):
            continue

        uses_caller = insn.mnemonic == _CALLER
        uses_origin = insn.mnemonic == _ORIGIN

        # Scan ahead for EQ followed by JUMPI
        ahead = insns[i + 1 : i + 1 + window]
        has_eq = any(a.mnemonic == _EQ for a in ahead)
        has_jumpi = any(a.mnemonic == _JUMPI for a in ahead)

        if has_eq and has_jumpi:
            patterns.append(
                CallerCheckPattern(
                    offset=int(insn.pc),
                    uses_caller=uses_caller,
                    uses_origin=uses_origin,
                )
            )

    return patterns


def extract_function_selectors(instructions: list) -> list[str]:
    """Find 4-byte function selectors in the dispatcher.

    Looks for PUSH4 <selector> ... EQ ... JUMPI patterns
    that appear in a Solidity function dispatcher.

    Args:
        instructions: List of pyevmasm Instruction objects.

    Returns:
        List of 4-byte selector hex strings (without 0x prefix).
    """
    selectors: list[str] = []
    insns = list(instructions)
    window = 8

    for i, insn in enumerate(insns):
        if insn.mnemonic != _PUSH4:
            continue
        ahead = insns[i + 1 : i + 1 + window]
        has_eq = any(a.mnemonic == _EQ for a in ahead)
        has_jumpi = any(a.mnemonic == _JUMPI for a in ahead)
        if has_eq and has_jumpi:
            try:
                operand = insn.operand
                if operand is not None:
                    sel = format(int(operand), "08x")
                    if sel not in selectors:
                        selectors.append(sel)
            except (TypeError, ValueError):
                pass

    return selectors
