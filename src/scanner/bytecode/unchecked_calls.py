"""Bytecode heuristics for low-level call success handling."""

from __future__ import annotations

from typing import Any

from scanner.bytecode.disasm import disassemble
from scanner.models.unchecked_calls import (
    CallKind,
    CallResultStatus,
    CallResultUsage,
    ExternalCallSite,
    FollowupEffect,
)

_CALL_OPS = {
    "CALL": CallKind.CALL,
    "DELEGATECALL": CallKind.DELEGATECALL,
    "STATICCALL": CallKind.STATICCALL,
    "CALLCODE": CallKind.CALLCODE,
}
_FOLLOWUP_OPS = {"SSTORE", "SELFDESTRUCT"}
_TERMINATORS = {"STOP", "RETURN", "REVERT", "INVALID"}


def analyze_unchecked_call_bytecode(
    hex_bytecode: str,
    *,
    contract_name: str = "",
) -> list[ExternalCallSite]:
    """Find CALL-family opcodes whose success result appears unchecked."""
    if not hex_bytecode:
        return []

    try:
        instructions = disassemble(hex_bytecode)
    except (OSError, ValueError):
        return []

    sites: list[ExternalCallSite] = []
    for index, instruction in enumerate(instructions):
        mnemonic = _mnemonic(instruction)
        if mnemonic not in _CALL_OPS:
            continue
        usage, effects = _classify_bytecode_usage(instructions, index)
        sites.append(
            ExternalCallSite(
                call_kind=_CALL_OPS[mnemonic],
                contract=contract_name,
                bytecode_pc=_pc(instruction),
                result_usage=usage,
                followup_effects=effects,
                snippet=mnemonic,
            )
        )
    return sites


def _classify_bytecode_usage(
    instructions: list[Any], call_index: int
) -> tuple[CallResultUsage, list[FollowupEffect]]:
    call_pc = _pc(instructions[call_index])
    lookahead = instructions[call_index + 1 : call_index + 18]
    effects: list[FollowupEffect] = []

    for distance, instruction in enumerate(lookahead, start=1):
        mnemonic = _mnemonic(instruction)
        if mnemonic == "POP":
            return (
                CallResultUsage(
                    status=CallResultStatus.UNCHECKED,
                    evidence=f"CALL-family result at pc {call_pc} is discarded with POP",
                ),
                effects,
            )
        if mnemonic == "JUMPI":
            return (
                CallResultUsage(
                    status=CallResultStatus.CHECKED,
                    success_checked=True,
                    failure_handling_exists=_nearby_revert(lookahead, distance),
                    evidence=f"CALL-family result at pc {call_pc} reaches conditional control flow",
                ),
                effects,
            )
        if mnemonic in _CALL_OPS and distance > 1:
            effects.append(
                FollowupEffect(
                    kind="call",
                    description=f"{mnemonic} follows before a success check",
                    bytecode_pc=_pc(instruction),
                )
            )
            break
        if mnemonic in _FOLLOWUP_OPS or mnemonic.startswith("LOG"):
            effects.append(
                FollowupEffect(
                    kind=mnemonic.lower(),
                    description=f"{mnemonic} follows before a success check",
                    bytecode_pc=_pc(instruction),
                )
            )
            return (
                CallResultUsage(
                    status=CallResultStatus.PROBABLY_UNCHECKED,
                    evidence=f"{mnemonic} follows CALL-family result at pc {call_pc}",
                ),
                effects,
            )
        if mnemonic in _TERMINATORS:
            break

    return (
        CallResultUsage(
            status=CallResultStatus.AMBIGUOUS,
            evidence=f"CALL-family result at pc {call_pc} is not clearly checked or discarded",
        ),
        effects,
    )


def _nearby_revert(instructions: list[Any], jumpi_distance: int) -> bool:
    ahead = instructions[jumpi_distance : jumpi_distance + 8]
    return any(_mnemonic(instruction) in {"REVERT", "INVALID"} for instruction in ahead)


def _mnemonic(instruction: Any) -> str:
    for attr in ("mnemonic", "name"):
        value = getattr(instruction, attr, None)
        if isinstance(value, str):
            return value.upper()
    return ""


def _pc(instruction: Any) -> int:
    value = getattr(instruction, "pc", 0)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
