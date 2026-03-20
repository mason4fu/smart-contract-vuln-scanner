"""Bytecode extraction and file I/O utilities.

Extracts creation and deployed bytecode from compiler output,
and provides helpers for loading raw hex bytecode from disk.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ContractBytecode:
    """Holds creation and runtime bytecode for a single contract."""

    contract_name: str
    creation_bytecode: str
    deployed_bytecode: str
    source_map: str = ""
    deployed_source_map: str = ""


def extract_bytecode(
    compiler_output: dict[str, Any],
) -> list[ContractBytecode]:
    """Extract bytecode for all contracts from compiler output.

    Args:
        compiler_output: Full standard JSON compiler output.

    Returns:
        A list of ContractBytecode instances, one per contract.
    """
    results: list[ContractBytecode] = []
    contracts = compiler_output.get("contracts", {})
    for _source_name, file_contracts in contracts.items():
        for contract_name, info in file_contracts.items():
            evm = info.get("evm", {})
            bc = evm.get("bytecode", {})
            dbc = evm.get("deployedBytecode", {})
            results.append(
                ContractBytecode(
                    contract_name=contract_name,
                    creation_bytecode=bc.get("object", ""),
                    deployed_bytecode=dbc.get("object", ""),
                    source_map=bc.get("sourceMap", ""),
                    deployed_source_map=dbc.get("sourceMap", ""),
                )
            )
    return results


def load_bytecode_from_file(path: Path) -> str:
    """Load raw hex bytecode from a file.

    The file should contain the hex-encoded bytecode with an
    optional 0x prefix.

    Args:
        path: Path to the bytecode file.

    Returns:
        Hex string of the bytecode (without 0x prefix).
    """
    raw = path.read_text(encoding="utf-8").strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    return raw
