"""Solidity compiler wrapper using py-solc-x.

Manages compiler installation and provides a typed interface
for compiling Solidity source files with full output selection
(AST, bytecode, source maps, ABI, storage layout).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import solcx


def ensure_solc(version: str = "0.8.28") -> Path:
    """Ensure the specified solc version is installed.

    Downloads it via py-solc-x if not already present.

    Args:
        version: Semantic version string (e.g. "0.8.28").

    Returns:
        Path to the installed solc binary.
    """
    installed = [str(v) for v in solcx.get_installed_solc_versions()]
    if version not in installed:
        solcx.install_solc(version)
    return solcx.get_solcx_install_folder() / f"solc-v{version}" / "solc.exe"


def compile_source(
    source_path: Path,
    *,
    version: str = "0.8.28",
    output_selection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile a Solidity source file and return the compiler output.

    Uses the standard JSON input/output interface so callers can
    request any combination of AST, bytecode, ABI, etc.

    Args:
        source_path: Path to the .sol file.
        version: Solidity compiler version.
        output_selection: Custom output selection dict. If None, a
            comprehensive default is used.

    Returns:
        The full compiler JSON output as a dictionary.
    """
    ensure_solc(version)
    solcx.set_solc_version(version)

    source_text = source_path.read_text(encoding="utf-8")
    file_name = source_path.name

    if output_selection is None:
        output_selection = {
            "*": {
                "*": [
                    "abi",
                    "evm.bytecode.object",
                    "evm.bytecode.sourceMap",
                    "evm.deployedBytecode.object",
                    "evm.deployedBytecode.sourceMap",
                    "metadata",
                    "storageLayout",
                ],
                "": ["ast"],
            }
        }

    standard_input: dict[str, Any] = {
        "language": "Solidity",
        "sources": {file_name: {"content": source_text}},
        "settings": {
            "outputSelection": output_selection,
            "optimizer": {"enabled": True, "runs": 200},
        },
    }

    output = solcx.compile_standard(standard_input, solc_version=version)
    return output


def save_compiler_output(output: dict[str, Any], dest: Path) -> Path:
    """Persist compiler JSON output to disk.

    Args:
        output: Compiler output dictionary.
        dest: Target file path (should end in .json).

    Returns:
        The path the output was written to.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(output, indent=2), encoding="utf-8")
    return dest


def load_compiler_output(path: Path) -> dict[str, Any]:
    """Load previously saved compiler JSON output.

    Args:
        path: Path to the JSON file.

    Returns:
        Parsed compiler output dictionary.
    """
    return json.loads(path.read_text(encoding="utf-8"))
