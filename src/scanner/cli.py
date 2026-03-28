"""CLI entrypoint for the vulnerability scanner.

Uses Typer for command-line argument parsing. Sub-commands:
  scan    - Run detectors on a Solidity file, directory, or bytecode
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="scanner",
    help="Static analysis tool for Solidity smart contract vulnerabilities.",
    add_completion=False,
)

console = Console()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit."),
) -> None:
    """Smart Contract Vulnerability Scanner."""
    if version:
        from scanner import __version__

        typer.echo(f"scanner {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Argument(
            help="Solidity file, compiled JSON, .bin bytecode, or directory."
        ),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Directory for analysis reports."),
    ] = Path("reports"),
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: json or text."),
    ] = "text",
    detector: Annotated[
        str,
        typer.Option("--detector", "-d", help="Detector name filter (default: all)."),
    ] = "",
    bytecode_only: Annotated[
        bool,
        typer.Option("--bytecode-only", help="Skip source analysis, use bytecode only."),
    ] = False,
    solc_version: Annotated[
        str,
        typer.Option("--solc-version", help="Solidity compiler version."),
    ] = "0.8.28",
) -> None:
    """Run vulnerability scan on a Solidity contract or directory.

    Accepts:
      - A .sol source file
      - A directory of .sol files
      - A pre-compiled .json file (standard JSON output)
      - A .bin or .hex file (bytecode-only analysis)
    """
    from scanner.ast.analysis import analyze_source
    from scanner.bytecode.loader import extract_bytecode
    from scanner.compiler.solc import compile_source, load_compiler_output
    from scanner.detectors import DETECTOR_REGISTRY, get_all_detectors
    from scanner.models.findings import Finding
    from scanner.output.report import render_json, render_text, write_report

    # Ensure access control detector is registered
    import scanner.detectors.access_control  # noqa: F401

    if not target.exists():
        console.print(f"[red]Error: target not found: {target}[/red]")
        raise typer.Exit(1)

    # --- Gather targets ---
    sol_files: list[Path] = []
    json_files: list[Path] = []
    bin_files: list[Path] = []

    if target.is_dir():
        sol_files = list(target.glob("**/*.sol"))
        json_files = list(target.glob("**/*.json"))
    elif target.suffix == ".sol":
        sol_files = [target]
    elif target.suffix == ".json":
        json_files = [target]
    elif target.suffix in (".bin", ".hex"):
        bin_files = [target]
    else:
        console.print(
            f"[yellow]Warning: unknown file type {target.suffix}, treating as Solidity source[/yellow]"
        )
        sol_files = [target]

    # --- Select detectors ---
    all_detectors = get_all_detectors()
    if detector:
        selected = [cls for cls in all_detectors if cls.name == detector]
        if not selected:
            console.print(
                f"[red]Unknown detector: {detector}. "
                f"Available: {[d.name for d in all_detectors]}[/red]"
            )
            raise typer.Exit(1)
    else:
        selected = all_detectors

    detector_instances = [cls() for cls in selected]

    all_findings: list[Finding] = []

    # --- Process .sol files ---
    for sol_file in sol_files:
        console.print(f"Scanning [bold]{sol_file}[/bold]...")
        try:
            compiler_output = compile_source(sol_file, version=solc_version)
        except Exception as exc:
            console.print(f"  [red]Compilation failed: {exc}[/red]")
            continue

        if not bytecode_only:
            try:
                contracts = analyze_source(compiler_output)
                for det in detector_instances:
                    all_findings.extend(det.detect_from_source(contracts))
            except Exception as exc:
                console.print(f"  [yellow]Source analysis error: {exc}[/yellow]")

        try:
            bytecodes = extract_bytecode(compiler_output)
            for det in detector_instances:
                all_findings.extend(det.detect_from_bytecode(bytecodes))
        except Exception as exc:
            console.print(f"  [yellow]Bytecode analysis error: {exc}[/yellow]")

    # --- Process pre-compiled JSON files ---
    for json_file in json_files:
        console.print(f"Loading compiled JSON [bold]{json_file}[/bold]...")
        try:
            compiler_output = load_compiler_output(json_file)
        except Exception as exc:
            console.print(f"  [red]Failed to load: {exc}[/red]")
            continue

        if not bytecode_only:
            try:
                contracts = analyze_source(compiler_output)
                for det in detector_instances:
                    all_findings.extend(det.detect_from_source(contracts))
            except Exception as exc:
                console.print(f"  [yellow]Source analysis error: {exc}[/yellow]")

        try:
            bytecodes = extract_bytecode(compiler_output)
            for det in detector_instances:
                all_findings.extend(det.detect_from_bytecode(bytecodes))
        except Exception as exc:
            console.print(f"  [yellow]Bytecode analysis error: {exc}[/yellow]")

    # --- Process raw bytecode files ---
    for bin_file in bin_files:
        console.print(f"Analyzing bytecode [bold]{bin_file}[/bold]...")
        from scanner.bytecode.loader import ContractBytecode, load_bytecode_from_file

        hex_code = load_bytecode_from_file(bin_file)
        bc = ContractBytecode(
            contract_name=bin_file.stem,
            creation_bytecode="",
            deployed_bytecode=hex_code,
        )
        for det in detector_instances:
            all_findings.extend(det.detect_from_bytecode([bc]))

    # --- Deduplicate findings ---
    seen: set[tuple] = set()
    unique_findings: list[Finding] = []
    for f in all_findings:
        key = (f.detector, f.title, f.contract, f.function)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # --- Print summary ---
    if unique_findings:
        _print_findings_table(unique_findings)
    else:
        console.print("[green]No findings.[/green]")

    # --- Write report ---
    output.mkdir(parents=True, exist_ok=True)
    stem = target.stem if target.is_file() else target.name
    report_path = output / f"{stem}.{fmt}"
    write_report(unique_findings, report_path, fmt)
    console.print(f"\nReport written to [bold]{report_path}[/bold]")

    raise typer.Exit(0)


def _print_findings_table(findings) -> None:
    table = Table(title=f"Findings ({len(findings)})")
    table.add_column("Severity", style="bold")
    table.add_column("Title")
    table.add_column("Contract")
    table.add_column("Function")
    table.add_column("Confidence")

    severity_colors = {
        "critical": "bright_red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "cyan",
    }

    for f in findings:
        color = severity_colors.get(f.severity.value, "white")
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.title,
            f.contract,
            f.function,
            f.confidence,
        )
    console.print(table)


if __name__ == "__main__":
    app()
