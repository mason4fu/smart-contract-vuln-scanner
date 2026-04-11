"""CLI entrypoint for the vulnerability scanner.

Uses Typer for command-line argument parsing. Sub-commands:
  scan    - Run detectors on a Solidity file, directory, or bytecode
"""

from __future__ import annotations

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

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _deduplicate_findings(all_findings):
    """Deduplicate findings by detector/title/contract/function tuple."""
    seen: set[tuple] = set()
    unique_findings = []
    for finding in all_findings:
        key = (finding.detector, finding.title, finding.contract, finding.function)
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    return unique_findings


def _suppress_bytecode_duplicates(unique_findings):
    """Prefer source findings over bytecode hints for the same contract+SWC."""
    source_swc_keys = {
        (finding.contract, finding.swc_id)
        for finding in unique_findings
        if finding.location is not None and finding.contract and finding.swc_id
    }
    return [
        finding
        for finding in unique_findings
        if not (
            "(bytecode)" in finding.title.lower()
            and finding.contract
            and finding.swc_id
            and (finding.contract, finding.swc_id) in source_swc_keys
        )
    ]


def _resolve_min_confidence(min_confidence: str, cfg, strict_access_control: bool) -> str:
    effective_min_conf = min_confidence.lower() if min_confidence else cfg.min_confidence.lower()
    if strict_access_control or cfg.strict_access_control:
        return "high"
    return effective_min_conf


def _filter_by_confidence(unique_findings, min_confidence: str):
    threshold = _CONFIDENCE_RANK[min_confidence]
    return [
        finding
        for finding in unique_findings
        if _CONFIDENCE_RANK.get(str(finding.confidence).lower(), 0) >= threshold
    ]


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
        typer.Argument(help="Solidity file, compiled JSON, .bin bytecode, or directory."),
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
    min_confidence: Annotated[
        str,
        typer.Option(
            "--min-confidence",
            help="Minimum confidence to report: low, medium, high.",
        ),
    ] = "",
    strict_access_control: Annotated[
        bool,
        typer.Option(
            "--strict-access-control",
            help="Prefer high-confidence access-control findings.",
        ),
    ] = False,
) -> None:
    """Run vulnerability scan on a Solidity contract or directory.

    Accepts:
      - A .sol source file
      - A directory of .sol files
      - A pre-compiled .json file (standard JSON output)
      - A .bin or .hex file (bytecode-only analysis)
    """
    # Ensure detectors are registered with the class registry
    import scanner.detectors.access_control  # noqa: F401
    import scanner.detectors.reentrancy  # noqa: F401
    from scanner.ast.analysis import analyze_source
    from scanner.bytecode.loader import extract_bytecode
    from scanner.compiler.solc import compile_source, load_compiler_output
    from scanner.config import load_config
    from scanner.detectors import get_all_detectors
    from scanner.models.findings import Finding
    from scanner.output.report import write_report
    from scanner.output.rich_report import print_rich_findings

    cfg = load_config(
        output_dir=output,
        solc_version=solc_version,
        min_confidence=min_confidence or "low",
        strict_access_control=strict_access_control,
    )

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
            f"[yellow]Warning: unknown file type {target.suffix}, "
            "treating as Solidity source[/yellow]"
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
    source_texts: dict[str, str] = {}

    # --- Process .sol files ---
    for sol_file in sol_files:
        console.print(f"Scanning [bold]{sol_file}[/bold]...")
        try:
            compiler_output = compile_source(sol_file, version=solc_version)
            # Store source text keyed by filename (matches finding.location.file)
            source_texts[sol_file.name] = sol_file.read_text(encoding="utf-8")
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
                for det in detector_instances:
                    all_findings.extend(det.detect_from_compiler_output(compiler_output))
            except Exception as exc:
                console.print(f"  [yellow]Compiler-output detection error: {exc}[/yellow]")

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
                for det in detector_instances:
                    all_findings.extend(det.detect_from_compiler_output(compiler_output))
            except Exception as exc:
                console.print(f"  [yellow]Compiler-output detection error: {exc}[/yellow]")

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

    # --- Deduplicate and filter findings ---
    unique_findings = _deduplicate_findings(all_findings)
    unique_findings = _suppress_bytecode_duplicates(unique_findings)

    effective_min_conf = _resolve_min_confidence(min_confidence, cfg, strict_access_control)
    if effective_min_conf not in _CONFIDENCE_RANK:
        console.print(
            f"[red]Invalid --min-confidence '{effective_min_conf}'. "
            "Expected one of: low, medium, high.[/red]"
        )
        raise typer.Exit(1)

    unique_findings = _filter_by_confidence(unique_findings, effective_min_conf)

    # --- Print summary ---
    print_rich_findings(unique_findings, source_texts)

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
