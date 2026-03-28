"""CLI entrypoint for the vulnerability scanner.

Uses Typer for command-line argument parsing. Each future analysis
command will be registered as a sub-command here.
"""

from pathlib import Path

import typer

from scanner.compiler.solc import compile_source, load_compiler_output
from scanner.config import load_config
from scanner.detectors import get_detectors
from scanner.models.findings import Finding
from scanner.output.report import write_report
from scanner.utils.paths import resolve_source

app = typer.Typer(
    name="scanner",
    help="Static analysis tool for Solidity smart contract vulnerabilities.",
    add_completion=False,
)


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
    target: Path = typer.Argument(..., help="Path to a Solidity file or compiled JSON."),
    output: Path = typer.Option(
        Path("reports"), "--output", "-o", help="Directory for analysis reports."
    ),
    fmt: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Report format: json or text.",
    ),
) -> None:
    """Run vulnerability scan on a Solidity contract.

    Compiles `.sol` sources (via py-solc-x) or loads a standard JSON compiler
    output from `.json`, runs registered detectors, and writes a report.
    """
    cfg = load_config()
    path = resolve_source(target)
    if not path.is_file():
        typer.echo(f"Not found: {path}", err=True)
        raise typer.Exit(code=1)

    suffix = path.suffix.lower()
    if suffix == ".sol":
        compiler_output = compile_source(path, version=cfg.solc_version)
    elif suffix == ".json":
        compiler_output = load_compiler_output(path)
    else:
        typer.echo("Target must be a .sol file or compiler output .json.", err=True)
        raise typer.Exit(code=1)

    findings: list[Finding] = []
    for detector_fn in get_detectors().values():
        findings.extend(detector_fn(compiler_output))

    if fmt not in {"json", "text"}:
        typer.echo("Unsupported --format (use json or text).", err=True)
        raise typer.Exit(code=1)

    output.mkdir(parents=True, exist_ok=True)
    dest = output / ("scan.json" if fmt == "json" else "scan.txt")
    write_report(findings, dest, fmt=fmt)
    typer.echo(f"Wrote {len(findings)} finding(s) to {dest}")


if __name__ == "__main__":
    app()
