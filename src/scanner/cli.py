"""CLI entrypoint for the vulnerability scanner.

Uses Typer for command-line argument parsing. Each future analysis
command will be registered as a sub-command here.
"""

from pathlib import Path

import typer

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
) -> None:
    """Run vulnerability scan on a Solidity contract.

    This is a placeholder command. Detectors will be registered here
    as they are implemented.
    """
    # TODO: Load configuration
    # TODO: Determine input type (source vs compiled JSON vs bytecode)
    # TODO: Run registered detectors
    # TODO: Collect and output results
    typer.echo(f"[placeholder] Would scan: {target}")
    typer.echo(f"[placeholder] Output dir: {output}")


if __name__ == "__main__":
    app()
