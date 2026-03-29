"""Rich panel-based CLI output for scanner findings."""
from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from scanner.models.findings import Finding, Severity

console = Console()

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "cyan",
}


def _get_source_snippet(source_text: str, line: int, context: int = 2) -> str:
    """Extract lines (line-context) to (line+context) from source text, with line numbers."""
    lines = source_text.splitlines()
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    result = []
    for i, ln in enumerate(lines[start:end], start=start + 1):
        prefix = ">>> " if i == line else "    "
        result.append(f"{prefix}{i:4d} | {ln}")
    return "\n".join(result)


def print_rich_findings(findings: list[Finding], source_texts: dict[str, str]) -> None:
    """Print findings as Rich panels with code snippets, severity badges, and remediation."""
    if not findings:
        console.print("[green]No findings.[/green]")
        return

    for finding in findings:
        color = _SEVERITY_COLORS.get(finding.severity, "white")

        # Panel title: severity badge + finding title
        title = Text()
        title.append(f" {finding.severity.value} ", style=f"bold {color} on {color}")
        title.append(f"  {finding.title}", style="bold white")

        # Build panel body
        lines = []
        lines.append(f"[bold]Contract:[/bold] {finding.contract}")
        if finding.function:
            lines.append(f"[bold]Function:[/bold] {finding.function}()")

        # Location
        loc_str = ""
        if finding.location:
            loc_str = finding.location.file
            if finding.location.line_start:
                loc_str += f":{finding.location.line_start}"
        if loc_str:
            lines.append(f"[bold]Location:[/bold] {loc_str}")

        lines.append("")
        lines.append(f"[dim]{finding.description}[/dim]")

        # Code snippet
        if (
            finding.location
            and finding.location.line_start
            and finding.location.file in source_texts
        ):
            src = source_texts[finding.location.file]
            snippet = _get_source_snippet(src, finding.location.line_start)
            if snippet:
                lines.append("")
                lines.append("[bold]Code:[/bold]")
                lines.append(snippet)

        # Remediation
        if finding.remediation:
            lines.append("")
            lines.append(f"[bold]Remediation:[/bold] {finding.remediation}")

        # SWC reference
        if finding.swc_id:
            lines.append(f"[bold]SWC:[/bold] {finding.swc_id}")

        body = "\n".join(lines)
        console.print(Panel(body, title=title, border_style=color, expand=False))

    # Summary section
    console.print()
    console.print(f"[bold]Total findings:[/bold] {len(findings)}")

    # Breakdown by severity
    sev_counts = Counter(f.severity.value for f in findings)
    sev_parts = ", ".join(f"{v} {k}" for k, v in sorted(sev_counts.items()))
    console.print(f"[bold]By severity:[/bold] {sev_parts}")

    # Breakdown by rule
    title_counts = Counter(f.title for f in findings)
    rule_parts = ", ".join(f"{v}x {t}" for t, v in title_counts.most_common())
    console.print(f"[bold]By rule:[/bold] {rule_parts}")
