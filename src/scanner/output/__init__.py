"""Output formatting and report generation.

Handles rendering scan results into different formats
(JSON, text, markdown) and writing reports to disk.
"""

from scanner.output.report import render_json, render_text

__all__ = ["render_json", "render_text"]
