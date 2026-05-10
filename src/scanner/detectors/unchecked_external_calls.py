"""Unchecked low-level external call detector."""

from __future__ import annotations

from typing import Any

from scanner.ast.unchecked_calls import analyze_unchecked_external_calls
from scanner.bytecode.loader import ContractBytecode
from scanner.bytecode.unchecked_calls import analyze_unchecked_call_bytecode
from scanner.detectors import BaseDetector, register_detector
from scanner.models.findings import Finding, Severity
from scanner.models.ir import ContractInfo
from scanner.models.unchecked_calls import CallResultStatus, ExternalCallSite
from scanner.remediation import unchecked_call_plan

_DETECTOR_NAME = "unchecked-external-calls"
_REPORTABLE_SOURCE_STATUSES = {
    CallResultStatus.UNCHECKED,
    CallResultStatus.PROBABLY_UNCHECKED,
}
_REPORTABLE_BYTECODE_STATUSES = {
    CallResultStatus.UNCHECKED,
    CallResultStatus.PROBABLY_UNCHECKED,
    CallResultStatus.AMBIGUOUS,
}


@register_detector
class UncheckedExternalCallDetector(BaseDetector):
    """Detects unchecked success handling for Solidity low-level calls."""

    name = _DETECTOR_NAME
    description = (
        "Flags low-level call/delegatecall/staticcall/send results that are ignored, "
        "discarded, or not used to gate failure handling."
    )

    def detect_from_source(self, contracts: list[ContractInfo]) -> list[Finding]:
        return []

    def detect_from_compiler_output(self, compiler_output: dict[str, Any]) -> list[Finding]:
        sites = analyze_unchecked_external_calls(compiler_output)
        return [
            _finding_from_source_site(site)
            for site in sites
            if site.result_usage.status in _REPORTABLE_SOURCE_STATUSES
        ]

    def detect_from_bytecode(
        self,
        bytecodes: list[ContractBytecode],
        extra: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for bytecode in bytecodes:
            hex_code = bytecode.deployed_bytecode or bytecode.creation_bytecode
            for site in analyze_unchecked_call_bytecode(
                hex_code, contract_name=bytecode.contract_name
            ):
                if site.result_usage.status not in _REPORTABLE_BYTECODE_STATUSES:
                    continue
                findings.append(_finding_from_bytecode_site(site))
        return findings


def _finding_from_source_site(site: ExternalCallSite) -> Finding:
    status = site.result_usage.status
    title = (
        "Unchecked external call result"
        if status == CallResultStatus.UNCHECKED
        else "Probably unchecked external call result"
    )
    confidence = "high" if status == CallResultStatus.UNCHECKED else "medium"
    followup = _followup_summary(site)
    description = (
        f"Low-level .{site.call_kind.value}() in contract '{site.contract}' can fail "
        "without reverting automatically, but its success result is not meaningfully "
        f"checked. Evidence: {site.result_usage.evidence}."
    )
    if followup:
        description += f" Follow-up effects before a clear failure gate: {followup}."
    if site.snippet:
        description += f" Snippet: {site.snippet}"
    return Finding(
        detector=_DETECTOR_NAME,
        title=title,
        description=description,
        severity=Severity.MEDIUM,
        confidence=confidence,
        location=site.source_location,
        contract=site.contract,
        function=site.function,
        swc_id="SWC-104",
        **unchecked_call_plan(bytecode=False),
    )


def _finding_from_bytecode_site(site: ExternalCallSite) -> Finding:
    status = site.result_usage.status
    if status == CallResultStatus.UNCHECKED:
        title = "Unchecked external call result (bytecode)"
        confidence = "medium"
    elif status == CallResultStatus.PROBABLY_UNCHECKED:
        title = "Probably unchecked external call result (bytecode)"
        confidence = "low"
    else:
        title = "Ambiguous external call result handling (bytecode)"
        confidence = "low"

    pc = site.bytecode_pc if site.bytecode_pc is not None else 0
    description = (
        f"Runtime bytecode for contract '{site.contract}' contains {site.snippet} at pc {pc}. "
        f"Evidence: {site.result_usage.evidence}. Bytecode-only analysis is heuristic; "
        "review source or source maps to confirm whether the success result gates failure."
    )
    return Finding(
        detector=_DETECTOR_NAME,
        title=title,
        description=description,
        severity=Severity.MEDIUM if status != CallResultStatus.AMBIGUOUS else Severity.LOW,
        confidence=confidence,
        contract=site.contract,
        swc_id="SWC-104",
        **unchecked_call_plan(bytecode=True),
    )


def _followup_summary(site: ExternalCallSite) -> str:
    return ", ".join(effect.description or effect.kind for effect in site.followup_effects[:3])
