"""Access control vulnerability detector.

Implements five detection rules:
1. tx.origin used for authorization (SWC-115)
2. Sensitive public/external functions with no authorization guard (SWC-105/106)
3. Uninitialized owner variable (never set in constructor or declaration)
4. Dangerous renounceOwnership without two-step transfer
5. Unguarded role grant (public function writes to role mapping without auth)
"""

from __future__ import annotations

import re
from typing import Any

from scanner.bytecode.analysis import analyze_bytecode
from scanner.bytecode.loader import ContractBytecode
from scanner.detectors import BaseDetector, register_detector
from scanner.models.findings import Finding, Severity
from scanner.models.ir import ContractInfo

_DETECTOR_NAME = "access-control"


@register_detector
class AccessControlDetector(BaseDetector):
    """Detects access control flaws in Solidity contracts."""

    name = _DETECTOR_NAME
    description = (
        "Detects tx.origin-based authorization (SWC-115), "
        "missing authorization guards on sensitive functions (SWC-105/106), "
        "uninitialized owner variables, dangerous renounceOwnership, "
        "and unguarded role grants."
    )

    def detect_from_source(self, contracts: list[ContractInfo]) -> list[Finding]:
        """Run source-level detection on extracted IR.

        Args:
            contracts: List of ContractInfo from AST analysis.

        Returns:
            List of findings.
        """
        findings: list[Finding] = []
        for contract in contracts:
            findings.extend(_check_tx_origin_source(contract))
            findings.extend(_check_missing_auth_source(contract))
            findings.extend(_check_uninitialized_owner(contract))
            findings.extend(_check_renounce_ownership(contract))
            findings.extend(_check_unguarded_role_grant(contract))
        return findings

    def detect_from_bytecode(
        self,
        bytecodes: list[ContractBytecode],
        extra: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Run bytecode-level detection as a fallback.

        Args:
            bytecodes: List of ContractBytecode from bytecode extraction.
            extra: Optional additional context (unused for now).

        Returns:
            List of findings (lower confidence than source analysis).
        """
        findings: list[Finding] = []
        for bc in bytecodes:
            hex_code = bc.deployed_bytecode or bc.creation_bytecode
            if not hex_code:
                continue
            analysis = analyze_bytecode(hex_code)
            if analysis.has_origin:
                findings.append(
                    Finding(
                        detector=_DETECTOR_NAME,
                        title="tx.origin used (bytecode)",
                        description=(
                            f"Contract '{bc.contract_name}' deployed bytecode contains the "
                            "ORIGIN opcode. This likely indicates tx.origin is used for "
                            "authorization, which is vulnerable to phishing attacks (SWC-115). "
                            "Review source code for require(tx.origin == ...) patterns."
                        ),
                        severity=Severity.HIGH,
                        confidence="medium",
                        contract=bc.contract_name,
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Internal rule implementations
# ---------------------------------------------------------------------------


def _check_tx_origin_source(contract: ContractInfo) -> list[Finding]:
    """Rule 1: tx.origin used for authorization (SWC-115)."""
    findings: list[Finding] = []
    for func in contract.functions:
        # Check inline auth checks that use tx.origin
        for ac in func.auth_checks:
            if ac.uses_tx_origin:
                findings.append(
                    Finding(
                        detector=_DETECTOR_NAME,
                        title="tx.origin used for authorization",
                        description=(
                            f"Function '{func.name}' in contract '{contract.name}' "
                            "uses tx.origin for an authorization check. "
                            "tx.origin refers to the original external account that "
                            "initiated the transaction and is vulnerable to phishing attacks "
                            "via malicious contracts. Use msg.sender instead. (SWC-115)"
                        ),
                        severity=Severity.HIGH,
                        confidence="high",
                        location=ac.source_location or func.source_location,
                        contract=contract.name,
                        function=func.name,
                    )
                )
        # Also check if tx.origin appears anywhere in the function body
        # (not just in a require — could be used in an if statement)
        if func.uses_tx_origin and not any(ac.uses_tx_origin for ac in func.auth_checks):
            findings.append(
                Finding(
                    detector=_DETECTOR_NAME,
                    title="tx.origin used for authorization",
                    description=(
                        f"Function '{func.name}' in contract '{contract.name}' "
                        "references tx.origin, which is vulnerable to phishing attacks. "
                        "Use msg.sender for authorization checks instead. (SWC-115)"
                    ),
                    severity=Severity.HIGH,
                    confidence="medium",
                    location=func.source_location,
                    contract=contract.name,
                    function=func.name,
                )
            )
    return findings


def _check_missing_auth_source(contract: ContractInfo) -> list[Finding]:
    """Rule 2: Sensitive externally callable function with no auth guard (SWC-105/106)."""
    findings: list[Finding] = []
    for func in contract.functions:
        # Skip non-externally-callable functions
        if func.visibility not in ("public", "external"):
            continue
        # Skip view/pure (read-only, not sensitive state-change)
        if func.state_mutability in ("pure", "view"):
            continue
        # Skip constructors, fallback, receive
        if func.is_constructor or func.is_fallback or func.is_receive:
            continue
        # Skip if already guarded
        if func.has_auth_guard:
            continue
        # Only flag if there are sensitive actions
        if not func.sensitive_actions:
            continue

        action_descs = ", ".join(a.description or a.kind for a in func.sensitive_actions[:3])
        findings.append(
            Finding(
                detector=_DETECTOR_NAME,
                title="Missing authorization on sensitive function",
                description=(
                    f"Function '{func.name}' in contract '{contract.name}' is publicly "
                    "callable but has no detected authorization guard (no onlyOwner modifier, "
                    f"no require(msg.sender == ...) check). Sensitive actions: {action_descs}. "
                    "Any caller can invoke this function. (SWC-105)"
                ),
                severity=Severity.HIGH,
                confidence="medium",
                location=func.source_location,
                contract=contract.name,
                function=func.name,
            )
        )
    return findings


_OWNER_VAR_RE = re.compile(
    r"(?i)\b(owner|admin|governance|authority|controller|manager)\b"
)


def _check_uninitialized_owner(contract: ContractInfo) -> list[Finding]:
    """Rule 3: Owner-like state variable exists but is never initialized (SWC-unset-owner)."""
    findings: list[Finding] = []
    # Only flag concrete contracts that actually have owner-pattern and functions
    if not contract.has_owner_pattern:
        return findings
    if not contract.functions:
        return findings
    # Find owner-like state variables
    owner_vars = [v for v in contract.state_variables if _OWNER_VAR_RE.search(v)]
    if not owner_vars:
        return findings
    if not contract.owner_initialized_in_constructor:
        findings.append(
            Finding(
                detector=_DETECTOR_NAME,
                title="Uninitialized owner variable",
                description=(
                    f"Contract '{contract.name}' declares owner-like variable(s) "
                    f"{owner_vars} but never initializes them in the constructor or "
                    "at declaration. Any authentication check against this variable "
                    "will compare against address(0), effectively disabling access control."
                ),
                severity=Severity.MEDIUM,
                confidence="medium",
                contract=contract.name,
            )
        )
    return findings


def _check_renounce_ownership(contract: ContractInfo) -> list[Finding]:
    """Rule 4: renounceOwnership without a two-step transfer safety net."""
    findings: list[Finding] = []
    has_renounce = any("renounce" in f.name.lower() for f in contract.functions)
    if not has_renounce:
        return findings
    has_accept = any("acceptownership" in f.name.lower() for f in contract.functions)
    has_pending_owner = any("pendingowner" in v.lower() for v in contract.state_variables)
    if not has_accept and not has_pending_owner:
        renounce_func = next(f for f in contract.functions if "renounce" in f.name.lower())
        findings.append(
            Finding(
                detector=_DETECTOR_NAME,
                title="Dangerous renounceOwnership without two-step transfer",
                description=(
                    f"Contract '{contract.name}' exposes '{renounce_func.name}' which "
                    "permanently removes the owner without a two-step (pendingOwner / "
                    "acceptOwnership) safety mechanism. A mistaken call will lock all "
                    "owner-gated functions forever."
                ),
                severity=Severity.LOW,
                confidence="medium",
                location=renounce_func.source_location,
                contract=contract.name,
                function=renounce_func.name,
            )
        )
    return findings


def _check_unguarded_role_grant(contract: ContractInfo) -> list[Finding]:
    """Rule 5: Public/external function grants a role without any auth guard."""
    findings: list[Finding] = []
    for func in contract.functions:
        if func.visibility not in ("public", "external"):
            continue
        if func.is_constructor or func.is_fallback or func.is_receive:
            continue
        if func.has_auth_guard:
            continue
        role_grants = [a for a in func.sensitive_actions if a.kind == "role_grant"]
        if role_grants:
            grant_descs = ", ".join(a.description or a.kind for a in role_grants[:3])
            findings.append(
                Finding(
                    detector=_DETECTOR_NAME,
                    title="Unguarded role grant",
                    description=(
                        f"Function '{func.name}' in contract '{contract.name}' grants "
                        "roles or writes to an access-control mapping without any "
                        f"authorization check. Actions: {grant_descs}. "
                        "Any caller can escalate their own privileges."
                    ),
                    severity=Severity.HIGH,
                    confidence="medium",
                    location=func.source_location,
                    contract=contract.name,
                    function=func.name,
                )
            )
    return findings
