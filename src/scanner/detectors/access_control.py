"""Access control vulnerability detector.

Implements six detection rules:
1. tx.origin used for authorization (SWC-115)
2. Wrong constructor / unprotected initializer exposure (SWC-118)
3. Sensitive public/external functions with no authorization guard (SWC-105/106)
4. Uninitialized owner variable (never set in constructor or declaration)
5. Dangerous renounceOwnership without two-step transfer
6. Unguarded role grant (public function writes to role mapping without auth)
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

_PRIVILEGED_ACTION_KINDS: frozenset[str] = frozenset(
    {
        "owner_change",
        "role_grant",
        "role_revoke",
        "pause",
        "unpause",
        "upgrade",
        "config_set",
        "selfdestruct",
        "delegatecall",
    }
)
_TRANSFER_ACTION_KINDS: frozenset[str] = frozenset({"eth_transfer", "token_transfer"})
_HIGH_CONF_NAME_HINTS = re.compile(
    r"(owner|admin|role|governance|authority|controller|manager|minter|pauser|"
    r"operator|creator|root|upgrade|migrate|pause|unpause|grant|revoke|kill|"
    r"destroy|selfdestruct|renounce)",
    re.IGNORECASE,
)
_USER_FLOW_NAME_HINTS = re.compile(
    r"(deposit|withdraw|claim|buy|sell|redeem|stake|unstake|swap|mint|burn|transfer)",
    re.IGNORECASE,
)
_MUTATION_NAME_HINTS = re.compile(
    r"(set|write|update|push|pop|append|remove|delete|clear|init)",
    re.IGNORECASE,
)


@register_detector
class AccessControlDetector(BaseDetector):
    """Detects access control flaws in Solidity contracts."""

    name = _DETECTOR_NAME
    description = (
        "Detects tx.origin-based authorization (SWC-115), "
        "wrong constructor exposure (SWC-118), "
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
            tx_origin = _check_tx_origin_source(contract)
            wrong_constructor = _check_wrong_constructor_surface(contract)
            admin_surface = _check_admin_surface_mutation(contract)
            missing_auth = _check_missing_auth_source(contract)
            role_grants = _check_unguarded_role_grant(contract)

            # Prefer constructor-specific findings over generic admin-surface findings.
            constructor_funcs = _finding_functions(wrong_constructor)
            admin_surface = _exclude_function_findings(admin_surface, constructor_funcs)

            # Prefer specific role-grant findings over generic missing-auth for the same function.
            specific_funcs = _finding_functions(role_grants + admin_surface + wrong_constructor)
            missing_auth = _exclude_function_findings(missing_auth, specific_funcs)

            findings.extend(tx_origin)
            findings.extend(wrong_constructor)
            findings.extend(admin_surface)
            findings.extend(missing_auth)
            findings.extend(_check_uninitialized_owner(contract))
            findings.extend(_check_renounce_ownership(contract))
            findings.extend(role_grants)
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
                        severity=Severity.MEDIUM,
                        confidence="low",
                        contract=bc.contract_name,
                        swc_id="SWC-115",
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
        if func.state_mutability in ("view", "pure"):
            continue
        auth_tx_origin_checks = [ac for ac in func.auth_checks if ac.uses_tx_origin]
        if auth_tx_origin_checks:
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
                    location=auth_tx_origin_checks[0].source_location or func.source_location,
                    contract=contract.name,
                    function=func.name,
                    swc_id="SWC-115",
                    remediation="Replace tx.origin with msg.sender for authorization checks.",
                )
            )
            continue

        # Also check if tx.origin appears anywhere in the function body
        # (not just in a require — could be used in an if statement)
        if func.uses_tx_origin:
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
                    swc_id="SWC-115",
                    remediation="Replace tx.origin with msg.sender for authorization checks.",
                )
            )
    return findings


def _check_missing_auth_source(contract: ContractInfo) -> list[Finding]:
    """Rule 2: Sensitive externally callable function with no auth guard (SWC-105/106)."""
    findings: list[Finding] = []
    for func in _iter_unguarded_callable_functions(contract):
        if func.state_mutability in ("pure", "view"):
            continue
        # Only flag if there are sensitive actions
        if not func.sensitive_actions:
            continue

        severity, confidence = _classify_missing_auth_risk(contract, func)
        if severity is None:
            continue

        action_descs = ", ".join(a.description or a.kind for a in func.sensitive_actions[:3])
        action_loc = _first_action_location(func.sensitive_actions, func.source_location)
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
                severity=severity,
                confidence=confidence,
                location=action_loc or func.source_location,
                contract=contract.name,
                function=func.name,
                swc_id="SWC-105",
                remediation="Add an onlyOwner modifier or require(msg.sender == owner) check.",
            )
        )
    return findings


def _check_wrong_constructor_surface(contract: ContractInfo) -> list[Finding]:
    """Rule 2: Callable constructor-like initializer mutates ownership (SWC-118)."""
    findings: list[Finding] = []

    for func in _iter_unguarded_callable_functions(contract):
        if not func.is_constructor_candidate:
            continue

        owner_mutations = _sensitive_actions_of_kind(func, "owner_change")
        if not owner_mutations:
            continue

        exact_name = func.name.lower() == contract.name.lower()
        confidence = "high" if exact_name else "medium"
        severity = Severity.HIGH if exact_name else Severity.MEDIUM

        findings.append(
            Finding(
                detector=_DETECTOR_NAME,
                title="Callable constructor-like initializer",
                description=(
                    f"Function '{func.name}' in contract '{contract.name}' looks like constructor "
                    "or initialization logic, is externally callable, and mutates ownership state "
                    "without an authorization guard. This can allow ownership takeover or unsafe "
                    "re-initialization. (SWC-118)"
                ),
                severity=severity,
                confidence=confidence,
                location=owner_mutations[0].source_location or func.source_location,
                contract=contract.name,
                function=func.name,
                swc_id="SWC-118",
                remediation=(
                    "Use the constructor keyword for one-time initialization "
                    "or protect initializer "
                    "functions so they cannot be called by arbitrary users."
                ),
            )
        )

    return findings


def _check_admin_surface_mutation(contract: ContractInfo) -> list[Finding]:
    """Rule: externally callable owner/admin/role surface mutation without auth."""
    findings: list[Finding] = []
    for func in _iter_unguarded_callable_functions(contract):
        admin_actions = _sensitive_actions_of_kind(func, "owner_change")
        if not admin_actions:
            continue

        findings.append(
            Finding(
                detector=_DETECTOR_NAME,
                title="Unguarded admin-surface mutation",
                description=(
                    f"Function '{func.name}' in contract '{contract.name}' mutates owner/admin "
                    "control state without any authorization guard. This directly exposes "
                    "privilege control to arbitrary callers. (SWC-105)"
                ),
                severity=Severity.HIGH,
                confidence="high",
                location=admin_actions[0].source_location or func.source_location,
                contract=contract.name,
                function=func.name,
                swc_id="SWC-105",
                remediation="Protect admin-surface state mutation with owner/role authorization.",
            )
        )
    return findings


_OWNER_VAR_RE = re.compile(
    r"(?i)\b(owner|admin|governance|authority|controller|manager|creator|root)\b"
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
                swc_id="SWC-105",
                remediation="Set owner = msg.sender in the constructor.",
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
                swc_id="SWC-106",
                remediation=(
                    "Use a two-step ownership transfer pattern with pendingOwner + acceptOwnership."
                ),
            )
        )
    return findings


def _check_unguarded_role_grant(contract: ContractInfo) -> list[Finding]:
    """Rule 5: Public/external function grants a role without any auth guard."""
    findings: list[Finding] = []
    for func in _iter_unguarded_callable_functions(contract):
        role_grants = _sensitive_actions_of_kind(func, "role_grant")
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
                    swc_id="SWC-105",
                    remediation="Add an authorization guard to the role grant function.",
                )
            )
    return findings


def _score_missing_auth_signal(contract: ContractInfo, func: Any) -> tuple[str, bool]:
    """Return (confidence, should_report) for missing-auth findings."""
    action_kinds = {a.kind for a in func.sensitive_actions}

    if action_kinds.intersection(_PRIVILEGED_ACTION_KINDS):
        return "high", True

    has_transfer = bool(action_kinds.intersection(_TRANSFER_ACTION_KINDS))
    if has_transfer:
        if _has_inverted_sender_balance_guard(func):
            return "high", True
        has_sender_flow_check = bool(func.extra.get("has_sender_flow_check", False))
        if _USER_FLOW_NAME_HINTS.search(func.name) and has_sender_flow_check:
            return "low", False
        if _HIGH_CONF_NAME_HINTS.search(func.name):
            return "high", True
        if contract.has_owner_pattern and not _USER_FLOW_NAME_HINTS.search(func.name):
            return "medium", True
        return "low", True

    if "state_mutation" in action_kinds:
        if _HIGH_CONF_NAME_HINTS.search(func.name):
            return "medium", True
        if not contract.has_owner_pattern:
            return "low", False
        if _MUTATION_NAME_HINTS.search(func.name):
            return "low", True
        return "low", False

    return "low", False


def _has_inverted_sender_balance_guard(func: Any) -> bool:
    """Return True when a transfer function uses a reversed sender-balance check."""
    for auth_check in func.auth_checks:
        if not auth_check.uses_msg_sender:
            continue
        if not auth_check.comparison_operator:
            continue
        if (
            auth_check.comparison_left_uses_sender_scoped_state
            and auth_check.comparison_operator in ("<", "<=")
        ):
            return True
        if (
            auth_check.comparison_right_uses_sender_scoped_state
            and auth_check.comparison_operator in (">", ">=")
        ):
            return True
    return False


def _classify_missing_auth_risk(contract: ContractInfo, func: Any) -> tuple[Severity | None, str]:
    """Classify missing-auth findings to avoid over-reporting non-admin user flows."""
    action_kinds = {a.kind for a in func.sensitive_actions}
    confidence, should_report = _score_missing_auth_signal(contract, func)
    if not should_report:
        return None, confidence

    if action_kinds.intersection(_PRIVILEGED_ACTION_KINDS):
        return Severity.HIGH, confidence

    if action_kinds.intersection(_TRANSFER_ACTION_KINDS):
        if confidence == "high":
            return Severity.HIGH, confidence
        return Severity.MEDIUM, confidence

    if "state_mutation" in action_kinds:
        if confidence == "medium":
            return Severity.MEDIUM, confidence
        return Severity.LOW, confidence

    return None, confidence


def _is_externally_callable(func: Any) -> bool:
    return func.visibility in ("public", "external")


def _is_non_callable_special(func: Any) -> bool:
    return bool(func.is_constructor or func.is_fallback or func.is_receive)


def _iter_unguarded_callable_functions(contract: ContractInfo) -> list[Any]:
    if not _is_concrete_contract(contract):
        return []
    return [
        func
        for func in contract.functions
        if _is_externally_callable(func)
        and not _is_non_callable_special(func)
        and not func.has_auth_guard
    ]


def _sensitive_actions_of_kind(func: Any, kind: str) -> list[Any]:
    return [action for action in func.sensitive_actions if action.kind == kind]


def _first_action_location(actions: list[Any], fallback: Any) -> Any:
    return next((action.source_location for action in actions if action.source_location), fallback)


def _finding_functions(findings: list[Finding]) -> set[str]:
    return {finding.function for finding in findings if finding.function}


def _exclude_function_findings(
    findings: list[Finding], excluded_functions: set[str]
) -> list[Finding]:
    if not excluded_functions:
        return findings
    return [
        finding
        for finding in findings
        if not finding.function or finding.function not in excluded_functions
    ]


def _is_concrete_contract(contract: ContractInfo) -> bool:
    return contract.kind not in ("interface", "abstract")
