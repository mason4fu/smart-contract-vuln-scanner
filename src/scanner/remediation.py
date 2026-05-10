"""Structured remediation templates for common scanner findings."""

from __future__ import annotations

from typing import Any


def tx_origin_plan() -> dict[str, Any]:
    return {
        "remediation": "Replace tx.origin with msg.sender for authorization checks.",
        "remediation_steps": [
            "Find the authorization branch that compares against tx.origin.",
            "Change the check to use msg.sender instead of tx.origin.",
            "Re-test privileged paths through direct calls and proxy-contract calls.",
        ],
        "secure_pattern": "Authorize with msg.sender, not tx.origin",
        "remediation_example": (
            "Replace `require(tx.origin == owner);` with "
            "`require(msg.sender == owner, \"not owner\");`."
        ),
    }


def missing_auth_plan(subject: str = "the sensitive function") -> dict[str, Any]:
    return {
        "remediation": "Add an onlyOwner modifier or require(msg.sender == owner) check.",
        "remediation_steps": [
            f"Identify the privileged action exposed by {subject}.",
            "Gate the entrypoint with onlyOwner, onlyRole, or an equivalent authorization check.",
            "Keep the sensitive state write or transfer behind that guard on every reachable path.",
        ],
        "secure_pattern": "Guard privileged entrypoints before sensitive actions",
        "remediation_example": (
            "Example:\n"
            "modifier onlyOwner() { require(msg.sender == owner, \"not owner\"); _; }\n"
            "function setTreasury(address next) external onlyOwner { treasury = next; }"
        ),
    }


def constructor_init_plan() -> dict[str, Any]:
    return {
        "remediation": (
            "Use the constructor keyword for one-time initialization or protect initializer "
            "functions so they cannot be called by arbitrary users."
        ),
        "remediation_steps": [
            "Convert legacy constructor-like setup logic to a real constructor when possible.",
            "If upgradeability requires an initializer, gate it and ensure it can run only once.",
            "Verify that ownership and role state cannot be reset after deployment.",
        ],
        "secure_pattern": "One-time constructor or guarded initializer",
        "remediation_example": (
            "Example:\n"
            "constructor() { owner = msg.sender; }\n"
            "// or\n"
            "function initialize() external onlyOwner { require(!initialized); initialized = true; }"
        ),
    }


def uninitialized_owner_plan() -> dict[str, Any]:
    return {
        "remediation": "Set owner = msg.sender in the constructor.",
        "remediation_steps": [
            "Initialize the owner-like variable during deployment or at declaration.",
            "Make sure later auth checks compare against a real privileged address.",
            "Add a regression test that owner-gated functions reject non-owners after deployment.",
        ],
        "secure_pattern": "Initialize auth state during deployment",
        "remediation_example": "constructor() { owner = msg.sender; }",
    }


def renounce_plan() -> dict[str, Any]:
    return {
        "remediation": "Use a two-step ownership transfer pattern with pendingOwner + acceptOwnership.",
        "remediation_steps": [
            "Avoid irreversible owner loss through a single public call.",
            "Introduce pendingOwner and acceptOwnership if ownership changes are allowed.",
            "Require explicit confirmation before privileges are dropped or transferred.",
        ],
        "secure_pattern": "Two-step ownership transfer",
        "remediation_example": (
            "Example:\n"
            "function transferOwnership(address next) external onlyOwner { pendingOwner = next; }\n"
            "function acceptOwnership() external { require(msg.sender == pendingOwner); owner = pendingOwner; }"
        ),
    }


def role_grant_plan() -> dict[str, Any]:
    return {
        "remediation": "Add an authorization guard to the role grant function.",
        "remediation_steps": [
            "Limit role updates to owner, admin, or role-admin callers.",
            "Separate self-service user flows from privileged role management.",
            "Test that arbitrary callers cannot grant themselves elevated permissions.",
        ],
        "secure_pattern": "Guard role writes with explicit admin checks",
        "remediation_example": (
            "Example:\n"
            "function grantRole(address user) external onlyOwner { admins[user] = true; }"
        ),
    }


def unchecked_call_plan(*, bytecode: bool = False) -> dict[str, Any]:
    summary = (
        "Ensure CALL-family success is checked before state changes or continuation."
        if bytecode
        else "Check the returned success boolean with require/assert or explicit if-failure handling before continuing."
    )
    return {
        "remediation": summary,
        "remediation_steps": [
            "Capture the success value returned by the low-level call or send operation.",
            "Abort or revert on failure before any follow-up state update or transfer continues.",
            "Avoid treating event emission or variable assignment alone as a failure gate.",
        ],
        "secure_pattern": "Gate continuation on low-level call success",
        "remediation_example": (
            "Example:\n"
            "(bool success, ) = target.call(data);\n"
            "require(success, \"call failed\");"
        ),
    }


def reentrancy_plan(*, bytecode: bool = False) -> dict[str, Any]:
    summary = (
        "Review external-call ordering and move state effects before interactions where possible."
        if bytecode
        else "Apply checks-effects-interactions: update state before the external call or add a reentrancy guard."
    )
    return {
        "remediation": summary,
        "remediation_steps": [
            "Move balance or privilege state updates before the external interaction when semantics allow.",
            "If the call must happen first, add a nonReentrant-style guard around the entrypoint.",
            "Re-test helper and modifier paths so no external call can re-enter before state is finalized.",
        ],
        "secure_pattern": "Checks-effects-interactions or explicit nonReentrant guard",
        "remediation_example": (
            "Example:\n"
            "balances[msg.sender] -= amount;\n"
            "(bool ok, ) = msg.sender.call{value: amount}(\"\");\n"
            "require(ok, \"transfer failed\");"
        ),
    }


def arithmetic_plan(*, bytecode: bool = False) -> dict[str, Any]:
    summary = (
        "Review source arithmetic around storage updates and ensure bounds checks or checked arithmetic semantics."
        if bytecode
        else "Use Solidity >=0.8 checked arithmetic or add explicit bounds checks before arithmetic updates."
    )
    return {
        "remediation": summary,
        "remediation_steps": [
            "Prefer Solidity 0.8+ checked arithmetic for state/accounting updates.",
            "If unchecked arithmetic is required, add explicit upper/lower bound checks first.",
            "Add tests around edge values such as zero, max uint, and repeated updates.",
        ],
        "secure_pattern": "Checked arithmetic or explicit bounds checks",
        "remediation_example": (
            "Example:\n"
            "require(balance + amount >= balance, \"overflow\");\n"
            "balance += amount;"
        ),
    }
