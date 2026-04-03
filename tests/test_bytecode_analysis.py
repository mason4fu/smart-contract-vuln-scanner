"""Tests for bytecode-level access control analysis."""

from __future__ import annotations

from scanner.bytecode.analysis import (
    BytecodeAnalysis,
    analyze_bytecode,
    detect_caller_checks,
    detect_origin_usage,
)
from scanner.bytecode.disasm import disassemble
from scanner.bytecode.loader import extract_bytecode


def test_detect_origin_in_tx_origin_vuln(compiled_tx_origin_vuln):
    bytecodes = extract_bytecode(compiled_tx_origin_vuln)
    vuln = next(b for b in bytecodes if b.contract_name == "TxOriginVuln")
    hex_code = vuln.deployed_bytecode
    assert hex_code

    offsets = detect_origin_usage(disassemble(hex_code))
    assert len(offsets) >= 1, "Expected ORIGIN opcode in TxOriginVuln deployed bytecode"


def test_no_origin_in_safe_contract(compiled_safe_contract):
    bytecodes = extract_bytecode(compiled_safe_contract)
    safe = next(b for b in bytecodes if b.contract_name == "SafeContract")
    hex_code = safe.deployed_bytecode
    assert hex_code

    offsets = detect_origin_usage(disassemble(hex_code))
    assert len(offsets) == 0, "SafeContract should not use ORIGIN opcode"


def test_caller_checks_in_safe_contract(compiled_safe_contract):
    bytecodes = extract_bytecode(compiled_safe_contract)
    safe = next(b for b in bytecodes if b.contract_name == "SafeContract")
    hex_code = safe.deployed_bytecode
    assert hex_code

    checks = detect_caller_checks(disassemble(hex_code))
    assert len(checks) >= 1, "SafeContract should have CALLER-based auth checks"
    assert all(c.uses_caller for c in checks)


def test_analyze_bytecode_tx_origin_vuln(compiled_tx_origin_vuln):
    bytecodes = extract_bytecode(compiled_tx_origin_vuln)
    vuln = next(b for b in bytecodes if b.contract_name == "TxOriginVuln")

    result = analyze_bytecode(vuln.deployed_bytecode)
    assert isinstance(result, BytecodeAnalysis)
    assert result.has_origin


def test_analyze_bytecode_safe_contract(compiled_safe_contract):
    bytecodes = extract_bytecode(compiled_safe_contract)
    safe = next(b for b in bytecodes if b.contract_name == "SafeContract")

    result = analyze_bytecode(safe.deployed_bytecode)
    assert not result.has_origin
    assert len(result.caller_checks) >= 1


def test_extract_function_selectors(compiled_safe_contract):
    bytecodes = extract_bytecode(compiled_safe_contract)
    safe = next(b for b in bytecodes if b.contract_name == "SafeContract")

    result = analyze_bytecode(safe.deployed_bytecode)
    # SafeContract has 3 public/external functions + receive
    assert len(result.function_selectors) >= 2


def test_analyze_empty_bytecode():
    result = analyze_bytecode("")
    assert not result.has_origin
    assert result.origin_offsets == []
