#!/usr/bin/env python3
"""
eip712dsa/test_audit.py — unit tests for the EIP-712 auditor.
Run: python3 tests/test_audit.py
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
from audit import (
    audit, extract_string_literals, find_selectors, find_basic_blocks,
    has_opcode_near, _iter_opcodes,
    EIP712_TYPEHASH_4FIELD, EIP712_TYPEHASH_5FIELD,
    SEL_DOMAIN_SEPARATOR, SEL_PERMIT, SEL_NAME,
    ADDRESS, CHAINID, JUMPDEST, RETURN, STOP, JUMPI, REVERT,
)  # noqa


# ----- helpers: build tiny synthetic bytecodes -----

def hex_of(s: str) -> bytes:
    return s.encode("ascii")

def PUSH1(v: int) -> bytes:
    return bytes([0x60, v])

def PUSH4(v: int) -> bytes:
    return bytes([0x63]) + v.to_bytes(4, "big")

def JUMPDEST() -> bytes:
    return bytes([0x5b])

def RETURN_() -> bytes:
    return bytes([RETURN])

def function_body(*parts) -> bytes:
    return JUMPDEST() + b"".join(parts) + RETURN_()


# ============== tests ==============

def test_extract_string_literal_eip712():
    """The 82-byte EIP712Domain type-hash string should be extractable, even when split
    across multiple PUSH-N opcodes (which is how Solidity emits long string literals)."""
    s = EIP712_TYPEHASH_4FIELD.encode("ascii")
    assert len(s) == 82
    bc = (
        bytes([0x7f]) + s[0:32]      # PUSH32 first 32 bytes
        + bytes([0x7f]) + s[32:64]   # PUSH32 next 32 bytes
        + bytes([0x71]) + s[64:82]   # PUSH18 last 18 bytes (0x71 = 0x5f + 18)
    )
    literals = extract_string_literals(bc)
    found = [x for _, x in literals if x == EIP712_TYPEHASH_4FIELD]
    assert found, f"type-hash literal not extracted from PUSH-split form; got: {literals}"
    print("  ✓ test_extract_string_literal_eip712")


def test_extract_skips_non_printable_push():
    """A PUSH-N whose payload contains non-printable bytes should NOT be extracted."""
    # PUSH4 0xDEADBEEF — all non-printable
    bc = JUMPDEST() + bytes([0x63]) + b"\xde\xad\xbe\xef" + RETURN_()
    literals = extract_string_literals(bc)
    assert all(not s.startswith("\xde") for _, s in literals), f"non-printable PUSH wrongly extracted: {literals}"
    print("  ✓ test_extract_skips_non_printable_push")


def test_extract_5field_literal():
    """The 5-field EIP712Domain type-hash (with salt) should also be extractable."""
    s = EIP712_TYPEHASH_5FIELD.encode("ascii")
    assert len(s) == 95
    bc = (
        bytes([0x7f]) + s[0:32]
        + bytes([0x7f]) + s[32:64]
        + bytes([0x7e]) + s[64:95]   # PUSH31 last 31 bytes (0x7e = 0x5f + 31)
    )
    literals = extract_string_literals(bc)
    found = [x for _, x in literals if x.startswith(EIP712_TYPEHASH_5FIELD[:50])]
    assert found, f"5-field type-hash not extracted; got: {literals}"
    print("  ✓ test_extract_5field_literal")


def test_find_selectors():
    """Selectors should be found in the bytecode."""
    # Build a function with PUSH4(0x3644e515) somewhere
    bc = JUMPDEST() + PUSH4(int(SEL_DOMAIN_SEPARATOR, 16)) + RETURN_()
    sels = find_selectors(bc)
    assert SEL_DOMAIN_SEPARATOR in sels, f"DOMAIN_SEPARATOR selector not found; got: {list(sels.keys())}"
    print("  ✓ test_find_selectors")


def test_basic_blocks():
    """find_basic_blocks should partition the bytecode into ranges."""
    code = JUMPDEST() + RETURN_() + bytes([STOP]) + JUMPDEST() + RETURN_()
    blocks = find_basic_blocks(code)
    assert len(blocks) == 2, f"expected 2 blocks, got {len(blocks)}"
    print("  ✓ test_basic_blocks")


def test_audit_4field_correct():
    """A 4-field EIP-712 implementation with CHAINID + ADDRESS should pass checks 1, 4, 5, 6."""
    s = EIP712_TYPEHASH_4FIELD.encode("ascii")
    typehash_pushed = (
        bytes([0x7f]) + s[0:32]
        + bytes([0x7f]) + s[32:64]
        + bytes([0x71]) + s[64:82]
    )
    bc = (
        # A function with selector 0x3644e515 + CHAINID + ADDRESS
        b"\x36\x44\xe5\x15"
        + bytes([CHAINID])
        + bytes([ADDRESS])
        + RETURN_()
        # The type-hash literal
        + typehash_pushed
    )
    result = audit("0x" + bc.hex(), contract="0xtest")
    c1 = next(c for c in result["checks"] if c["id"] == 1)
    assert c1["verdict"] == "PASS", f"check 1 should PASS, got {c1['verdict']}: {c1['evidence']}"
    c6 = next(c for c in result["checks"] if c["id"] == 6)
    assert c6["verdict"] == "PASS", f"check 6 should PASS, got {c6['verdict']}: {c6['evidence']}"
    c4 = next(c for c in result["checks"] if c["id"] == 4)
    assert c4["verdict"] == "PASS", f"check 4 should PASS, got {c4['verdict']}: {c4['evidence']}"
    c5 = next(c for c in result["checks"] if c["id"] == 5)
    assert c5["verdict"] == "PASS", f"check 5 should PASS, got {c5['verdict']}: {c5['evidence']}"
    print("  ✓ test_audit_4field_correct")


def test_audit_missing_chainid():
    """A contract without CHAINID should FAIL check 4."""
    s = EIP712_TYPEHASH_4FIELD.encode("ascii")
    typehash_pushed = (
        bytes([0x7f]) + s[0:32]
        + bytes([0x7f]) + s[32:64]
        + bytes([0x71]) + s[64:82]
    )
    bc = (
        b"\x36\x44\xe5\x15"
        + RETURN_()
        + typehash_pushed
    )
    result = audit("0x" + bc.hex(), contract="0xtest")
    c4 = next(c for c in result["checks"] if c["id"] == 4)
    assert c4["verdict"] == "FAIL", f"check 4 should FAIL, got {c4['verdict']}: {c4['evidence']}"
    print("  ✓ test_audit_missing_chainid")


def test_audit_missing_address():
    """A contract without ADDRESS should FAIL check 5."""
    s = EIP712_TYPEHASH_4FIELD.encode("ascii")
    typehash_pushed = (
        bytes([0x7f]) + s[0:32]
        + bytes([0x7f]) + s[32:64]
        + bytes([0x71]) + s[64:82]
    )
    bc = (
        b"\x36\x44\xe5\x15"
        + bytes([CHAINID])
        + RETURN_()
        + typehash_pushed
    )
    result = audit("0x" + bc.hex(), contract="0xtest")
    c5 = next(c for c in result["checks"] if c["id"] == 5)
    assert c5["verdict"] == "FAIL", f"check 5 should FAIL, got {c5['verdict']}: {c5['evidence']}"
    print("  ✓ test_audit_missing_address")


def test_audit_not_eip712():
    """A contract without EIP712Domain type-hash should be NOT_FOUND for check 1."""
    bc = JUMPDEST() + bytes([STOP])
    result = audit("0x" + bc.hex(), contract="0xtest")
    c1 = next(c for c in result["checks"] if c["id"] == 1)
    assert c1["verdict"] in ("NOT_FOUND", "FAIL"), f"check 1 should be NOT_FOUND/FAIL, got {c1['verdict']}"
    print("  ✓ test_audit_not_eip712")


def test_audit_5field_with_salt():
    """A 5-field implementation should PASS check 1 and WARN check 7."""
    s = EIP712_TYPEHASH_5FIELD.encode("ascii")
    typehash_pushed = (
        bytes([0x7f]) + s[0:32]
        + bytes([0x7f]) + s[32:64]
        + bytes([0x7e]) + s[64:95]
    )
    bc = (
        b"\x36\x44\xe5\x15"
        + bytes([CHAINID])
        + bytes([ADDRESS])
        + RETURN_()
        + typehash_pushed
    )
    result = audit("0x" + bc.hex(), contract="0xtest")
    c1 = next(c for c in result["checks"] if c["id"] == 1)
    assert c1["verdict"] == "PASS", f"check 1 should PASS for 5-field, got {c1['verdict']}"
    c7 = next(c for c in result["checks"] if c["id"] == 7)
    assert c7["verdict"] == "WARN", f"check 7 should WARN for 5-field, got {c7['verdict']}"
    print("  ✓ test_audit_5field_with_salt")


def test_overall_score_all_pass():
    """When all critical checks PASS, overall should be 100."""
    s = EIP712_TYPEHASH_4FIELD.encode("ascii")
    typehash_pushed = (
        bytes([0x7f]) + s[0:32]
        + bytes([0x7f]) + s[32:64]
        + bytes([0x71]) + s[64:82]
    )
    bc = (
        b"\x36\x44\xe5\x15"  # DOMAIN_SEPARATOR selector
        + b"\x06\xfd\xde\x03"  # name() selector
        + b"\x54\xfd\x4d\x50"  # version() selector
        + bytes([CHAINID])
        + bytes([ADDRESS])
        + RETURN_()
        + typehash_pushed
    )
    result = audit("0x" + bc.hex(), contract="0xtest")
    assert result["overall_score"] == 100, f"expected 100, got {result['overall_score']}"
    print("  ✓ test_overall_score_all_pass")


def test_overall_score_is_min_of_failures():
    """Overall score is the min severity of all FAIL/NOT_FOUND checks."""
    s = EIP712_TYPEHASH_4FIELD.encode("ascii")
    typehash_pushed = (
        bytes([0x7f]) + s[0:32]
        + bytes([0x7f]) + s[32:64]
        + bytes([0x71]) + s[64:82]
    )
    # Has DOMAIN_SEPARATOR selector, ADDRESS, type-hash — but NO CHAINID
    bc = (
        b"\x36\x44\xe5\x15"
        + bytes([ADDRESS])
        + RETURN_()
        + typehash_pushed
    )
    result = audit("0x" + bc.hex(), contract="0xtest")
    # check 1 (severity 100) PASSES, check 4 (severity 95) FAILS
    # expected overall = min of FAIL severities = 95
    assert result["overall_score"] == 95, f"expected 95 (check 4 fails with severity 95), got {result['overall_score']}"
    print("  ✓ test_overall_score_is_min_of_failures")


def test_severity_label_thresholds():
    from audit import sev_label
    assert sev_label(0)   == "NOT EIP-712"
    assert sev_label(30)  == "LOW"
    assert sev_label(31)  == "MEDIUM"
    assert sev_label(60)  == "MEDIUM"
    assert sev_label(61)  == "HIGH"
    assert sev_label(80)  == "HIGH"
    assert sev_label(81)  == "CRITICAL"
    assert sev_label(100) == "CRITICAL"
    print("  ✓ test_severity_label_thresholds")


# ----- runner -----

if __name__ == "__main__":
    tests = [
        test_extract_string_literal_eip712,
        test_extract_skips_non_printable_push,
        test_extract_5field_literal,
        test_find_selectors,
        test_basic_blocks,
        test_audit_4field_correct,
        test_audit_missing_chainid,
        test_audit_missing_address,
        test_audit_not_eip712,
        test_audit_5field_with_salt,
        test_overall_score_all_pass,
        test_overall_score_is_min_of_failures,
        test_severity_label_thresholds,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  ✗ {t.__name__} — {e}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {t.__name__} — EXCEPTION: {e}")
    print(f"\n{len(tests) - failed} test(s) passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
