#!/usr/bin/env bash
# eip712dsa/audit.sh — zero-dep bash auditor for EIP-712 domain separator implementations.
# Usage:
#   bash scripts/audit.sh 0xCONTRACT --network mainnet
#   bash scripts/audit.sh 0xCONTRACT --network testnet --format json
#   bash scripts/audit.sh 0xCONTRACT --network mainnet --strict
#
# Requires: bash 4+, curl, python3
# Read-only: never asks for a private key, never sends a transaction.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -------------------- args --------------------
if [[ $# -lt 1 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
  cat <<EOF
Usage: bash scripts/audit.sh 0xCONTRACT [--network mainnet|atlantic-testnet] [--format md|json|txt] [--strict]

Networks:
  atlantic-testnet  (default) — Pharos Atlantic Testnet, chain 688689
  mainnet                       — Pharos Pacific Ocean Mainnet, chain 1672

Examples:
  bash scripts/audit.sh 0xYOUR_CONTRACT --network mainnet
  bash scripts/audit.sh 0xYOUR_CONTRACT --network testnet --format json
  bash scripts/audit.sh 0xYOUR_CONTRACT --network mainnet --strict
EOF
  exit 0
fi

CONTRACT="${1,,}"
NETWORK="atlantic-testnet"
FORMAT="md"
STRICT=0

shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --network)  NETWORK="$2"; shift 2 ;;
    --format)   FORMAT="$2"; shift 2 ;;
    --strict)   STRICT=1; shift ;;
    *) echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

# validate
if [[ ! "$CONTRACT" =~ ^0x[0-9a-f]{40}$ ]]; then
  echo "ERROR: contract must look like 0x + 40 hex chars" >&2; exit 2
fi

case "$NETWORK" in
  mainnet)
    CHAIN_ID=1672
    RPC="https://rpc.pharos.xyz"
    EXPLORER="https://www.pharosscan.xyz"
    NET_LABEL="Pharos Pacific Ocean Mainnet (chain 1672)"
    ;;
  atlantic-testnet|testnet)
    CHAIN_ID=688689
    RPC="https://atlantic.dplabs-internal.com"
    EXPLORER="https://atlantic.pharosscan.xyz"
    NET_LABEL="Pharos Atlantic Testnet (chain 688689)"
    ;;
  *) echo "ERROR: unknown network: $NETWORK" >&2; exit 2 ;;
esac

case "$FORMAT" in md|json|txt) ;; *) echo "ERROR: format must be md|json|txt" >&2; exit 2 ;; esac

# -------------------- fetch bytecode --------------------
PAYLOAD=$(printf '{"jsonrpc":"2.0","method":"eth_getCode","params":["%s","latest"],"id":1}' "$CONTRACT")

RESP=$(curl -sS -X POST -H "Content-Type: application/json" --data "$PAYLOAD" "$RPC")
BYTECODE_HEX=$(printf '%s' "$RESP" | python3 -c '
import sys, json
d = json.load(sys.stdin)
if "error" in d:
    print("ERROR:", d["error"].get("message", d["error"]), file=sys.stderr); sys.exit(3)
r = d.get("result", "")
if not r or r == "0x":
    print("ERROR: contract has no deployed code (or address is an EOA)", file=sys.stderr); sys.exit(4)
print(r)
')

BYTECODE_SIZE=$((${#BYTECODE_HEX} / 2 - 1))
echo "[eip712dsa] fetched ${BYTECODE_SIZE} bytes of bytecode for $CONTRACT on $NET_LABEL" >&2

# -------------------- run auditor --------------------
REPORT_JSON=$(export REEPATTS_BYTECODE_HEX="$BYTECODE_HEX" && BYTECODE_HEX="$BYTECODE_HEX" python3 <<'PYEOF'
import os, json

bytecode = os.environ["REEPATTS_BYTECODE_HEX"]
assert bytecode.startswith("0x")
raw = bytes.fromhex(bytecode[2:])

ADDRESS = 0x30
CHAINID = 0x46
JUMPDEST = 0x5b
STOP = 0x00
RETURN = 0xf3
REVERT = 0xfd
JUMPI = 0x57

EIP712_TYPEHASH_4FIELD = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
EIP712_TYPEHASH_5FIELD = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
SEL_DOMAIN_SEPARATOR = "3644e515"
SEL_PERMIT = "d505accf"
SEL_NAME = "06fdde03"
SEL_VERSION = "54fd4d50"

def iter_opcodes(b):
    i = 0
    while i < len(b):
        op = b[i]
        yield i, op
        if 0x60 <= op <= 0x7f:
            i += (op - 0x5f) + 1
        else:
            i += 1

def extract_string_literals(raw):
    """Solidity emits string literals as PUSH-N opcodes whose payload IS the string.
    Extract PUSH-N regions and stitch together consecutive printable PUSHes.
    """
    push_regions = []
    for off, op in iter_opcodes(raw):
        if 0x60 <= op <= 0x7f:
            n = op - 0x5f
            payload = raw[off + 1:off + 1 + n]
            push_regions.append((off, payload, n))
    literals = []
    i = 0
    while i < len(push_regions):
        start_off, payload, n = push_regions[i]
        if not all(0x20 <= b <= 0x7e for b in payload):
            i += 1
            continue
        literal_start = start_off
        literal_bytes = bytearray()
        for j in range(i, len(push_regions)):
            off_j, payload_j, n_j = push_regions[j]
            if not all(0x20 <= b <= 0x7e for b in payload_j):
                break
            literal_bytes.extend(payload_j)
            if j + 1 < len(push_regions):
                off_next, _, _ = push_regions[j + 1]
                if off_next != off_j + n_j + 1:
                    break
        literal_str = literal_bytes.decode("ascii", errors="replace").rstrip("\x00")
        if len(literal_str) >= 3:
            literals.append((literal_start, literal_str))
        i += 1
    return literals

def find_selectors(raw):
    if len(raw) < 4: return {}
    results = {}
    for i in range(len(raw) - 3):
        sel_hex = "".join(f"{b:02x}" for b in raw[i:i + 4])
        if sel_hex in {SEL_DOMAIN_SEPARATOR, SEL_PERMIT, SEL_NAME, SEL_VERSION}:
            results.setdefault(sel_hex, []).append(i)
    return results

def has_opcode_near(raw, opcode, ref, window=64):
    lo = max(0, ref - window)
    hi = min(len(raw), ref + window)
    for off, op in iter_opcodes(raw[lo:hi]):
        if op == opcode:
            return True, lo + off
    return False, None

literals = extract_string_literals(raw)
selectors = find_selectors(raw)
checks = []

has_4 = any(s == EIP712_TYPEHASH_4FIELD for _, s in literals)
has_5 = any(s == EIP712_TYPEHASH_5FIELD for _, s in literals)
if has_4:
    off = next(o for o, s in literals if s == EIP712_TYPEHASH_4FIELD)
    checks.append({"id":1,"name":"EIP712Domain type-hash literal (4-field)","verdict":"PASS","evidence":f"Found 82-byte string at offset 0x{off:x}","severity":100})
elif has_5:
    off = next(o for o, s in literals if s == EIP712_TYPEHASH_5FIELD)
    checks.append({"id":1,"name":"EIP712Domain type-hash literal (5-field with salt)","verdict":"PASS","evidence":f"Found 95-byte string at offset 0x{off:x}","severity":100})
else:
    checks.append({"id":1,"name":"EIP712Domain type-hash literal","verdict":"NOT_FOUND","evidence":"No EIP712Domain(...) string literal in bytecode — contract may not implement EIP-712","severity":100})

if SEL_DOMAIN_SEPARATOR in selectors:
    offs = selectors[SEL_DOMAIN_SEPARATOR]
    checks.append({"id":6,"name":"DOMAIN_SEPARATOR() is a public view","verdict":"PASS","evidence":f"Found selector 0x3644e515 at offsets {[hex(o) for o in offs[:3]]}","severity":100})
    ds_ref = offs[0]
else:
    checks.append({"id":6,"name":"DOMAIN_SEPARATOR() is a public view","verdict":"FAIL","evidence":"Selector 0x3644e515 (DOMAIN_SEPARATOR()) not found in bytecode","severity":100})
    ds_ref = None

if ds_ref is not None:
    found, off = has_opcode_near(raw, CHAINID, ds_ref, 64)
    if found:
        checks.append({"id":4,"name":"chainId fetched via chainid() opcode, not hardcoded","verdict":"PASS","evidence":f"Found CHAINID opcode (0x46) at offset 0x{off:x} within 64 bytes of DOMAIN_SEPARATOR","severity":95})
    else:
        any_ci = any(op == CHAINID for _, op in iter_opcodes(raw))
        if any_ci:
            checks.append({"id":4,"name":"chainId fetched via chainid() opcode, not hardcoded","verdict":"WARN","evidence":"CHAINID opcode (0x46) found in bytecode but not within 64 bytes of DOMAIN_SEPARATOR — may be hardcoded","severity":60})
        else:
            checks.append({"id":4,"name":"chainId fetched via chainid() opcode, not hardcoded","verdict":"FAIL","evidence":"No CHAINID opcode (0x46) in bytecode — chainId is hardcoded; signature is replayable across forks","severity":95})
else:
    checks.append({"id":4,"name":"chainId fetched via chainid() opcode, not hardcoded","verdict":"SKIP","evidence":"Skipped: no DOMAIN_SEPARATOR() reference point","severity":95})

if ds_ref is not None:
    found, off = has_opcode_near(raw, ADDRESS, ds_ref, 32)
    if found:
        checks.append({"id":5,"name":"verifyingContract is address(this)","verdict":"PASS","evidence":f"Found ADDRESS opcode (0x30) at offset 0x{off:x} within 32 bytes of DOMAIN_SEPARATOR","severity":90})
    else:
        checks.append({"id":5,"name":"verifyingContract is address(this)","verdict":"FAIL","evidence":"ADDRESS opcode (0x30) not found within 32 bytes of DOMAIN_SEPARATOR — verifyingContract may be hardcoded","severity":90})
else:
    checks.append({"id":5,"name":"verifyingContract is address(this)","verdict":"SKIP","evidence":"Skipped: no DOMAIN_SEPARATOR() reference point","severity":90})

if SEL_NAME in selectors:
    checks.append({"id":2,"name":"name() function present (ERC-20 name accessible)","verdict":"PASS","evidence":f"Found selector 0x06fdde03 (name()) at offsets {[hex(o) for o in selectors[SEL_NAME][:3]]}","severity":50})
else:
    checks.append({"id":2,"name":"name() function present","verdict":"WARN","evidence":"No name() selector (0x06fdde03) found — domain may use a hardcoded name string","severity":50})

if SEL_VERSION in selectors:
    checks.append({"id":3,"name":"version() function present","verdict":"PASS","evidence":f"Found selector 0x54fd4d50 (version()) at offsets {[hex(o) for o in selectors[SEL_VERSION][:3]]}","severity":30})
else:
    version_like = [s for _, s in literals if s in ("1","2","v1","v2","0.1","1.0","1.0.0","2.0","0.2")]
    if version_like:
        checks.append({"id":3,"name":"version field present","verdict":"PASS","evidence":f"Found version-like literal(s): {version_like[:3]}","severity":30})
    else:
        checks.append({"id":3,"name":"version field present","verdict":"WARN","evidence":"No version() selector and no version-like literal — old signatures may be valid forever after upgrades","severity":30})

if has_5:
    checks.append({"id":7,"name":"5-field salt is not hardcoded","verdict":"WARN","evidence":"5-field EIP-712 domain with salt detected. Manually verify the salt comes from a state variable, not a hardcoded constant.","severity":80})
else:
    checks.append({"id":7,"name":"5-field salt is not hardcoded","verdict":"N/A","evidence":"4-field EIP-712 domain (no salt) — check does not apply","severity":80})

if has_5:
    checks.append({"id":8,"name":"Salt included in domain (best practice)","verdict":"PASS","evidence":"5-field domain with salt detected","severity":0})
else:
    checks.append({"id":8,"name":"Salt included in domain (best practice)","verdict":"INFO","evidence":"4-field domain without salt — standard EIP-712, acceptable","severity":0})

# Special verdict: if check 1 is NOT_FOUND, this isn't an EIP-712 contract at all
if any(c["id"] == 1 and c["verdict"] == "NOT_FOUND" for c in checks):
    overall = 0
    audit_verdict = "NOT_EIP712"
else:
    fail_severities = [c["severity"] for c in checks if c["verdict"] in ("FAIL",)]
    overall = min(fail_severities) if fail_severities else 100
    audit_verdict = "PASS" if overall == 100 else ("PARTIAL" if overall >= 60 else "FAIL")

report = {
    "bytecode_size": len(raw),
    "has_domain_separator": ds_ref is not None,
    "has_permit": SEL_PERMIT in selectors,
    "overall_score": overall,
    "verdict": audit_verdict,
    "checks": checks,
    "literals_found": len(literals),
}
print(json.dumps(report))
PYEOF
)

# -------------------- render --------------------
EXPLORER_LINK="$EXPLORER/address/$CONTRACT"
echo "$REPORT_JSON" | python3 "$SCRIPT_DIR/_render.py" \
  "contract=$CONTRACT" \
  "network=$NETWORK" \
  "chain_id=$CHAIN_ID" \
  "net_label=$NET_LABEL" \
  "explorer_link=$EXPLORER_LINK" \
  "bytecode_size=$BYTECODE_SIZE" \
  "format=$FORMAT"

# -------------------- strict mode --------------------
if [[ "$STRICT" -eq 1 ]]; then
  FAIL_COUNT=$(echo "$REPORT_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for c in d["checks"] if c["verdict"] in ("FAIL","NOT_FOUND")))')
  if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "" >&2
    echo "[eip712dsa] STRICT MODE: $FAIL_COUNT check(s) FAILED — exiting 1" >&2
    exit 1
  fi
fi
