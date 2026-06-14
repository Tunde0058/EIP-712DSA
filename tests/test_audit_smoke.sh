#!/bin/bash
# Smoke test for eip712dsa (Foundry/bash port, v2.0.0).
# Verifies the CLI parses, help text works offline, and error paths are clear.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
SCRIPT="$SKILL_DIR/scripts/audit.sh"

PASS=0
FAIL=0

run() {
  local name="$1"
  local expected="$2"
  shift 2
  local out
  out=$(bash "$SCRIPT" "$@" 2>&1 || true)
  if echo "$out" | grep -qF -- "$expected"; then
    echo "  OK: $name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $name"
    echo "       expected substring: $expected"
    echo "       actual: $(echo "$out" | head -3)"
    FAIL=$((FAIL + 1))
  fi
}

echo "Test 1: --help works (no cast required)"
run "help text present" "Usage:" --help

echo "Test 2: no contract shows usage"
run "no-contract shows usage" "0xCONTRACT required"

echo "Test 3: bad contract format rejected"
run "bad contract rejected" "Unknown arg" not-hex

echo "Test 4: bad format rejected"
run "bad format rejected" "format must be md|json|txt" \
  0x1234567890123456789012345678901234567890 --format xml

echo "Test 5: bad network rejected"
run "bad network rejected" "unknown network" \
  0x1234567890123456789012345678901234567890 --network bogus

echo "Test 6: cast-missing error is clear (only when cast is not installed)"
if ! command -v cast >/dev/null 2>&1; then
  run "cast-missing error clear" "not found" \
    0x1234567890123456789012345678901234567890
else
  echo "  SKIP: cast is installed"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" = "0" ] || exit 1
