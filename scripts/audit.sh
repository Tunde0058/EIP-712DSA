#!/usr/bin/env bash
# eip712dsa/audit.sh — bash + cast (Foundry) auditor for EIP-712 domain separator implementations.
# Scans deployed EVM bytecode for 8 EIP-712 correctness checks.
#
# Usage:
#   bash scripts/audit.sh 0xCONTRACT [--network mainnet|testnet] [--format md|json|txt] [--strict]
#   bash scripts/audit.sh --demo
#   bash scripts/audit.sh --help
#
# Requires: bash 4+, cast (Foundry), jq
# Read-only: never asks for a private key, never sends a transaction.

set -uo pipefail

# ---- Foundry required (after arg parsing so --help works offline) ----
ensure_cast() {
  if ! command -v cast >/dev/null 2>&1; then
    echo "Error: 'cast' not found. Install Foundry:" >&2
    echo "  curl -L https://foundry.paradigm.xyz | bash && foundryup" >&2
    exit 1
  fi
}

# ---- Load network config from assets/networks.json ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET_JSON="$SCRIPT_DIR/../assets/networks.json"
[ ! -f "$NET_JSON" ] && { echo "Error: $NET_JSON not found" >&2; exit 1; }

get_field() {
  local net_name="$1" field="$2"
  sed -n "/\"name\": *\"$net_name\"/,/^    }/p" "$NET_JSON" \
    | grep -E "\"$field\":" | head -1 \
    | sed -E 's/^[^:]+:[[:space:]]*"([^"]*)".*/\1/' | sed -E 's/,$//'
}

# ---- Demo mode (no cast needed) ----
DEMO_ADDR="0x6dc35147eb53152cd834b5799a07934f13f398a3"
DEMO_LABEL="0x6dc351…98a3 (known public mainnet ERC-20)"

# ---- EVM opcodes ----
ADDRESS_OP=0x30
CHAINID_OP=0x46
JUMPDEST_OP=0x5b
STOP_OP=0x00
RETURN_OP=0xf3
REVERT_OP=0xfd
JUMPI_OP=0x57
PUSH1_OP=0x60
PUSH32_OP=0x7f

# EIP-712 typehash strings (the canonical 76-byte and 89-byte versions)
EIP712_TYPEHASH_4FIELD="EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
EIP712_TYPEHASH_5FIELD="EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"

# Function selectors (4-byte hex, no 0x)
SEL_DOMAIN_SEPARATOR="3644e515"
SEL_PERMIT="d505accf"
SEL_NAME="06fdde03"
SEL_VERSION="54fd4d50"

# ---- Arg parsing ----
CONTRACT=""
NETWORK="mainnet"
FORMAT="md"
STRICT=0
PRINT_HELP=0
DEMO=0
PREV=""

for arg in "$@"; do
  case "$PREV" in
    --network)  NETWORK="$arg"; PREV=""; continue ;;
    --format)   FORMAT="$arg";  PREV=""; continue ;;
  esac
  case "$arg" in
    -h|--help)   PRINT_HELP=1 ;;
    --network)   PREV="--network" ;;
    --format)    PREV="--format" ;;
    --strict)    STRICT=1 ;;
    --demo)      DEMO=1 ;;
    0x*)         [ -z "$CONTRACT" ] && CONTRACT="$arg" ;;
    *)           echo "Unknown arg: $arg" >&2; exit 2 ;;
  esac
done
[ -n "$PREV" ] && { echo "Error: $PREV requires a value" >&2; exit 1; }

# ---- Help (no cast needed) ----
if [ "$PRINT_HELP" = "1" ]; then
  cat <<'EOF'
Usage: bash scripts/audit.sh 0xCONTRACT [--network mainnet|testnet] [--format md|json|txt] [--strict]
       bash scripts/audit.sh --demo
       bash scripts/audit.sh --help

Networks:
  mainnet  (default) — Pharos Pacific Ocean Mainnet, chain 1672
  testnet             — Pharos Atlantic Testnet, chain 688689

Formats:
  md    Markdown report (default; human-friendly)
  json  Structured JSON (for agent consumption)
  txt   Plain text

Examples:
  bash scripts/audit.sh 0xYOUR_CONTRACT
  bash scripts/audit.sh 0xYOUR_CONTRACT --network testnet --format json
  bash scripts/audit.sh 0xYOUR_CONTRACT --strict   # exit 1 on any FAIL

Prerequisites:
  - Foundry (cast): curl -L https://foundry.paradigm.xyz | bash && foundryup
  - jq: for --format json pretty-printing
EOF
  exit 0
fi

# ---- Demo mode (no cast needed) ----
if [ "$DEMO" = "1" ]; then
  CONTRACT="$DEMO_ADDR"
fi

# ---- Validate contract ----
if [ -z "$CONTRACT" ]; then
  echo "Error: 0xCONTRACT required (or use --demo)" >&2
  exit 1
fi
if [[ ! "$CONTRACT" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
  echo "Error: contract must be 0x + 40 hex chars" >&2
  exit 1
fi
CONTRACT="${CONTRACT,,}"

# ---- Validate format ----
case "$FORMAT" in md|json|txt) ;; *) echo "Error: format must be md|json|txt" >&2; exit 1 ;; esac

# ---- Resolve network ----
case "$NETWORK" in
  mainnet)
    RPC_URL=$(get_field mainnet rpcUrl)
    EXPLORER_URL=$(get_field mainnet explorerUrl)
    CHAIN_ID=$(grep -A 30 '"name": "mainnet"' "$NET_JSON" | grep -oE '"chainId": [0-9]+' | grep -oE '[0-9]+' | head -1)
    NET_LABEL="Pharos Pacific Ocean Mainnet (chain $CHAIN_ID)"
    ;;
  testnet|atlantic-testnet)
    RPC_URL=$(get_field atlantic-testnet rpcUrl)
    EXPLORER_URL=$(get_field atlantic-testnet explorerUrl)
    CHAIN_ID=$(grep -A 30 '"name": "atlantic-testnet"' "$NET_JSON" | grep -oE '"chainId": [0-9]+' | grep -oE '[0-9]+' | head -1)
    NET_LABEL="Pharos Atlantic Testnet (chain $CHAIN_ID)"
    ;;
  *) echo "Error: unknown network: $NETWORK (use 'mainnet' or 'testnet')" >&2; exit 1 ;;
esac

# ---- Fetch bytecode (cast required from here) ----
ensure_cast

# Use `cast code` (the dedicated subcommand for eth_getCode) — simpler
# and more reliable than `cast rpc eth_getCode [...]` which has fragile
# arg-quoting. `cast code` returns the bytecode hex on stdout, or
# exits non-zero with a clear error on stderr.
RAW_OUTPUT=$(timeout 30 cast code --rpc-url "$RPC_URL" "$CONTRACT" 2>&1)
CAST_EXIT=$?

BYTECODE_HEX="$RAW_OUTPUT"

if [ "$CAST_EXIT" -ne 0 ]; then
  echo "Error: cast code failed (exit $CAST_EXIT) for $CONTRACT on $NETWORK" >&2
  echo "  RPC URL: $RPC_URL" >&2
  echo "  cast output: $RAW_OUTPUT" >&2
  echo "" >&2
  echo "  Possible causes:" >&2
  echo "    - the RPC endpoint is unreachable (check your network)" >&2
  echo "    - the Pharos public RPC is rate-limiting your IP" >&2
  echo "    - the contract address is wrong or on a different chain" >&2
  echo "    - cast is not the latest version (run 'foundryup')" >&2
  exit 1
fi

# Strip 0x prefix; handle empty/0x results
BYTECODE_HEX="${BYTECODE_HEX#0x}"

if [ -z "$BYTECODE_HEX" ] || [ "$BYTECODE_HEX" = "0x" ] || [ "$BYTECODE_HEX" = "0X" ]; then
  echo "Error: contract has no deployed code at $CONTRACT on $NETWORK" >&2
  echo "  Possible causes:" >&2
  echo "    - the address is an EOA (not a contract)" >&2
  echo "    - the contract hasn't been deployed yet" >&2
  echo "    - the contract was deployed on a different chain (try --network testnet)" >&2
  echo "    - the public RPC is rate-limited; try again or use a private RPC" >&2
  exit 1
fi

BYTECODE_SIZE=$((${#BYTECODE_HEX} / 2 - 1))  # subtract the 0x prefix
echo "[eip712dsa] fetched ${BYTECODE_SIZE} bytes of bytecode for $CONTRACT on $NET_LABEL" >&2

# Strip 0x prefix and convert to lower-case hex stream
HEX="${BYTECODE_HEX#0x}"
HEX="${HEX,,}"

# Build a bash array of bytes (0-255 each)
# Each byte is 2 hex chars; iterate the hex string in 2-char steps
BYTES=()
for ((i = 0; i < ${#HEX}; i += 2)); do
  BYTES+=("$(printf '%d' "0x${HEX:i:2}")")
done
NBYTES=${#BYTES[@]}

# ---- Helper: scan for PUSH-N regions (PUSH1..PUSH32) ----
# Outputs lines: "offset payload_hex" where offset is the PUSH opcode offset
# and payload_hex is the bytes pushed (without 0x)
scan_push_regions() {
  local i=0
  while [ "$i" -lt "$NBYTES" ]; do
    local op=${BYTES[$i]}
    if [ "$op" -ge "$PUSH1_OP" ] && [ "$op" -le "$PUSH32_OP" ]; then
      local n=$((op - PUSH1_OP + 1))
      local end=$((i + n))
      if [ "$end" -le "$NBYTES" ]; then
        # build the payload hex
        local payload=""
        for ((j = i + 1; j < end; j++)); do
          payload+=$(printf '%02x' "${BYTES[$j]}")
        done
        echo "$i $payload"
        i=$end
        continue
      fi
    fi
    i=$((i + 1))
  done
}

# ---- Helper: extract printable string literals (PUSH-N + consecutive printable bytes) ----
# Returns newline-separated "offset decoded_string" lines
extract_literals() {
  # Get the PUSH regions: array of "offset payload_hex"
  local regions=()
  while IFS= read -r line; do
    regions+=("$line")
  done < <(scan_push_regions)

  local n=${#regions[@]}
  local i=0
  while [ "$i" -lt "$n" ]; do
    local off=$(echo "${regions[$i]}" | awk '{print $1}')
    local payload=$(echo "${regions[$i]}" | awk '{print $2}')
    local nbytes=$((${#payload} / 2))

    # Check first byte printable
    if [ "$nbytes" -lt 1 ] || [ "$nbytes" -gt 64 ]; then
      i=$((i + 1))
      continue
    fi
    local first_byte=$(printf '%d' "0x${payload:0:2}")
    if [ "$first_byte" -lt 0x20 ] || [ "$first_byte" -gt 0x7e ]; then
      i=$((i + 1))
      continue
    fi

    # Check all bytes printable
    local all_print=1
    local literal_hex="$payload"
    local j=$((i + 1))
    while [ "$j" -lt "$n" ]; do
      local off2=$(echo "${regions[$j]}" | awk '{print $1}')
      local payload2=$(echo "${regions[$j]}" | awk '{print $2}')
      local expected=$((off + nbytes + 1))  # +1 because the PUSH opcode itself is 1 byte
      if [ "$off2" -ne "$expected" ]; then
        break
      fi
      local nbytes2=$((${#payload2} / 2))
      if [ "$nbytes2" -lt 1 ] || [ "$nbytes2" -gt 64 ]; then
        break
      fi
      local fb2=$(printf '%d' "0x${payload2:0:2}")
      if [ "$fb2" -lt 0x20 ] || [ "$fb2" -gt 0x7e ]; then
        break
      fi
      literal_hex+="$payload2"
      nbytes=$((nbytes + nbytes2))
      j=$((j + 1))
    done

    # Decode the hex to a string and check length
    if [ "$nbytes" -ge 3 ]; then
      local decoded
      decoded=$(printf '%b' "$(printf '\\x%s' $(echo "$literal_hex" | sed 's/../& /g' | sed 's/ /\n/g' | tr -d '\n'))" 2>/dev/null) || decoded=""
      if [ -n "$decoded" ]; then
        echo "$off $decoded"
      fi
    fi

    i=$j
  done
}

# ---- Helper: find 4-byte function selectors in the bytecode ----
# Returns newline-separated "selector offsets" (comma-sep)
find_selectors() {
  for sel in "$@"; do
    local first_byte=${sel:0:2}
    local hits=()
    # Slide a 4-byte window and compare
    for ((i = 0; i < NBYTES - 3; i++)); do
      local b0=$(printf '%02x' "${BYTES[$i]}")
      if [ "$b0" != "$first_byte" ]; then continue; fi
      local b1=$(printf '%02x' "${BYTES[$((i+1))]}")
      local b2=$(printf '%02x' "${BYTES[$((i+2))]}")
      local b3=$(printf '%02x' "${BYTES[$((i+3))]}")
      if [ "$b1$b2$b3" = "${sel:2}" ]; then
        hits+=("$i")
      fi
    done
    if [ "${#hits[@]}" -gt 0 ]; then
      local joined
      joined=$(IFS=,; echo "${hits[*]}")
      echo "$sel $joined"
    fi
  done
}

# ---- Helper: search for an opcode within `window` bytes of a reference offset ----
# Returns "offset" if found, empty otherwise
opcode_near() {
  local target_op="$1"
  local ref="$2"
  local window="$3"
  local lo=$((ref - window))
  [ "$lo" -lt 0 ] && lo=0
  local hi=$((ref + window))
  [ "$hi" -gt "$NBYTES" ] && hi=$NBYTES
  for ((i = lo; i < hi; i++)); do
    if [ "${BYTES[$i]}" = "$target_op" ]; then
      echo "$i"
      return
    fi
  done
}

# ---- Run the analysis ----
LITERALS_RAW=$(extract_literals)

# Check 1: EIP712Domain type-hash literal
HAS_4FIELD=""
HAS_5FIELD=""
while IFS= read -r line; do
  [ -z "$line" ] && continue
  literal=$(echo "$line" | cut -d' ' -f2-)
  if [ "$literal" = "$EIP712_TYPEHASH_4FIELD" ]; then
    HAS_4FIELD=$(echo "$line" | awk '{print $1}')
  fi
  if [ "$literal" = "$EIP712_TYPEHASH_5FIELD" ]; then
    HAS_5FIELD=$(echo "$line" | awk '{print $1}')
  fi
done <<< "$LITERALS_RAW"

# Check selectors
SELECTOR_HITS=$(find_selectors "$SEL_DOMAIN_SEPARATOR" "$SEL_PERMIT" "$SEL_NAME" "$SEL_VERSION")
DS_HITS=$(echo "$SELECTOR_HITS" | grep "^$SEL_DOMAIN_SEPARATOR " | awk '{print $2}')

LITERALS_FOUND=$(echo "$LITERALS_RAW" | grep -c . 2>/dev/null || echo "0")

# ---- Build the checks ----
CHECKS=()

# Check 1
if [ -n "$HAS_4FIELD" ]; then
  CHECKS+=("1|EIP712Domain type-hash literal (4-field)|PASS|Found 82-byte string at offset 0x$HAS_4FIELD|100")
elif [ -n "$HAS_5FIELD" ]; then
  CHECKS+=("1|EIP712Domain type-hash literal (5-field with salt)|PASS|Found 95-byte string at offset 0x$HAS_5FIELD|100")
else
  CHECKS+=("1|EIP712Domain type-hash literal|NOT_FOUND|No EIP712Domain(...) string literal in bytecode — contract may not implement EIP-712|100")
fi

# Check 6: DOMAIN_SEPARATOR() selector
if [ -n "$DS_HITS" ]; then
  DS_REF=$(echo "$DS_HITS" | cut -d',' -f1)
  CHECKS+=("6|DOMAIN_SEPARATOR() is a public view|PASS|Found selector 0x3644e515 at offsets [$(echo "$DS_HITS" | awk 'BEGIN{ORS=", "}{print "0x"$0}' | sed 's/, $//')]|100")
else
  DS_REF=""
  CHECKS+=("6|DOMAIN_SEPARATOR() is a public view|FAIL|Selector 0x3644e515 (DOMAIN_SEPARATOR()) not found in bytecode|100")
fi

# Check 4: CHAINID near DOMAIN_SEPARATOR
if [ -n "$DS_REF" ]; then
  CHAINID_NEAR=$(opcode_near "$CHAINID_OP" "$DS_REF" 64)
  if [ -n "$CHAINID_NEAR" ]; then
    CHECKS+=("4|chainId fetched via chainid() opcode, not hardcoded|PASS|Found CHAINID opcode (0x46) at offset 0x$CHAINID_NEAR within 64 bytes of DOMAIN_SEPARATOR|95")
  else
    # Look for any CHAINID in entire bytecode
    CHAINID_ANY=""
    for ((i = 0; i < NBYTES; i++)); do
      if [ "${BYTES[$i]}" = "$CHAINID_OP" ]; then
        CHAINID_ANY="$i"
        break
      fi
    done
    if [ -n "$CHAINID_ANY" ]; then
      CHECKS+=("4|chainId fetched via chainid() opcode, not hardcoded|WARN|CHAINID opcode (0x46) found in bytecode but not within 64 bytes of DOMAIN_SEPARATOR — may be hardcoded|60")
    else
      CHECKS+=("4|chainId fetched via chainid() opcode, not hardcoded|FAIL|No CHAINID opcode (0x46) in bytecode — chainId is hardcoded; signature is replayable across forks|95")
    fi
  fi
else
  CHECKS+=("4|chainId fetched via chainid() opcode, not hardcoded|SKIP|Skipped: no DOMAIN_SEPARATOR() reference point|95")
fi

# Check 5: ADDRESS near DOMAIN_SEPARATOR
if [ -n "$DS_REF" ]; then
  ADDR_NEAR=$(opcode_near "$ADDRESS_OP" "$DS_REF" 32)
  if [ -n "$ADDR_NEAR" ]; then
    CHECKS+=("5|verifyingContract is address(this)|PASS|Found ADDRESS opcode (0x30) at offset 0x$ADDR_NEAR within 32 bytes of DOMAIN_SEPARATOR|90")
  else
    CHECKS+=("5|verifyingContract is address(this)|FAIL|ADDRESS opcode (0x30) not found within 32 bytes of DOMAIN_SEPARATOR — verifyingContract may be hardcoded|90")
  fi
else
  CHECKS+=("5|verifyingContract is address(this)|SKIP|Skipped: no DOMAIN_SEPARATOR() reference point|90")
fi

# Check 2: name() selector
NAME_HITS=$(echo "$SELECTOR_HITS" | grep "^$SEL_NAME " | awk '{print $2}')
if [ -n "$NAME_HITS" ]; then
  NAME_OFFS=$(echo "$NAME_HITS" | awk 'BEGIN{ORS=", "}{print "0x"$0}' | sed 's/, $//')
  CHECKS+=("2|name() function present (ERC-20 name accessible)|PASS|Found selector 0x06fdde03 (name()) at offsets [$NAME_OFFS]|50")
else
  CHECKS+=("2|name() function present|WARN|No name() selector (0x06fdde03) found — domain may use a hardcoded name string|50")
fi

# Check 3: version() selector or version-like literal
VERSION_HITS=$(echo "$SELECTOR_HITS" | grep "^$SEL_VERSION " | awk '{print $2}')
if [ -n "$VERSION_HITS" ]; then
  VER_OFFS=$(echo "$VERSION_HITS" | awk 'BEGIN{ORS=", "}{print "0x"$0}' | sed 's/, $//')
  CHECKS+=("3|version() function present|PASS|Found selector 0x54fd4d50 (version()) at offsets [$VER_OFFS]|30")
else
  # Check for short version-like literals
  VERSION_LIKE=""
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    lit=$(echo "$line" | cut -d' ' -f2-)
    case "$lit" in
      1|2|v1|v2|0.1|1.0|1.0.0|2.0|0.2)
        VERSION_LIKE+="\"$lit\","
        ;;
    esac
  done <<< "$LITERALS_RAW"
  if [ -n "$VERSION_LIKE" ]; then
    VERSION_LIKE=$(echo "$VERSION_LIKE" | sed 's/,$//')
    CHECKS+=("3|version field present|PASS|Found version-like literal(s): [$VERSION_LIKE]|30")
  else
    CHECKS+=("3|version field present|WARN|No version() selector and no version-like literal — old signatures may be valid forever after upgrades|30")
  fi
fi

# Check 7: 5-field salt check
if [ -n "$HAS_5FIELD" ]; then
  if [ "$BYTECODE_SIZE" -lt 8000 ]; then
    CHECKS+=("7|5-field salt is not hardcoded|WARN|5-field EIP-712 domain with salt detected. Salt source cannot be verified from bytecode alone — manually inspect source for hardcoded bytes32.|80")
  else
    CHECKS+=("7|5-field salt is not hardcoded|WARN|5-field EIP-712 domain with salt detected. Manually verify the salt comes from a state variable, not a hardcoded constant.|80")
  fi
else
  CHECKS+=("7|5-field salt is not hardcoded|N/A|4-field EIP-712 domain (no salt) — check does not apply|80")
fi

# Check 8: salt included (info)
if [ -n "$HAS_5FIELD" ]; then
  CHECKS+=("8|Salt included in domain (best practice)|PASS|5-field domain with salt detected|0")
else
  CHECKS+=("8|Salt included in domain (best practice)|INFO|4-field domain without salt — standard EIP-712, acceptable|0")
fi

# ---- Compute overall ----
OVERALL=100
NOT_EIP712=0
for chk in "${CHECKS[@]}"; do
  IFS='|' read -r id name verdict evidence severity <<< "$chk"
  if [ "$verdict" = "NOT_FOUND" ] && [ "$id" = "1" ]; then
    NOT_EIP712=1
  fi
  if [ "$verdict" = "FAIL" ] && [ "$severity" -lt "$OVERALL" ]; then
    OVERALL="$severity"
  fi
done

if [ "$NOT_EIP712" = "1" ]; then
  OVERALL=0
  AUDIT_VERDICT="NOT_EIP712"
elif [ "$OVERALL" = "100" ]; then
  AUDIT_VERDICT="PASS"
elif [ "$OVERALL" -ge 60 ]; then
  AUDIT_VERDICT="PARTIAL"
else
  AUDIT_VERDICT="FAIL"
fi

HAS_PERMIT=0
if [ -n "$(echo "$SELECTOR_HITS" | grep "^$SEL_PERMIT ")" ]; then
  HAS_PERMIT=1
fi

# ---- Render ----
EXPLORER_LINK="$EXPLORER_URL/address/$CONTRACT"

case "$FORMAT" in
  json)
    # Build JSON output via jq
    CHECKS_JSON="["
    first=1
    for chk in "${CHECKS[@]}"; do
      IFS='|' read -r id name verdict evidence severity <<< "$chk"
      if [ "$first" = "1" ]; then first=0; else CHECKS_JSON+=","; fi
      CHECKS_JSON+="$(jq -n --argjson id "$id" --arg name "$name" --arg verdict "$verdict" --arg evidence "$evidence" --argjson severity "$severity" \
        '{id:$id, name:$name, verdict:$verdict, evidence:$evidence, severity:$severity}')"
    done
    CHECKS_JSON+="]"
    jq -n \
      --arg contract "$CONTRACT" \
      --argjson bytecode_size "$BYTECODE_SIZE" \
      --argjson has_domain_separator "$([ -n "$DS_REF" ] && echo true || echo false)" \
      --argjson has_permit "$HAS_PERMIT" \
      --argjson overall "$OVERALL" \
      --arg verdict "$AUDIT_VERDICT" \
      --argjson checks "$CHECKS_JSON" \
      --argjson literals_found "$LITERALS_FOUND" \
      --arg network "$NETWORK" \
      --argjson chain_id "$CHAIN_ID" \
      --arg net_label "$NET_LABEL" \
      --arg explorer_link "$EXPLORER_LINK" \
      '{
        contract: $contract,
        network: $network,
        chain_id: $chain_id,
        net_label: $net_label,
        explorer_link: $explorer_link,
        bytecode_size: $bytecode_size,
        has_domain_separator: $has_domain_separator,
        has_permit: $has_permit,
        overall_score: $overall,
        verdict: $verdict,
        checks: $checks,
        literals_found: $literals_found
      }'
    ;;

  txt)
    echo ""
    echo "========================================================================"
    echo "  EIP-712 DOMAIN SEPARATOR AUDIT"
    echo "  Contract: $CONTRACT"
    echo "  Network:  $NET_LABEL"
    echo "  Bytecode: $BYTECODE_SIZE bytes"
    echo "========================================================================"
    echo ""
    echo "  Verdict: $AUDIT_VERDICT"
    echo "  Score:   $OVERALL/100"
    echo ""
    echo "  Per-check findings:"
    echo "  ----------------------------------------------------------------"
    for chk in "${CHECKS[@]}"; do
      IFS='|' read -r id name verdict evidence severity <<< "$chk"
      printf "  [%-9s] (id=%s, sev=%s) %s\n" "$verdict" "$id" "$severity" "$name"
      echo "             $evidence"
    done
    echo ""
    echo "  Explorer: $EXPLORER_LINK"
    echo "========================================================================"
    ;;

  md|*)
    echo ""
    echo "# EIP-712 Domain Separator Audit"
    echo ""
    echo "| Field | Value |"
    echo "|---|---|"
    echo "| Contract | \`$CONTRACT\` |"
    echo "| Network | $NET_LABEL |"
    echo "| Bytecode size | $BYTECODE_SIZE bytes |"
    echo "| **Verdict** | **$AUDIT_VERDICT** |"
    echo "| **Score** | **$OVERALL / 100** |"
    echo "| Explorer | [view ↗]($EXPLORER_LINK) |"
    echo ""
    echo "## Per-check findings"
    echo ""
    echo "| # | Check | Verdict | Severity | Evidence |"
    echo "|---:|---|---|---:|---|"
    for chk in "${CHECKS[@]}"; do
      IFS='|' read -r id name verdict evidence severity <<< "$chk"
      echo "| $id | $name | \`$verdict\` | $severity | $evidence |"
    done
    echo ""
    echo "## What to do"
    echo ""
    if [ "$AUDIT_VERDICT" = "NOT_EIP712" ]; then
      echo "Contract does not appear to implement EIP-712 (no \`EIP712Domain(...)\` typehash in bytecode). Audit not applicable."
    elif [ "$AUDIT_VERDICT" = "PASS" ]; then
      echo "All checks passed. EIP-712 implementation looks correct."
    elif [ "$AUDIT_VERDICT" = "PARTIAL" ]; then
      echo "Some warnings to investigate. See the per-check table above for the specific findings."
    else
      echo "**Critical issues found.** Do NOT trust signatures from this contract until the FAIL items are resolved."
    fi
    echo ""
    ;;
esac

# ---- Strict mode ----
if [ "$STRICT" = "1" ]; then
  FAIL_COUNT=0
  for chk in "${CHECKS[@]}"; do
    IFS='|' read -r id name verdict evidence severity <<< "$chk"
    if [ "$verdict" = "FAIL" ] || [ "$verdict" = "NOT_FOUND" ]; then
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
  done
  if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "" >&2
    echo "[eip712dsa] STRICT MODE: $FAIL_COUNT check(s) FAILED — exiting 1" >&2
    exit 1
  fi
fi
