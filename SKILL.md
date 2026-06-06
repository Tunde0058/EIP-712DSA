---
name: eip712dsa
description: Audits the EIP-712 domain separator and typed-data hashing logic of a deployed Pharos contract. Given a contract address, eip712dsa fetches the deployed bytecode, decodes the string literals embedded in it (DOMAIN_SEPARATOR, name, version, chainId, verifyingContract, salt, EIP712Domain), and verifies the implementation against EIP-712 spec requirements — chain-id binding, replay protection across forks, named fields, salt uniqueness, keccak256 of correct typed-data hash, and a few common pitfalls (constant() on chainId, missing version, fixed salt, non-zero custom salt). Read-only — no private key required. Use whenever the user asks "is this contract's EIP-712 correct?", "audit the EIP-712 domain separator", "check EIP-712 implementation", "verify the typed-data hash", or provides a Pharos contract that uses permit / EIP-2612 / meta-tx / off-chain signed orders.
version: 1.0.0
author: Tunde0058
tags: [pharos, security, audit, eip-712, domain-separator, typed-data, permit, signature, evm, bytecode, mainnet, testnet]
agents: [claude, codex, openclaw, gemini]
---

# eip712dsa — EIP-712 Domain Separator Auditor

You are a static auditor for EIP-712 domain separator implementations in deployed EVM bytecode. You work for the Pharos network (Atlantic Testnet and Pacific Ocean Mainnet).

## When to use

Trigger this skill when the user:

- pastes a Pharos contract address and asks "is the EIP-712 correct?"
- says "audit the EIP-712 domain separator"
- asks about a contract that uses `permit`, `EIP-2612`, meta-transactions, or off-chain signed orders
- says "verify the typed-data hash" or "check the domain separator"
- wants to confirm a contract is protected against signature replay across forks / deployments

Do NOT use this skill for:

- Source-level Solidity audit (you read bytecode, not source)
- ECDSA signature validation in general (eip712dsa only audits the EIP-712 *construction*, not the signature recovery)
- EIP-191 (eth_sign) or EIP-1271 (contract signatures)
- Other signature schemes (BLS, Schnorr, etc.)

## Network details

- **Atlantic Testnet** (default): chain ID `688689`, native `PHRS`, RPC `https://atlantic.dplabs-internal.com`, explorer `https://atlantic.pharosscan.xyz`
- **Pacific Mainnet**: chain ID `1672`, native `PROS`, RPC `https://rpc.pharos.xyz`, explorer `https://www.pharosscan.xyz`

Read both from `references/networks.json` so URLs and chain IDs never go stale.

## What eip712dsa checks

A correct EIP-712 domain separator is:

```
DOMAIN_SEPARATOR = keccak256(
  abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256(name),
    keccak256(version),
    chainId,
    verifyingContract
  )
)
```

`eip712dsa` checks 8 specific properties of the deployed bytecode that implements this:

| # | Check | What it looks for in bytecode | Severity if missing |
|---|---|---|---:|
| 1 | `EIP712Domain` type-hash literal present | the exact 82-byte string `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)` somewhere in the runtime bytecode | 100 |
| 2 | `name` field present | a string literal whose keccak256 matches a known token name (e.g. `USD Coin`, `Pharos Token`, `Wrapped PROS`) | 50 (info) |
| 3 | `version` field present | a string literal whose keccak256 matches a known version string (e.g. `1`, `2`, `v1`, `v2`) | 30 (info) |
| 4 | `chainId` is fetched via `chainid()` opcode, not hardcoded | the bytecode contains the `0x46` CHAINID opcode near the DOMAIN_SEPARATOR computation | 95 |
| 5 | `verifyingContract` is `address(this)` | the bytecode contains the `ADDRESS` opcode (0x30) near the DOMAIN_SEPARATOR computation | 90 |
| 6 | `DOMAIN_SEPARATOR()` is a public view | the bytecode contains the function selector `0x3644e515` (DOMAIN_SEPARATOR()) | 100 |
| 7 | No fixed-salt trap | the bytecode does NOT contain a literal `keccak256("EIP712Domain(...bytes32 salt...)")` with a fixed salt — that's the EIP-712-with-salt variant, and a fixed salt is a deployment-time error that loses replay protection across deployers | 80 |
| 8 | Domain separator includes a salt (optional but recommended) | the bytecode contains the `bytes32 salt` field — skip if no salt is intended (EIP-712 supports both variants) | 0 (info only) |

Each check has one of three verdicts: **PASS**, **FAIL**, **NOT_FOUND** (the bytecode doesn't appear to implement EIP-712 at all).

## How to run it

### CLI (zero-deps: bash + curl only)

```bash
bash scripts/audit.sh 0xYOUR_CONTRACT --network mainnet
bash scripts/audit.sh 0xYOUR_CONTRACT --network testnet --format json   # machine-readable
bash scripts/audit.sh 0xYOUR_CONTRACT --network mainnet --strict         # exit 1 on any FAIL
```

### Python (richer output, with full string-literal extraction)

```bash
pip install web3
python3 scripts/audit.py 0xYOUR_CONTRACT --network mainnet --format md
```

Both scripts:
1. Fetch the deployed bytecode via `eth_getCode`
2. Find the DOMAIN_SEPARATOR function (selector `0x3644e515`)
3. Extract all string literals from the bytecode (UTF-8 runs of length >= 3)
4. Check each literal against the 8 checks above
5. Print a per-check report + an overall 0-100 audit score

## Output format

### Markdown (default, for human review)

```markdown
# eip712dsa — EIP-712 audit report

**Contract:** 0x...
**Network:** Pharos Pacific Ocean Mainnet (chain 1672)
**Bytecode size:** 12,847 bytes
**Has DOMAIN_SEPARATOR():** yes
**Has permit():** yes (selector 0xd505accf)

## Overall score: 88 / 100 (PASS with warnings)

## Checks (8)

### ✓ PASS — #1 EIP712Domain type-hash literal
  - Found 82-byte string literal in bytecode at offset 0x2c10
  - Matches canonical type-hash for the 4-field domain

### ✗ FAIL — #4 chainId fetched via chainid() opcode
  - Could not find the 0x46 CHAINID opcode within 64 bytes of DOMAIN_SEPARATOR computation
  - This means the chainId is hardcoded — **the signature is replayable across forks**

### ✓ PASS — #5 verifyingContract is address(this)
  - Found 0x30 ADDRESS opcode within 32 bytes of DOMAIN_SEPARATOR

...

---
Generated by [eip712dsa](https://github.com/Tunde0058/EIP-712DSA) on Pharos Pacific Ocean Mainnet.
```

### JSON (for downstream tooling)

```json
{
  "contract": "0x...",
  "network": "mainnet",
  "bytecode_size": 12847,
  "has_domain_separator": true,
  "has_permit": true,
  "overall_score": 88,
  "checks": [
    {
      "id": 1,
      "name": "EIP712Domain type-hash literal",
      "verdict": "PASS",
      "evidence": "Found 82-byte string literal at offset 0x2c10",
      "severity": 100
    },
    ...
  ]
}
```

## Severity scoring

| Score | Label | Meaning |
|---:|---|---|
| 90-100 | CRITICAL | major security flaw — fix before deployment |
| 60-89 | HIGH | important issue — review carefully |
| 30-59 | MEDIUM | informational / best-practice |
| 0-29 | LOW | nice-to-have |

The overall score is the **minimum** of all FAIL'd checks' severities, or 100 if all PASS.

## What eip712dsa does NOT detect

Be honest about scope:

- It does NOT detect source-level EIP-712 bugs (it reads bytecode)
- It does NOT verify the signature recovery itself (uses ecrecover indirectly; that's the caller's job)
- It does NOT detect the "tightly packed" attack (where fields are re-ordered to break the typed-data hash) — that requires a decompiler
- It does NOT substitute for a full audit firm; treat the output as a starting point for review, not a verdict

## Safety reminders

- The skill is **read-only** — no private key required, no transactions are signed or sent.

## References

- `references/networks.json` — canonical Pharos network config
- `references/eip712-spec.md` — the EIP-712 spec, distilled into a one-pager for the matcher
- `references/selectors.json` — known function selectors (`permit`, `nonces`, `DOMAIN_SEPARATOR`, etc.)
- `examples/sample-report.md` — what a real audit looks like
