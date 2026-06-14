---
name: eip712dsa
description: Security-focused AI agent skill that audits any Pharos contract's deployed bytecode for EIP-712 correctness. Checks the EIP712Domain typehash string, the chainid() opcode (vs hardcoded), the verifyingContract as address(this), the DOMAIN_SEPARATOR() public view, the version() field, and the optional 5-field salt. Use this skill whenever an agent needs to verify a contract's signature scheme before approving it, recommending it, or relying on its signatures. Triggers on phrases like "is this contract EIP-712 safe", "audit the signature scheme", "check EIP-712", "verify domain separator", "pharos permit safety".
version: 2.0.0
author: Tunde0058
requires: read
bins: [bash, cast, jq]
network: pharos
tags: [security, eip-712, signature, domain-separator, permit, pharos, foundry, bash]
agents: [claude, codex, gemini, openclaw]
---

# EIP-712 Domain Separator Auditor

A bash + cast (Foundry) skill that audits any Pharos contract's deployed bytecode for EIP-712 correctness. Fetches the bytecode via `cast rpc eth_getCode` and runs 8 pattern checks in pure bash: typehash literal, `DOMAIN_SEPARATOR()` selector, `chainid()` (0x46) opcode, `ADDRESS` (0x30) opcode, `name()` / `version()` selectors, and the optional 5-field salt.

## What it checks

| # | Check | Severity |
|---|---|---:|
| 1 | `EIP712Domain` type-hash literal (4-field or 5-field) | 100 |
| 2 | `name()` function present | 50 |
| 3 | `version` field present (selector or literal) | 30 |
| 4 | `chainId` via `chainid()` opcode (not hardcoded) | 95 |
| 5 | `verifyingContract` is `address(this)` | 90 |
| 6 | `DOMAIN_SEPARATOR()` is a public view | 100 |
| 7 | 5-field salt is not hardcoded (manual check) | 80 |
| 8 | Salt included in domain (info) | 0 |

## Quick Actions

### Audit a contract on Pharos mainnet
```
Audit the EIP-712 implementation of contract 0xabc...def on Pharos mainnet
```

### Run the demo
```
Run the EIP-712 demo audit
```

### Get the audit as JSON
```
Audit contract 0xabc...def and return JSON
```

## Invocation

```bash
# Default: Markdown report, mainnet
bash scripts/audit.sh 0xYOUR_CONTRACT

# JSON output for an agent
bash scripts/audit.sh 0xYOUR_CONTRACT --format json

# Testnet
bash scripts/audit.sh 0xYOUR_CONTRACT --network testnet

# Strict mode: exit 1 on any FAIL (CI-friendly)
bash scripts/audit.sh 0xYOUR_CONTRACT --strict

# Demo
bash scripts/audit.sh --demo
```

## Flags

| Flag | Description |
|---|---|
| `0xCONTRACT` | Contract address to audit (positional, required unless `--demo`) |
| `--network mainnet \| testnet` | Pharos chain (default: mainnet) |
| `--format md \| json \| txt` | Output format (default: md) |
| `--strict` | Exit 1 on any FAIL or NOT_FOUND (CI-friendly) |
| `--demo` | Audit a known public mainnet ERC-20 |
| `-h`, `--help` | Show the help text |

## Networks

| Network | Chain ID | RPC URL |
|---|---:|---|
| mainnet (Pacific Ocean) | 1672 | `https://rpc.pharos.xyz` |
| atlantic-testnet | 688689 | `https://atlantic.dplabs-internal.com` |

Chain config is read from `assets/networks.json` at startup.

## Verdict logic

- `NOT_EIP712` — no `EIP712Domain(...)` string in bytecode; contract is out of scope
- `PASS` — all checks passed
- `PARTIAL` — some warnings, no critical FAILs (score >= 60)
- `FAIL` — at least one FAIL; do not trust signatures until resolved

## Dependencies

- **Foundry** (gives you `cast`) — install with `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- **bash 4+** — preinstalled on macOS, Ubuntu 20+, most Linux
- **jq** — required only for `--format json` output

## Security model

- The skill is **read-only** — it never imports, reads, or stores a private key.
- It reads deployed bytecode via `eth_getCode` (read-only RPC) — it cannot move funds or sign anything.
- It never submits a transaction, never writes to disk, never phones home.
- The only network call is to the user-configured RPC URL.

## Error handling

- Missing cast → "Error: 'cast' not found. Install Foundry..."
- Bad address format → "Error: contract must be 0x + 40 hex chars"
- Empty bytecode → "Error: contract has no deployed code (or address is an EOA, or RPC error)"
- Bad format → "Error: format must be md|json|txt"
- Bad network → "Error: unknown network: X (use 'mainnet' or 'testnet')"
- Unknown arg → "Unknown arg: X"

## Reference docs

- `references/eip712-spec.md` — relevant EIP-712 spec sections
- `references/selectors.json` — the curated function selector list

## Repository layout

```
EIP-712DSA/
├── SKILL.md              # This file
├── README.md             # Full documentation
├── foundry.toml          # Minimal config so cast can find the project root
├── LICENSE               # MIT
├── assets/
│   └── networks.json     # mainnet + testnet chain config
├── references/
│   ├── eip712-spec.md
│   └── selectors.json
├── examples/
│   └── sample-report.md
├── scripts/
│   └── audit.sh          # The single bash script that does the work
└── tests/
    └── test_audit_smoke.sh   # Offline smoke test
```
