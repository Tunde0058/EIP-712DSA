# EIP-712 Domain Separator Auditor

> Audit any Pharos contract's deployed bytecode for EIP-712 correctness — type-hash, chainid() opcode, verifyingContract, salt, version.

[![foundry](https://img.shields.io/badge/built%20with-Foundry-orange)]()
[![bash](https://img.shields.io/badge/script-bash-blue)]()
[![license](https://img.shields.io/badge/license-MIT-green)]()
[![pharos](https://img.shields.io/badge/network-Pharos-blueviolet)]()
[![ai-agent](https://img.shields.io/badge/callable%20by-AI%20agent-purple)]()

## What it is

This is a **skill built for the Pharos network** — a self-contained, deterministic bash script that runs on top of the [Pharos](https://pharos.network) EVM chains. It is **not** an AI agent itself, and not a chatbot. It is a single bash script that:

- takes input from the caller via CLI flags,
- reads live bytecode from Pharos via `cast` (Foundry),
- runs its own bytecode-pattern checks in pure bash,
- prints a structured report (Markdown, JSON, or text) to stdout.

Fetches the contract's deployed bytecode via `cast rpc eth_getCode`, then runs 8 pattern checks in pure bash: the canonical 76-byte / 89-byte `EIP712Domain(...)` typehash string, the `DOMAIN_SEPARATOR()` selector, the `chainid()` (0x46) opcode near the DOMAIN_SEPARATOR, the `ADDRESS` (0x30) opcode (i.e. `address(this)`), the optional `version()` selector, the presence of a 5-field salt, and the `permit()` selector. Each check is tagged PASS / FAIL / WARN / SKIP / N/A / NOT_FOUND, and the lot rolls up into an overall score + verdict of PASS / PARTIAL / FAIL / NOT_EIP712. Output as Markdown, JSON, or plain text.

## What it checks

| # | Check | What it looks for in bytecode | Severity |
|---|---|---|---:|
| 1 | `EIP712Domain` type-hash literal present | the 76-byte (4-field) or 89-byte (5-field) canonical string | 100 |
| 2 | `name()` function present | the 4-byte selector `0x06fdde03` somewhere in the bytecode | 50 |
| 3 | `version` field present | the `version()` selector `0x54fd4d50` or a short version-like literal (`1`, `v1`, `1.0.0`, …) | 30 |
| 4 | `chainId` via `chainid()` opcode, not hardcoded | the `0x46` CHAINID opcode within 64 bytes of the `DOMAIN_SEPARATOR` selector | 95 |
| 5 | `verifyingContract` is `address(this)` | the `0x30` ADDRESS opcode within 32 bytes of the `DOMAIN_SEPARATOR` selector | 90 |
| 6 | `DOMAIN_SEPARATOR()` is a public view | the 4-byte selector `0x3644e515` somewhere in the bytecode | 100 |
| 7 | 5-field salt is not hardcoded | (5-field variant only) — manual source check recommended | 80 |
| 8 | Salt included in domain (best practice) | 5-field variant present | 0 (info) |

Each check has one of these verdicts: **PASS**, **FAIL**, **WARN**, **SKIP**, **N/A**, **NOT_FOUND**, or **INFO**. The overall verdict is:

| Overall | Meaning |
|---|---|
| `NOT_EIP712` | No `EIP712Domain(...)` string in bytecode — contract is out of scope |
| `PASS` | All checks passed |
| `PARTIAL` | Some warnings, no critical FAILs (score >= 60) |
| `FAIL` | At least one FAIL — do not trust signatures until resolved |

## Use it from an AI agent

This skill is designed to be **called by an AI agent** (a Claude Code / Codex / Cursor agent, the Pharos Agent Center, or any custom LLM agent). The agent reads `SKILL.md` to discover the skill's flags, fills them in based on the user's request, and runs the bash script in its sandbox. The agent's job is just to translate "is this contract's EIP-712 correct?" into `bash scripts/audit.sh 0xADDR`.

Typical agent-side flow:

```text
User -> Agent: "Is this contract's EIP-712 implementation correct?"
Agent -> looks up SKILL.md for EIP-712 Domain Separator Auditor
Agent -> runs: bash scripts/audit.sh 0xCONTRACT
Agent -> reads the verdict, presents the per-check findings to the user
```

The script prints structured output to stdout and human-readable progress to stderr, so the agent can parse the stdout cleanly (with `jq`) without being polluted by progress messages.

## Install

You need three things: **Foundry** (for `cast`), **jq** (for JSON pretty-printing), and **git** (to clone the repo).

```bash
# 1. Install Foundry (gives you cast, forge, anvil, chisel)
curl -L https://foundry.paradigm.xyz | bash
foundryup
# Reload your shell so the new commands are on PATH:
exec $SHELL
cast --version   # should print 1.x or higher

# 2. Install jq (required for --format json)
# macOS:   brew install jq
# Ubuntu:  sudo apt-get install -y jq
# Alpine:  apk add jq
jq --version

# 3. Clone this repo
git clone https://github.com/Tunde0058/EIP-712DSA.git
cd EIP-712DSA
chmod +x scripts/*.sh tests/*.sh
```

## Quick test (30 seconds, no API keys needed)

```bash
bash scripts/audit.sh --demo
```

The demo audits a known public mainnet ERC-20 contract and prints a Markdown report.

## Usage

```bash
# Default: Markdown report, mainnet
bash scripts/audit.sh 0xYOUR_CONTRACT

# JSON output for an agent
bash scripts/audit.sh 0xYOUR_CONTRACT --format json

# Testnet
bash scripts/audit.sh 0xYOUR_CONTRACT --network testnet

# Strict mode: exit 1 on any FAIL (CI-friendly)
bash scripts/audit.sh 0xYOUR_CONTRACT --strict

# Demo: known public mainnet ERC-20
bash scripts/audit.sh --demo
```

### All flags

```
0xCONTRACT --network mainnet|testnet --format md|json|txt --strict --demo --help
```

| Flag | Description |
|---|---|
| `0xCONTRACT` | The contract address to audit (positional, required unless `--demo`) |
| `--network mainnet \| testnet` | Pharos chain (default: mainnet) |
| `--format md \| json \| txt` | Output format (default: md) |
| `--strict` | Exit 1 on any FAIL or NOT_FOUND (CI-friendly) |
| `--demo` | Audit a known public mainnet ERC-20 (no args needed) |
| `-h`, `--help` | Show the help text |

## Networks

The skill is built to run against the Pharos EVM chains. The chain config is stored in `assets/networks.json` and read at startup — no hardcoded URLs in the script.

| Network | Chain ID | RPC URL | Default |
|---|---:|---|:---:|
| mainnet (Pacific Ocean) | 1672 | `https://rpc.pharos.xyz` | ✓ |
| atlantic-testnet | 688689 | `https://atlantic.dplabs-internal.com` |  |

The script defaults to mainnet. Pass `--network testnet` to use the testnet instead. You can also override the RPC URL by editing `assets/networks.json`.

## Set it up in an AI agent

Three install paths for any AI agent that wants to call this skill.

### Path A — Pharos Agent Center (for the official Pharos LLM agent)

The Pharos Agent Center is the official agent runtime for the Pharos network. It reads `SKILL.md` from any skill repo to discover capabilities, dependencies, and required flags.

1. **Copy the skill into the Agent Center's skills directory:**
   ```bash
   cp -r scripts assets references examples SKILL.md README.md foundry.toml LICENSE \
     ~/.pharos/agent-center/skills/EIP-712DSA/
   ```

2. **Reload the Agent Center's skill registry:**
   ```bash
   pharos-agent reload-skills
   ```

3. **Invoke from the agent's chat UI:**
   ```text
   User: "Is this Pharos contract's EIP-712 implementation correct?"
   Agent Center: loads EIP-712 Domain Separator Auditor, runs:
     bash ~/.pharos/agent-center/skills/EIP-712DSA/scripts/audit.sh 0xCONTRACT
   ```

### Path B — `npx skills add` (for Claude Code, Cursor, Codex, generic MCP agents)

```bash
npx skills add https://github.com/Tunde0058/EIP-712DSA --skill EIP-712DSA
```

### Path C — Manual copy (any agent that reads `~/.claude/skills/`)

```bash
mkdir -p ~/.claude/skills/EIP-712DSA
cp -r scripts assets references examples SKILL.md README.md foundry.toml LICENSE ~/.claude/skills/EIP-712DSA/
```

### Path D — Direct invocation (shell agents, cron jobs, CI pipelines)

```bash
bash scripts/audit.sh 0xCONTRACT
```

### What the agent says to invoke this skill

| Caller says | Script invocation |
|---|---|
| Audit `0xabc...def` for EIP-712 correctness on Pharos mainnet | `bash scripts/audit.sh 0xabc...def` |
| Run the EIP-712 demo audit | `bash scripts/audit.sh --demo` |
| Audit and return JSON for an agent | `bash scripts/audit.sh 0xabc...def --format json` |
| "Run the demo" | `bash scripts/audit.sh --demo` |

## Security model

The skill is **read-only by design**:

- The script never imports, reads, or stores a private key.
- It reads deployed bytecode via `eth_getCode` (read-only RPC) — it cannot move funds or sign anything.
- It never submits a transaction, never writes to disk, never phones home.
- The only network call is to the user-configured RPC URL.

## Framework

| Layer | Tech | Purpose |
|---|---|---|
| Engine | **bash 4+** | Script host (single file per skill) |
| RPC client | **Foundry / cast** | Bytecode fetch via `cast rpc eth_getCode` |
| Bytecode analysis | **pure bash** | PUSH-N opcode iteration, printable string extraction, 4-byte selector scan, opcode-near-offset lookup — all in bash arrays + `printf '%d'` |
| Chain config | **JSON** (`assets/networks.json`) | Network endpoints + chain IDs |
| Data format | **JSON** | Output via `jq` for agent consumption |
| Runtime | Any POSIX shell, Foundry 1.0+ | Tested on Linux + macOS |

## Dependencies

**Required:**
- [Foundry](https://getfoundry.sh) (gives you `cast`)
- `bash` 4+ (preinstalled on macOS, Ubuntu 20+, most Linux)
- `jq` (for `--format json` output)

**Optional:**
- `git` — only required if you're cloning the repo (you already have it)

## Tests

Each repo ships with a bash smoke test that verifies:
1. `--help` works (no cast required)
2. No contract shows the usage hint
3. Bad address format is rejected
4. Bad format is rejected
5. Bad network is rejected
6. The cast-missing error is clear (when cast is not installed)

```bash
bash tests/test_audit_smoke.sh
```

The test runs offline by default. If cast is installed, the live `eth_getCode` fetch will take a few seconds.

## Reference docs

The skill ships with two reference documents:

- `references/eip712-spec.md` — the relevant sections of the EIP-712 spec this auditor checks against
- `references/selectors.json` — the curated list of 4-byte function selectors this auditor recognizes

## Repository layout

```
EIP-712DSA/
├── SKILL.md              # Skill contract
├── README.md             # This file
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

## License

MIT — see `LICENSE`.
