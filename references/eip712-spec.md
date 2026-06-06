# EIP-712 spec, distilled

A one-page distillation of [EIP-712](https://eips.ethereum.org/EIPS/eip-712) for the auditor. If you've already read EIP-712, skip this.

## The structure of an EIP-712 signed message

```
keccak256("\x19\x01" ‖ domainSeparator ‖ hashStruct(message))
```

Where:

```
domainSeparator = keccak256(abi.encode(
  keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
  keccak256(name),
  keccak256(version),
  chainId,
  verifyingContract
))

hashStruct(s) = keccak256(abi.encode(
  keccak256(typeHash),
  s.field1,
  s.field2,
  ...
))
```

## The 4-field canonical domain

The 82-byte string literal that MUST be embedded in the contract bytecode somewhere:

```
EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
```

If a contract implements EIP-712, this string is in the bytecode. The auditor's check #1 is just: does this string appear?

## The 5-field "with salt" variant

Some contracts (notably Permit2 by Uniswap) add a `bytes32 salt` field:

```
EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)
```

Audit risk: if `salt` is a hardcoded constant, the signature is replayable across deployers. The auditor's check #7 looks for this trap.

## Why chainId matters

The chainId is what makes the signature chain-specific. If the contract hardcodes chainId = 1 (Ethereum mainnet), then a signed message valid on Pharos Pacific (chain 1672) would also be valid on Ethereum mainnet — and a malicious chain replaying the message could drain the contract.

The correct way to get chainId in EVM is the `CHAINID` opcode (0x46), introduced in EIP-1884 (Istanbul). Pre-Istanbul contracts had to use a stored value, but those values are subject to constructor mistakes and chain forks.

The auditor's check #4 verifies the bytecode uses `CHAINID` (0x46) within 64 bytes of the DOMAIN_SEPARATOR computation.

## Why verifyingContract matters

`verifyingContract` binds the signature to a specific contract address. If two contracts share the same name, version, and chainId (e.g. two forks of the same token), the verifyingContract field is what keeps their signatures separate.

The correct way to get verifyingContract in EVM is `ADDRESS` (0x30), which pushes the address of the executing contract. The auditor's check #5 verifies the bytecode uses `ADDRESS` near DOMAIN_SEPARATOR.

## Function selectors the auditor recognizes

| Selector | Function | Notes |
|---|---|---|
| `0x3644e515` | `DOMAIN_SEPARATOR()` | public view; returns the EIP-712 domain separator |
| `0xd505accf` | `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` | EIP-2612 permit |
| `0x7ecebe00` | `nonces(address)` | EIP-2612 nonce getter |
| `0x8fcbaf23` | `name()` | ERC-20 name |
| `0x54fd4d50` | `version()` | EIP-712 version (custom) |
| `0x06fdde03` | `name()` (canonical ERC-20) | same as above |

## Common pitfalls the auditor flags

1. **Hardcoded chainId**: signature replayable across forks. CRITICAL.
2. **Hardcoded `verifyingContract`**: signature replayable across clones. CRITICAL.
3. **Missing `version`**: old signatures are valid forever, even after upgrading the contract. MEDIUM.
4. **Fixed `salt`** (in the 5-field variant): signature replayable across deployers. HIGH.
5. **No `DOMAIN_SEPARATOR()` public getter**: harder to verify on-chain; off-chain tooling needs the full type-hash. LOW.

## References

- [EIP-712: typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712) — the canonical spec
- [EIP-2612: permit extension for ERC-20](https://eips.ethereum.org/EIPS/eip-2612) — the most common usage
- [Permit2 by Uniswap](https://github.com/uniswap/permit2) — uses the 5-field-with-salt variant
- [OpenZeppelin: ECDSA.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol) — reference implementation
