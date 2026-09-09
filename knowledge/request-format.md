# The request wire format

A proof or exec request selects the statement, the derivation family, the response count and rounds, the request-anchored derivation parameters, the proof binding, and an optional response range.
The same parser runs on the device and in the host tests, so the format cannot drift and the strict-parse behaviour is testable without a device.

## Layout

All integers are big-endian.

1. `num_iters(2)`, present in every request; an exec request ignores it.
2. Optionally `rounds(2)`.
3. Optionally a `flags(1)` byte announcing the optional fields that follow.

`REQ_FLAG_FAMILY` announces a `family(1)` byte immediately after the flags byte, because it selects how the other fields are interpreted.
The remaining fields follow in flag-bit order:

| flag                | bit | payload                                                      |
| ------------------- | --- | ------------------------------------------------------------ |
| `REQ_FLAG_PATH`     | 0   | a witness path: `u8` count, then that many `u32` components  |
| `REQ_FLAG_INDEX_CC` | 1   | an asserted child `index(4)` and parent `chain_code(32)`     |
| `REQ_FLAG_BINDING`  | 2   | the proof binding: `u8` length, then that many bytes         |
| reserved            | 3   | claimed by the parked mnemonic-entry ceremony line; rejected |
| `REQ_FLAG_FAMILY`   | 4   | the derivation `family(1)`                                   |
| `REQ_FLAG_RANGE`    | 5   | the response range `start(2)` and `end(2)`, half-open        |

## Strictness

An empty buffer, or a prefix alone, yields the per-statement defaults: an empty binding, the BIP-32/secp256k1 family, and the full response sequence.

A buffer is malformed and rejected when it declares more than it carries, sets unknown flag bits, carries an unknown family byte, carries an out-of-order or overlong range, or carries undeclared trailing bytes.
A request-anchored proof must never silently fall back to a default on a field the host thought it sent.

`start < end <= num_iters` is checked against the clamped count on a proof request.
An exec request ignores `num_iters` and the range alike, so only `start < end` is checked there.

## The response range and entropy mode

No `REQ_FLAG_RANGE` emits the full sequence with fresh TRNG prover entropy.
Any range — including an explicit full range — switches the prover to the deterministic entropy of [`ranged-entropy.md`](ranged-entropy.md), so ranges produced by separate runs or devices assemble into one verifying proof.

## Families

The statement semantics are identical across families; only the derivation constants and the curve differ.

- `Bip32Secp256k1` (wire 0, the default): BIP-32 over secp256k1, master constant `"Bitcoin seed"`.
  Bitcoin, Ethereum and the EVM chains, and the wider BIP-44 ecosystem.
- `Slip10Ed25519` (wire 1): SLIP-10 over ed25519, master constant `"ed25519 seed"`, hardened-only, with the child key being `I_L` directly.
  Solana, TON, NEAR and others.
  This family carries only the recovery statements.
