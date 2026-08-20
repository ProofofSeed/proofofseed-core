# proofofseed-core

The shared proof-of-seed library: the ZKBoo statement circuits (BIP-32/secp256k1 and SLIP-10/ed25519 families), the request/proof-identity transcript with ranged deterministic-entropy proving, and the host-side prover/verifier — consumed by the Ledger app, the standalone `proofofseed` CLI, and the `proofofseed` Python package.

**Status: planning.** Nothing has been extracted yet; the code this repo will hold currently lives in `../ledger-app` (`circuits/`, `host/psverify/`). The ratified plan of record — architecture, milestones, and their acceptance tests — is [`knowledge/plan.md`](knowledge/plan.md).

## Planned structure

- `circuits/` — `proofofseed-circuits`: the statement circuits, request format, ranged proving (`no_std + alloc`).
- `host/` — `proofofseed-host`: streaming verifier, host prover, executor-based witness derivation.
- `knowledge/` — design records, starting with the plan of record.

Depends on the `zkboo` crates (the underlying MPC-in-the-Head proof system); resolved to local working trees via `[patch.crates-io]` until zkboo 0.2.0 is published.
