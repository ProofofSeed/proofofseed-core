# proofofseed-core

The shared proof-of-seed library: the ZKBoo statement circuits (BIP-32/secp256k1 and SLIP-10/ed25519 families), the request/proof-identity transcript with ranged deterministic-entropy proving, and the host-side prover/verifier — consumed by the Ledger app, the standalone `proofofseed` CLI, and the `proofofseed` Python package.

**Status: extraction half-done (milestone M1a).** The library stands here as a verified copy of `../ledger-app`'s `circuits/` and `host/psverify/` (renamed, PyO3-stripped), with the full test battery green and a proof-byte-neutrality gate pinning every stream byte-identical to the pre-extraction code; ledger-app still builds from its own copy until the consumer switch (M1b, gated on its hardware milestone). The plan of record — architecture, milestones, and their acceptance tests — is [`knowledge/plan.md`](knowledge/plan.md).

## Structure

- `circuits/` — `proofofseed-circuits`: the statement circuits (both derivation families), request format, ranged proving with deterministic entropy (`no_std + alloc`).
- `host/` — `proofofseed-host`: streaming verifier, host prover (full and ranged), executor-based derivation, profiling examples.
- `knowledge/` — design records, starting with the plan of record.

Build/test: `cargo test --release --workspace` (the golden-stream neutrality gate included).

Depends on the `zkboo` crates (the underlying MPC-in-the-Head proof system); resolved to local working trees via `[patch.crates-io]` until zkboo 0.2.0 is published.
