# proofofseed-core

The shared proof-of-seed library: the ZKBoo statement circuits (BIP-32/secp256k1 and SLIP-10/ed25519 families), the request/proof-identity transcript with ranged deterministic-entropy proving, and the host-side prover/verifier — consumed by the Ledger app, the standalone `proofofseed` CLI, and the `proofofseed` Python package.

**Status: this is the single implementation of the statements.** The extraction from `../ledger-app` is complete and so is the consumer switch: the device app depends on `proofofseed-circuits` and its host shim on `proofofseed-host`, with no copy of either surviving in that repo, and `../rust-app` and `../python-app` consume the same crates. A change here reaches the device app, the CLI and the Python package at once, so all four are built before one is called done. The plan of record — architecture, milestones and their acceptance tests — is [`knowledge/plan.md`](knowledge/plan.md).

## Reading a circuit's outputs

Since ZKBoo 2.0.0 every circuit emits, as its **last output word**, the conjunction of the in-circuit assertions it made. It is a `u8`, so it is the last element of `Words::u8` whatever widths the payload uses — for the curve statements the payload is entirely `u64` and the `u8` section holds nothing but the assertion word.

**Read outputs through `proofofseed_circuits::checked_payload`, never raw.** It removes the word and returns `None` when it is false. Slicing the raw outputs takes the assertion word for payload, and the failure is silent rather than loud: a 64-byte BIP-39 seed reads as 65 bytes, and every key derived from it belongs to a different wallet.

The serialized form a verifier pins (`serialize_words`) **keeps** the word — it is part of what the proof commits to. Only a caller consuming outputs as values wants it removed.

## Build and test

    cargo test --release --workspace

Debug and sequential builds are impractical for these circuits; use `--release`. The suite includes the statement outputs against their canonical vectors, the circuit fingerprints, the request vectors, the ranged-proving transcript, and a proof-byte pin (`host/tests/golden_streams.txt`) that fails when proof bytes move for any reason — deliberate or not.

Soundness default is **438 responses** (`(2/3)^438 ≤ 2^-256`, 128-bit post-quantum) throughout this repo and its consumers.

## Structure

- `circuits/` — `proofofseed-circuits`: the statement circuits for both derivation families, the request format, ranged proving with deterministic entropy, and the fixed-base comb table source (`no_std + alloc`).
- `host/` — `proofofseed-host`: the streaming verifier, the host prover (full and ranged), executor-based witness derivation, statement plumbing shared by every frontend, and the profiling/measurement examples.
- `knowledge/` — design records, starting with the plan of record.

## Dependencies

The `zkboo` crates (the underlying MPC-in-the-Head proof system) at **2.0.0**, published on crates.io and resolved to the local working trees under `<zkboo>` by the workspace's `[patch.crates-io]`.

⚠️ A `[patch.crates-io]` entry is ignored **in silence** once the local crate's version stops satisfying the requirement, and cargo resolves the published crate instead with no warning. When the zkboo crates take a major version, every requirement here and in all three consumers has to move with them, or the graph ends up holding two incompatible copies.

Licensed LGPL-3.0-or-later; every source file carries an SPDX header.
