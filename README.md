# proofofseed-core

The shared proof-of-seed library: the ZKBoo statement circuits for the BIP-32/secp256k1 and SLIP-10/ed25519 derivation families, the request and proof-identity transcript with ranged deterministic-entropy proving, and the host-side prover and verifier.
It is the single implementation of the statements, consumed by the ProofofSeed Ledger app, the standalone `proofofseed` command-line tool, and the `proofofseed` Python package, so a change here reaches all three at once.

## Status

A research prototype: it has not been audited and is not for production use.
The 438-response default gives a soundness error of `(2/3)^438 <= 2^-256` only under the Fiat-Shamir transform and the security of the Keccak-256 hash, assumptions that have not been independently reviewed.
The `zkboo` crates it depends on are not yet published, so the workspace cannot be built from a clean checkout until they are; the dependency table says where they are expected to sit.

## Build and test

```sh
cargo test --release --workspace
```

Debug and sequential builds are impractical for these circuits.
`rust-toolchain.toml` pins the compiler to Rust 1.95.0, and `host/build.rs` refuses to build if this workspace's lockfile resolves a zkboo crate from anywhere but crates.io, so that a `[patch]` in force cannot pass for the published code.
It sits in `host` rather than `circuits` because a build script in `circuits` moves the Ledger app's application hash, that crate being linked into the device binary.
The suite covers the statement outputs against their canonical vectors, the circuit fingerprints, the request vectors, the ranged-proving transcript, and a proof-byte pin (`host/tests/golden_streams.txt`) that fails when proof bytes move for any reason.

The soundness default is 438 responses throughout this repository and its consumers: `(2/3)^438 <= 2^-256`, 128-bit post-quantum.

## Reading a circuit's outputs

Every statement circuit emits, as its last output word, the conjunction of the in-circuit assertions it made.
Read outputs through `proofofseed_circuits::checked_payload`, never by slicing the raw words: slicing takes the assertion word for payload, and a 64-byte BIP-39 seed then reads as 65 bytes with every key derived from it belonging to a different wallet.
The uniform output shape this relies on is the suite's own discipline rather than the library's, so every `exec` here ends in an assertion scope and the ones with nothing to assert end in `assert_nothing`.
See [`knowledge/assertion-word.md`](knowledge/assertion-word.md).

## Structure

- `circuits/` — `proofofseed-circuits`: the statement circuits for both derivation families, the request format, ranged proving with deterministic entropy, the proof hash, and the fixed-base comb table sources (`no_std + alloc`).
- `host/` — `proofofseed-host`: the streaming verifier, the host prover (full and ranged), executor-based witness derivation, the statement plumbing shared by every frontend, and the profiling and measurement examples.
- `knowledge/` — design records, indexed in [`knowledge/README.md`](knowledge/README.md).

## Dependencies

The `zkboo` crates resolve from crates.io: `zkboo` at 1.3.1, `zkboo-keccak` and `zkboo-ripemd160` at 1.2.0, and the others at 1.3.0.
The proof hash is Keccak-256 and is this ecosystem's to supply, in `proofofseed_circuits::hasher`.
See [`knowledge/dependencies.md`](knowledge/dependencies.md).

Licensed LGPL-3.0-or-later; every source file carries an SPDX header.

## Licence

Copyright © 2026 Stefano Gogioso.
The code is LGPL-3.0-or-later (see `LICENSE`); vendored third-party code keeps its own licence.
