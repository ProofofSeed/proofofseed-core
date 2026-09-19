# proofofseed-core

The shared proof-of-seed library: the ZKBoo statement circuits for the BIP-32/secp256k1 and SLIP-10/ed25519 derivation families, the request and proof-identity transcript with ranged deterministic-entropy proving, and the host-side prover and verifier.
It is the single implementation of the statements, consumed by the ProofofSeed Ledger app, the standalone `proofofseed` command-line tool, and the `proofofseed` Python package, so a change here reaches all three at once.

## Build and test

```sh
cargo test --release --workspace
```

Debug and sequential builds are impractical for these circuits.
`rust-toolchain.toml` pins the compiler to Rust 1.95.0, and `host/build.rs` refuses to build if this workspace's lockfile resolves a zkboo crate from a registry, which is what a `[patch.crates-io]` table does silently once a local version stops satisfying its requirement.
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

The `zkboo` crates at 1.2.0, resolved to the local working trees under `<zkboo>` by the workspace's `[patch.crates-io]`.
That release is not on crates.io yet, and every earlier published version is yanked.
The proof hash is Keccak-256 and is this ecosystem's to supply, in `proofofseed_circuits::hasher`.
See [`knowledge/dependencies.md`](knowledge/dependencies.md), which records why a patch table can disengage in silence.

Licensed LGPL-3.0-or-later; every source file carries an SPDX header.
