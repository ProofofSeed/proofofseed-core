# Dependencies

## The zkboo crates

The `zkboo` crates are required at 1.3.0 — `zkboo-keccak` and `zkboo-ripemd160` stayed at 1.2.0 and are required there — and resolve from crates.io, where `zkboo` is at 1.3.1 (published 2026-11-24, with the short-replay fix) and the others at the versions required.
Until that publication they resolved to local working trees through a `[patch.crates-io]` table, and the guard in `host/build.rs` refused a registry source; it now refuses any source other than crates.io, so a `[patch]` in a manifest or a cargo configuration cannot build this workspace unnoticed.
The circuit fingerprints, the request vectors and the proof-byte pin pass unchanged on the published crates (2026-11-24).

The requirements are caret requirements, so a local tree that moves within the major version satisfies them and the patch table stays engaged.
They are nonetheless moved to the release the trees carry, because a requirement left behind states something untrue and stops being the record of what this repository is built against.

While a `[patch.crates-io]` table was in use, an entry was ignored in silence once the local crate's version stopped satisfying the requirement, and cargo resolved the published crate instead with no warning.
When the zkboo crates take a major version, every requirement here and in all three consumers has to move with them, or the graph ends up holding two incompatible copies of one crate.
This has already cost a round of proofs; see [`zkboo-port-record.md`](zkboo-port-record.md).

## The proof hash

`zkboo` defines the `Hasher` trait and ships no concrete hash, leaving the choice to the consumer.
`proofofseed_circuits::hasher::Keccak256Hasher` is where this ecosystem makes it, once, so the device app, the CLI and the Python package cannot drift apart on it.

The hash is Keccak-256 — Ethereum's `keccak256`, with the original Keccak padding byte `0x01` rather than NIST SHA3-256's `0x06`.
It fixes the Fiat-Shamir transcript, the view commitments and the pseudo-random generator, so a consumer that picks anything else produces proofs none of the others will verify.

## Consumers

A change here reaches the `ledger-app`, `rust-app` and `python-app` repositories at once, so all four are built before one is called done.
