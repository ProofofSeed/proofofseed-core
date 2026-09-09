# proofofseed-core — project guide

The shared proof-of-seed library: statement circuits, the request and ranged protocol, and the host prover and verifier.
It is consumed by `../ledger-app`, `../rust-app` (`proofofseed-cli`) and `../python-app` (the pip package `proofofseed`).

The plan of record is [`knowledge/plan.md`](knowledge/plan.md); read it before changing anything here.
The rest of [`knowledge/`](knowledge/README.md) carries the design records, and the code documentation deliberately does not repeat them.

## Current state

The library exists and every consumer is on it.
`../ledger-app/app` depends on `proofofseed-circuits` by path and `../ledger-app/host/psverify` on `proofofseed-host`; no copy of either survives in that repository, whose `app/src/` is device code only and whose `psverify/src/` is a single PyO3 shim.
There is one implementation of the statements, and a change here reaches the device app, the command-line tool and the Python package at once.
The only divergence is additive: this library carries `WitnessMaterial::Seed` and `::Mnemonic` for the software-wallet provers, which the device app has no use for.

The stack is on zkboo v1.2.0 plus the assertion, advice and format-identity release, ported 2026-09-04 and 2026-09-06 and confirmed on hardware 2026-09-07 and 2026-09-09.
`DETERMINISTIC_ENTROPY_VERSION` is 4.
What each release required, and what was measured to establish that nothing else moved, is in [`knowledge/zkboo-port-record.md`](knowledge/zkboo-port-record.md).

## Rules for this repository

- **The soundness default is 438 responses everywhere.**
  The classical-128 figure (219) must not appear in this repository or the app repositories unless Stefano explicitly asks.
- **Every circuit ends in an assertion scope**, `assert_nothing` where there is nothing to assert, and outputs are read through `checked_payload`.
  `circuits/tests/assertion_word.rs` is what makes forgetting fail.
- **The entropy transcript tags, the circuit fingerprints and `DETERMINISTIC_ENTROPY_VERSION` are format commitments, not internals.**
  A change may move them, but never silently, and never in more rows of the proof-byte fixture than it means to.
- **No secret may reach a circuit through `Frontend::input` without also appearing in the `WitnessMaterial` handed to `request_transcript_digest`.**
  The circuit fingerprint cannot substitute for it; see [`knowledge/ranged-entropy.md`](knowledge/ranged-entropy.md).
- Rust edition 2024, `no_std + alloc` for the circuits crate, LGPL-3.0-or-later, crates.io-style cross-dependencies with `[patch.crates-io]` path overrides.
- Build and test in `--release`; targeted tests only.
- The working agreements of `../CLAUDE.md` apply.
