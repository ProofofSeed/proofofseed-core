# proofofseed-core — project guide

The shared proof-of-seed library repo: statement circuits + request/ranged protocol + host prover/verifier, to be consumed by `../ledger-app`, `../rust-app` (`proofofseed-cli`), and `../python-app` (pip `proofofseed`).

**Current state: planning only.** The plan of record is `knowledge/plan.md` (ratified 2026-08-20) — read it before doing anything here. The code to be extracted lives in `../ledger-app` (`circuits/` = the future `proofofseed-circuits`, `host/psverify/` = the future `proofofseed-host` + a PyO3 shim that stays behind).

Binding rules for this repo:

- **Soundness default is 438 responses (PQ-128), everywhere.** The classical-128 figure (219) must not appear in this repo or the app repos unless Stefano explicitly asks.
- Extraction must be **proof-byte neutral** (milestone-1 acceptance: golden stream fixtures reproduce byte-identically) — the deterministic-entropy transcript tags, circuit fingerprints, and `DETERMINISTIC_ENTROPY_VERSION` in the moved code are untouchable during the move.
- Extraction does not start until the ledger-app hardware gate has run and its branch is merged (see the plan's sequencing section).
- Rust: edition 2024, `no_std + alloc` for the circuits crate, LGPL-3.0-or-later, crates.io-style cross-deps with `[patch.crates-io]` path overrides to `<zkboo>/*` (and to this repo, from consumers).
- The general working agreements of `../CLAUDE.md` (the ProofofSeed project guide) apply: natural-language commits, milestone branches, acceptance-test-first, adversarial review before presenting completed chunks, no security-shortcut numbers.
