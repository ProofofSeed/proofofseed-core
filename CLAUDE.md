# proofofseed-core — project guide

The shared proof-of-seed library repo: statement circuits + request/ranged protocol + host prover/verifier, to be consumed by `../ledger-app`, `../rust-app` (`proofofseed-cli`), and `../python-app` (pip `proofofseed`).

**Current state: the library exists and every consumer is on it.** The plan of record is `knowledge/plan.md` (ratified 2026-08-20) — read it before doing anything here. The extraction landed as a verified copy of `../ledger-app` (`circuits/` → `proofofseed-circuits`, `host/psverify/` → `proofofseed-host`, with the PyO3 shim left behind in the app), and `../rust-app` and `../python-app` consume it.

**The consumer switch is done** (verified 2026-08-28, correcting a guide that still said it was not): `../ledger-app/app` depends on `proofofseed-circuits` by path, `../ledger-app/host/psverify` on `proofofseed-host`, and no copy of either survives in that repo — `app/src/` is device code only (UI, APDU, stack probe, heap monitor) and `psverify/src/` is a single PyO3 shim. There is one implementation of the statements, and a change here reaches the device app, the CLI and the Python package at once. The divergence the guide warned about is now only additive: this library carries `WitnessMaterial::Seed` and `::Mnemonic` for the software-wallet provers, which the app has no use for.

## State as of 2026-08-28 (branch `watchdog-safe-fingerprinting`, 9+ commits ahead of `main`, unmerged)

Three things landed together, and the first two were pre-existing faults found while making the third.

- 🚨 **The assertion word was being read as payload.** ZKBoo 2.0.0 makes every circuit emit, as its last output word, the conjunction of its in-circuit assertions; it is a `u8` and lands at the end of `Words::u8`. `derive::bip39_seed` returned it as a 65th seed byte, so **every statement `resolve()` built from a mnemonic was about a different wallet** — and its proof verified, being self-consistent. Read outputs through **`checked_payload`**, never raw. It also *checks* the word: a zero secp256k1 scalar makes it false, which is what gives the refusal a test that can go red.
- **The golden fixture is no longer the extraction acceptance.** ZKBoo 2.0.0's breaking format left nothing able to reproduce the 1.x bytes, so it had been failing on eight of nine rows. It is re-anchored and demoted to a proof-byte regression pin; `raw/master_key/n2` is the control row. Its header records what it stopped proving.
- ✅ **`PubKeyCircuit` emits the comb's affine coordinates** instead of wrapping them into a Jacobian point and converting back: **367,523 AND-messages and 2,904,268 B/response**, from 379,070 and 2,995,675 B (3.1%). The value is unchanged; the **fingerprint moved** (`7b317aa8…` → `77b98847…`). The Flex has **not** been reloaded, so the hardware gate will fail its fingerprint phase on `public_key` until it is.

Traps this cost, worth not repeating:

- 🪤 A `[patch.crates-io]` entry is ignored **in silence** once the local version stops satisfying the requirement. `rust-app` and `python-app` still required `zkboo = "1.0.0"`, so they linked the published 1.0.0 beside the shared circuits' 2.0.0 and failed on a `Circuit` trait that was plainly implemented. Both are bumped.
- 🪤 A dev-dependency's features unify into the lib build. Adding `zkboo-modular` only under `flash-comb` compiled and tested green here — because `[dev-dependencies]` turns that feature on — and broke in `rust-app`, which does not. **Verify a feature-gated dependency with `cargo build -p <crate>` alone**, or in a consumer.
- 🪤 Output checks that live only in an example are not run. Five of six in `validate_statements` had been failing since the version bump, under a closing line that announced all six correct regardless. They are now `circuits/tests/statement_outputs.rs`; the example exits non-zero.

Binding rules for this repo:

- **Soundness default is 438 responses (PQ-128), everywhere.** The classical-128 figure (219) must not appear in this repo or the app repos unless Stefano explicitly asks.
- The extraction's **proof-byte neutrality** was the milestone-1 acceptance and it passed; the golden fixture that established it could not survive ZKBoo 2.0.0's format break and is now a regression pin (see above). The standing rule it leaves behind: the deterministic-entropy transcript tags, the circuit fingerprints and `DETERMINISTIC_ENTROPY_VERSION` are **format commitments, not internals** — a change may move them, but never silently, and never in more rows than it means to.
- Extraction does not start until the ledger-app hardware gate has run and its branch is merged (see the plan's sequencing section).
- Rust: edition 2024, `no_std + alloc` for the circuits crate, LGPL-3.0-or-later, crates.io-style cross-deps with `[patch.crates-io]` path overrides to `<zkboo>/*` (and to this repo, from consumers).
- The general working agreements of `../CLAUDE.md` (the ProofofSeed project guide) apply: natural-language commits, milestone branches, acceptance-test-first, adversarial review before presenting completed chunks, no security-shortcut numbers.
