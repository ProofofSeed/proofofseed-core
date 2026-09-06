# proofofseed-core — project guide

The shared proof-of-seed library repo: statement circuits + request/ranged protocol + host prover/verifier, to be consumed by `../ledger-app`, `../rust-app` (`proofofseed-cli`), and `../python-app` (pip `proofofseed`).

**Current state: the library exists and every consumer is on it.** The plan of record is `knowledge/plan.md` (ratified 2026-08-20) — read it before doing anything here. The extraction landed as a verified copy of `../ledger-app` (`circuits/` → `proofofseed-circuits`, `host/psverify/` → `proofofseed-host`, with the PyO3 shim left behind in the app), and `../rust-app` and `../python-app` consume it.

**The consumer switch is done** (verified 2026-08-28, correcting a guide that still said it was not): `../ledger-app/app` depends on `proofofseed-circuits` by path, `../ledger-app/host/psverify` on `proofofseed-host`, and no copy of either survives in that repo — `app/src/` is device code only (UI, APDU, stack probe, heap monitor) and `psverify/src/` is a single PyO3 shim. There is one implementation of the statements, and a change here reaches the device app, the CLI and the Python package at once. The divergence the guide warned about is now only additive: this library carries `WitnessMaterial::Seed` and `::Mnemonic` for the software-wallet provers, which the app has no use for.

## State as of 2026-09-06 — the advice is gone and the format has an identity

zkboo carried out the four requirements this repo filed in `<zkboo>/TODO-ASSERTIONS-HINTS.md`.
Ported here and in all three consumers, all four green. The upstream record is
`<zkboo>/MIGRATION-NEXT.md` and `<zkboo>/DESIGN-ASSERTIONS-HINTS.md`. Three things changed:

- **`PROOF_FORMAT_VERSION` is replaced by `PROOF_FORMAT_ID`**, a `[u8; 32]` that *is* the digest of
  a canonical reference proof, so re-pinning it and announcing the change are one edit. The
  entropy transcript in `circuits/src/ranged.rs` absorbs it in place of the counter, which is a
  change to that transcript's own layout, so `DETERMINISTIC_ENTROPY_VERSION` goes **2 → 3**.
- **An assertion accumulator comes only from `Assertions::scope`**, which emits the flag when its
  body returns, so "asserted but never emitted" has no spelling. zkboo declined to make the flag
  universal: **a circuit that opens no scope emits no word.** This suite still wants a uniform
  output shape, because `checked_payload` strips the word without knowing which statements assert,
  so **every circuit here ends in a scope** and the ones with nothing to assert end in
  `assert_nothing`. That uniformity is now this repo's discipline, not the library's — a new
  circuit that forgets it silently loses a payload byte.
- **The comb advice objects are deleted.** `PubKeyCircuit`, `AddressCircuit` and
  `NormalChildCircuit` hold a `mirror_scalar: bool` instead of a `PublicKeyAdvice`; `new` sets it
  and `shaped` clears it, and `exec` passes `Some(scalar_of(..))` or `None`. Nothing
  key-equivalent is held for the proof any more, and the arithmetic runs inside `exec` under the
  caller's `BackendHook` — so **both device measurements this repo was owing are withdrawn**, and
  the ledger app's three pre-circuit keepalives are removed.

**Nothing about the circuits moved, and that is measured twice over.** All eight statement
fingerprints are byte-identical (`proofofseed-host --example statement_fingerprints`, and the table
in `../ledger-app/docs/benchmarks.md`), and the proof-byte fixture's four `raw/` rows are identical
in length *and* digest — both `public_key` rows among them. Only the five `derived/` rows moved,
which is exactly what an entropy-transcript change should do and nothing else. Sizes, rates and the
device cost laws carry over untouched.

⚠️ What it trades: the heap loses the 1,664 B advice object and the **stack gains a known 224 B**
(`size_of::<CombMirror<u64, 4, Secp256k1PM>>()`, niche-packed so the verifier's `None` path costs the
same). On the device a heap shortfall reboots and a stack shortfall wipes, so check that 224 B
against the curve statements' measured high-water rather than re-reading the depth. And the mirror
runs once per circuit execution rather than once per proof (876 against one at 438 responses), which
zkboo measures at **+0.33% to +0.50%** of prover wall clock — a **host** figure at window width 5
over precomputed tables, on arithmetic whose long dependent 256-bit multiply-reduce chain is the
shape most likely to scale differently on a 32-bit core. Do not restate the per-response law from it.

The `new`/`shaped` fingerprint invariant is pinned at both layers: ours covers whole statements
(`circuits/tests/fingerprint.rs`), zkboo's fails first and localises to the comb
(`zkboo-ecc/tests/test_comb_fingerprint.rs`, `zkboo-bip32/tests/test_verifier_view.rs`).

## State as of 2026-09-04 — ported to zkboo v1.2.0

zkboo was re-architected and its history rebuilt. Every published version is **yanked**; the tip is
**v1.2.0**, whose number is *lower* than the `2.0.0` it replaces, and which is not on crates.io yet.
Ported here and in all three consumers, all four green. `<zkboo>/MIGRATION.md` is the upstream
record; what it meant for this repo:

- **The assertion word is the circuit's own now.** `zkboo::circuit::Assertions` replaced
  `Backend::assert_true` / `emit_assertions`, so every `exec` ends with `Assertions::output`. A
  circuit written without that line loses the word **silently**, and a caller stripping it with
  `checked_payload` eats a payload byte instead — which is exactly what happened to two hand-written
  test circuits during the port, one in `host/tests/solana.rs` and one in `rust-app/src/seed.rs`.
  Every circuit in the tree ends with the word, including the ones that assert nothing.
- **The comb's advice is a circuit input the caller computes**, not a backend hint. The elephant
  circuits carry a `PublicKeyAdvice`: `new` computes it from the key, `shaped` supplies only its
  count, which is what a verifier needs. Two consequences are filed in `<zkboo>/TODO.md`: the
  advice is key-equivalent and cannot be zeroized, and computing it services no io (a watchdog
  hazard on the device — measured at 0.317% of a response, so ~4.8 s on the Flex against a 30–50 s
  window; the app keepalives before it and it wants measuring on hardware).
- **The core crate ships no concrete `Hasher`.** `zkboo::crypto::Keccak256Hasher` and the `keccak`
  feature are gone. The ecosystem's choice now lives once, in
  `proofofseed_circuits::hasher::Keccak256Hasher`, which the device app, the CLI and the Python
  package all take.
- **Fifteen entry points became six**, each taking an options value: `build_proof`, `prove`,
  `verify`, `exec`, `build_challenge_entropy`, `ProofBuilder::new`, with `ProofOptions` /
  `VerifyOptions` / `ExecOptions` / `ChallengeOptions`.
- **`zkboo_ecc::montgomery` is `weierstrass`**, and its point types lost their `Curve` prefix.
- **No proof made before v1.2.0 verifies**, because the Fiat-Shamir transcript, the view commitments
  and the PRG are now separately domain-separated. `PROOF_FORMAT_VERSION` is still `3` — it does
  **not** discriminate this change, so a consumer using it as a compatibility gate is not protected.
  The streaming verifier must use `zkboo::crypto::{TAG_CHALLENGE, absorb_framed}` rather than its own
  copy of the framing.

The wire format did **not** move. The proof-byte fixture re-anchored with all nine digests changed
and both `public_key` rows byte-identical in length, every other delta a whole number of that
statement's own input shares. The curve statements' 1,696-byte input share is still 32 key bytes plus
52 comb slopes of 32 bytes. So sizes, rates and the device's cost laws all carry over; the circuit
fingerprints do not, and the current set is tabulated in `ledger-app/docs/benchmarks.md`.

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
