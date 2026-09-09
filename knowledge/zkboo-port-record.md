# Porting this library across the zkboo releases

The record of what each upstream release required here, and what was measured to establish that nothing else moved.
Upstream records are `<zkboo>/MIGRATION.md`, `MIGRATION-NEXT.md` and `DESIGN-ASSERTIONS-HINTS.md`.

## zkboo v1.2.0, 2026-09-04

zkboo was re-architected and its history rebuilt.
Every published version is yanked; the tip is v1.2.0, whose number is lower than the 2.0.0 it replaces, and it is not on crates.io.
The port landed here and in all three consumers together.

- **The assertion word became the circuit's own.**
  `zkboo::circuit::Assertions` replaced `Backend::assert_true` and `emit_assertions`, so every `exec` had to end by emitting the word.
  A circuit written without that line loses the word silently, and a caller stripping it with `checked_payload` eats a payload byte instead — which is what happened to two hand-written test circuits during the port, one in `host/tests/solana.rs` and one in `rust-app/src/seed.rs`.
- **The comb's advice became a circuit input the caller computes**, not a backend hint.
  The curve circuits carried a `PublicKeyAdvice`: `new` computed it from the key, `shaped` supplied only its count.
- **The core crate ships no concrete `Hasher`.**
  `zkboo::crypto::Keccak256Hasher` and the `keccak` feature are gone, and the choice moved to `proofofseed_circuits::hasher`.
- **Fifteen entry points became six**, each taking an options value.
- **`zkboo_ecc::montgomery` became `weierstrass`**, and its point types lost their `Curve` prefix.
- **No proof made before v1.2.0 verifies**, because the Fiat-Shamir transcript, the view commitments and the PRG are separately domain-separated.
  `PROOF_FORMAT_VERSION` was still `3` across that change, so it did not discriminate it, and a consumer using it as a compatibility gate was not protected.
  The streaming verifier must use `zkboo::crypto::{TAG_CHALLENGE, absorb_framed}` rather than its own copy of the framing.

The wire format did not move; see [`proof-byte-pins.md`](proof-byte-pins.md) for the evidence.
Sizes, rates and the device cost laws carried over; the circuit fingerprints did not.

## The assertion, advice and format-identity release, 2026-09-06

zkboo carried out the four requirements this repository filed.

- **`PROOF_FORMAT_VERSION` is replaced by `PROOF_FORMAT_ID`**, a `[u8; 32]` that is the digest of a canonical reference proof, so re-pinning it and announcing the change are one edit.
  The entropy transcript absorbs it in place of the counter.
- **An assertion accumulator comes only from `Assertions::scope`**, so "asserted but never emitted" has no spelling. zkboo declined to make the flag universal, which is why uniform output shape is this repository's discipline; see [`assertion-word.md`](assertion-word.md).
- **The comb advice objects are deleted.**
  `PubKeyCircuit`, `AddressCircuit` and `NormalChildCircuit` hold a `mirror_scalar: bool` instead of a `PublicKeyAdvice`, and `exec` passes the scalar or `None`.
  Nothing key-equivalent is held for the duration of a proof, and the arithmetic runs inside `exec` under the caller's backend hook, which withdrew both device measurements this repository owed and let the app drop its three pre-circuit keepalives.

Two further ports landed the same day.

- **The affine conversion is asserted, not computed.**
  The host supplies a point's affine coordinates and the circuit asserts they scale back, instead of inverting in circuit.
  This fixed a regression of +11.2% on Taproot and +8.1% on Solana, introduced when the hint gate went and `MontgomeryWordRef::inv` lost its prover hint, to below the pre-regression cost.
- **A `Montgomery<W, N>` newtype** separates a stored field value from a canonical residue, with `value()` renamed `canonical()`; see [`comb-tables.md`](comb-tables.md).

Nothing about the circuits moved, measured twice: all eight statement fingerprints are byte-identical, and the proof-byte fixture's four `raw/` rows are identical in length and digest while only the five `derived/` rows moved.
`DETERMINISTIC_ENTROPY_VERSION` went 2 to 3 for the format identity and 3 to 4 for the domain tags.

The `new`/`shaped` fingerprint invariant is pinned at both layers: this repository's covers whole statements (`circuits/tests/fingerprint.rs`), and zkboo's fails first and localises to the comb (`zkboo-ecc/tests/test_comb_fingerprint.rs`, `zkboo-bip32/tests/test_verifier_view.rs`).

### What the release traded on the device

Predicted: the heap loses the 1,664 B advice object and the stack gains a known 224 B. On the device a heap shortfall reboots and a stack shortfall wipes, so the 224 B was to be checked against the curve statements' measured high-water rather than against a re-read depth.

Confirmed on hardware 2026-09-07 and 2026-09-09, better than predicted.
Every curve heap peak came back 8 B below its pre-advice value, so the advice object arrived and left without the device seeing it, and the least servable hole is 3,400–6,848 B against a 2,048 B largest request.
The 224 B never appeared in the stack high-water at all, because a marginal frame adds to the high-water only if it sits on the deepest call path and this one does not.
The full record is `../../ledger-app/docs/benchmarks.md`.

The mirror also runs once per circuit execution rather than once per proof — 876 evaluations against one at 438 responses — which zkboo measures at +0.33% to +0.50% of prover wall clock.
That is a host figure at window width 5 over precomputed tables, on arithmetic whose long dependent 256-bit multiply-reduce chain is the shape most likely to scale differently on a 32-bit core, so the per-response device law must not be restated from it.

## Traps this cost

- A `[patch.crates-io]` entry is ignored in silence once the local version stops satisfying the requirement, and cargo resolves the published crate instead.
  `rust-app` and `python-app` still required `zkboo = "1.0.0"` after a major bump, so they linked the published 1.0.0 beside the shared circuits' 2.0.0 and failed on a `Circuit` trait that was plainly implemented.
- A dev-dependency's features unify into the lib build.
  Adding `zkboo-modular` only under `flash-comb` compiled and tested green here, because `[dev-dependencies]` turns that feature on, and broke in `rust-app`, which does not.
  Verify a feature-gated dependency with `cargo build -p <crate>` alone, or in a consumer.
- Output checks that live only in an example are not run.
  Five of six in `validate_statements` had been failing since a version bump, under a closing line that announced all six correct regardless.
  They are now `circuits/tests/statement_outputs.rs`, and the example exits non-zero.
