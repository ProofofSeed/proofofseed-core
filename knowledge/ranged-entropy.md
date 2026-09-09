# Ranged proving and its deterministic entropy

Ranged proving emits any half-open sub-range `[start, end)` of a proof's response sequence, so a long proof is resumable, retriable, and can be split across several devices holding the same seed.

## Two facts shape the design

The Fiat-Shamir challenge is global.
The challenge entropy hashes the commitments of all `num_iters` iterations, plus the binding, so a prover emitting any sub-range must still run the full challenge phase; only the response phase is restricted to the range.
Skipping the responses before `start` costs one PRG step and one challenge draw each, and no circuit execution.
The skipping itself is `zkboo`'s `ProofBuilder::skip_iters`; this repository supplies only the request-keyed entropy the ranges must share.

Ranges compose only under identical prover entropy.
Responses produced in different runs, or on different devices, verify as one proof only if every run derives the same per-iteration view seeds and the same challenge sequence.
The prover entropy therefore cannot be drawn from a TRNG per run.
It is derived deterministically — the construction Picnic uses for its per-signature seeds — as a hash of the witness secrets and the full request transcript, bound to the circuit fingerprint and a transcript version.

## Why the derivation is safe

Re-running the prover with the same entropy and the same request re-opens exactly the same view pair of the same commitment in every iteration, which reveals nothing beyond the first run.

The danger is the same entropy under a *different* challenge: opening two different view pairs of the same seeded iteration reconstructs all three input shares, which is the witness.
The derivation therefore absorbs everything the challenge depends on, so that a change which could move the challenge also moves the entropy:

- the statement and family, `num_iters` (the challenge hashes that many commitments), the BIP-39 rounds, the derivation path, the asserted index and chain code, and the binding;
- the witness itself;
- the circuit's structural fingerprint, so that an app update changing a circuit — a gate-level optimisation, say — moves the entropy along with the commitments;
- `zkboo::PROOF_FORMAT_ID`, because a change to the emitted response bytes or to the commitment preimages is invisible to a circuit fingerprint but moves every commitment and hence the challenge;
- the three domain-separation tags this repository frames its own hashing with;
- `DETERMINISTIC_ENTROPY_VERSION`, this transcript's own layout.

The response range is deliberately not absorbed: ranges of the same proof must share the entropy.

Fields absorbed narrowed are bounded first.
`num_iters` in particular does not change the circuit fingerprint, so two counts sharing a low sixteen bits would derive the same entropy while phase one hashed a different number of commitments — a different challenge over the same seeds, which is the leak condition.
Every caller in this workspace bounds them already, but the function is public and a third-party prover must not be able to walk into it.

## The invariant the absorbed material cannot enforce

No secret may reach the circuit through `Frontend::input` without also appearing in the `WitnessMaterial` handed to `request_transcript_digest`.

The circuit fingerprint cannot substitute for this.
`zkboo-circuit-hash` ingests the *type* of each input and never its value, so two circuits differing only in a compiled-in witness value fingerprint identically and, if that value is not absorbed, derive identical entropy under different commitments.

That is why `WitnessMaterial::TestVector` absorbs no secret: it is sound only because its witnesses are public constants compiled into the binary.
Change one to another value of the same length and the guarantee is gone with no visible signal.
A new statement, or a new witness source for an existing one, must extend `WitnessMaterial` rather than rely on the fingerprint.

`WitnessMaterial` lives in the shared library rather than in app code precisely because this seam is where the secret enters the derivation, and it has to be testable.

## Variant disambiguation

The absorbed parts carry no variant tag, so variants are disambiguated by the absorbed part count together with the statement byte.
Each statement admits at most one variant per part count: the master key is `TestVector` (one part, on a device) or `Seed` (two, a real seed); BIP-39 is `TestVector` (one) or `Mnemonic` (three); the child statements are `Child` (four); the key statements are `Priv` (two).
A new variant must not create a (statement, part-count) collision with an existing one.

## Version history of the transcript

`DETERMINISTIC_ENTROPY_VERSION` covers this module's own field layout, and is bumped by hand on any change to what the transcript absorbs or how.

- Version 1 tracked the proof format by hand.
- Version 3 absorbs `zkboo::PROOF_FORMAT_ID`, a 32-byte content-derived identity, in place of the four-byte counter it retired.
  A change to the emitted response bytes or the commitment preimages now moves the entropy mechanically, whether or not anyone remembers to touch the constant.
- Version 4 adds the three domain-separation tags.
  `PROOF_FORMAT_ID` is the digest of a proof the *library* makes, so it moves when the library's framing changes but cannot see this repository's own use of that framing — the streaming verifier frames its binding with `TAG_CHALLENGE` directly.
  The tags are absorbed length-prefixed and in a fixed order, so no two can be read as one.

## Residual caveats

Mixing app versions across the runs of one ranged proof is unsupported.
A change to this transcript's own layout still relies on `DETERMINISTIC_ENTROPY_VERSION` being bumped by hand; only the proof format is tracked mechanically.

Unlike the TRNG mode, a deterministic prover re-runs identically, so a fault injected into a later run's challenge phase could in principle steer reopenings.
The TRNG mode therefore remains the default for full-sequence proofs, and ranged mode is opt-in per request.
