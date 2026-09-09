# The proof-byte pins

`host/tests/golden_streams.txt` records the length and Keccak-256 of the streams this repository's circuits and prover produce.
`host/tests/golden_streams.rs` recomputes each with the parameters that recorded it.

## What the rows assert

Proof bytes do not move unless a change is meant to move them, and when one is, exactly the intended rows move and the others are seen not to.

The deterministic-entropy transcript, the circuit fingerprints and `DETERMINISTIC_ENTROPY_VERSION` are format commitments rather than internals, so any of them moving shows up here.

The `raw/` rows draw prover entropy directly and the `derived/` rows draw it through the entropy transcript, so a change to the transcript must move the `derived/` rows and leave the `raw/` rows byte-identical.
That split is what makes a re-anchor evidence rather than a formality.

## What the rows stopped asserting

The fixture began as the extraction acceptance.
Recorded from the untouched `ledger-app` tree at `86a4656`, it showed that moving the circuits and the prover into this repository left every proof byte alone.
That claim was established and stands in the history: the fixture passed unaltered from the extraction through `6c5978c`.

It can no longer serve that purpose.
ZKBoo 2.0.0 was a breaking format change, so no tree that exists today reproduces the 1.x bytes, and the second implementation to record from is gone.
Re-anchoring is therefore circular with respect to the extraction, and the extraction is not what these rows assert any more.

## Re-anchoring history

**First recorded** at `ledger-app` `86a4656`.

**2026-08-21**, at `ledger-app` `130cb2e`, when the deterministic-entropy transcript began absorbing `PROOF_FORMAT_VERSION`.
The `derived/` rows moved and the `raw/` rows did not.

**2026-08-22**, `raw/bip39-r2/n2` only, when the BIP-39 PBKDF2 salt became witness instead of a public circuit constant, at one input-share byte per salt byte.

**2026-08-28**, against ZKBoo 2.0.0. Eight of the nine rows moved.

- `raw/bip39-r2/n2` and the `derived/hardened_child/*` rows shrank, the hardened-child ones by 32 B per response, which is that statement's 32 parent-key bytes appearing or not with the challenge.
  A row moving by exactly one input share is the bimodality landing the other way, not a defect.
- `derived/slip10_child/n4/full` kept its length and changed digest, because the `derived/` rows key their prover entropy on the circuit fingerprint, which 2.0.0 moved.
- `raw/public_key/*` fell by 3.77x, the elliptic-curve reduction 2.0.0 was built for.
- `raw/master_key/n2` did not move in length or digest.
  It was the one row whose circuit 2.0.0 left alone and whose entropy is raw rather than derived, so it was the control.

**2026-08-28, second time**, `raw/public_key/*` only: the public-key statement stopped wrapping the comb's affine output into a Jacobian point and converting it back.
The n=2 stream fell 181,086 B (3.02%) and the single response fell to 2,904,268 B. The other seven rows did not move, including the control and the hardened-child rows, whose statement shares none of the curve machinery.

**2026-09-04**, against zkboo v1.2.0.
All nine digests moved and no row could have been expected not to: v1.2.0 domain-separates the Fiat-Shamir transcript, the view commitments and the pseudo-random generator, so every party seed, commitment and challenge is drawn differently.
`raw/master_key/n2` moved with the rest, which cost the fixture its control row for that change; the lengths stood in for it, saying something a digest cannot.

The lengths said the wire format did not move.
Every delta was a whole number of input shares of the statement's own witness.

- `raw/master_key/n2` +32: two responses gaining the 16-byte seed witness.
- `raw/bip39-r2/n2` +214: two responses gaining 107 B, the 93-byte mnemonic plus the 14-byte salt.
- The four `hardened_child` rows +64, +32, +32, +0: two more of the four responses carrying the 32-byte parent key, with the three segments still summing to the full row.
- `derived/slip10_child/n4/full` +32, likewise one parent key.
- Both `raw/public_key` rows byte-identical in length.
  That was the load-bearing pair: v1.2.0 moved the comb's advice out of a backend hint and into circuit inputs the caller computes, and had that changed what goes on the wire these rows would have moved.
  The curve statements' 1,696-byte input share is still the 32-byte key plus 52 comb slopes of 32 bytes.

**2026-09-06**, against zkboo's assertion, advice and format-identity release.
Five rows moved and four did not, and the split is the finding.

Upstream, the comb's advice objects were deleted — the comb takes the scalar it multiplies by and follows it on the host, one window at a time, inside circuit execution — and `PROOF_FORMAT_VERSION` was replaced by `PROOF_FORMAT_ID`.
This repository's transcript absorbs the new constant in place of the old, a change to the transcript's own layout, so `DETERMINISTIC_ENTROPY_VERSION` went 2 to 3.

- The five `derived/` rows moved, their entropy now absorbing 32 different bytes under a new version.
  `hardened_child` full +32 and seg0-2 +32, seg2-3 and seg3-4 unchanged; `slip10_child` +32.
  Bimodality re-rolled by different entropy, not a format change.
- The four `raw/` rows were byte-identical in digest and length.
  That recovered what the control row had lost in the previous re-anchor: their entropy does not go through the transcript, so had the proof bytes moved they would have moved.
  Both `raw/public_key` rows are among them, which is load-bearing, the advice rework being entirely a curve-statement change that put not one byte differently on the wire.

**2026-09-06, second time**, for two changes ported together so that one re-anchor covers both.

1. The transcript absorbs zkboo's three domain-separation tags, each length-prefixed and in a fixed order.
   `DETERMINISTIC_ENTROPY_VERSION` went 3 to 4.
2. zkboo introduced the `Montgomery<W, N>` newtype and renamed `value()` to `canonical()`.
   Host-side API only.

Pairing them is what makes the split informative: change 1 must move exactly the transcript-derived rows and nothing else, and change 2 must move nothing at all.
Had change 2 touched a proof byte the `raw/public_key` pair would have said so, the newtype landing on the comb table's stored coordinates.

- `hardened_child` full +32, seg0-2 and seg2-3 unchanged, seg3-4 +32, with the three segments still summing to the full row (103,382 + 51,691 + 51,691 = 206,764).
  `slip10_child` -64.
- The four `raw/` rows unchanged.

Independently, all eight circuit fingerprints were unchanged across both releases, as the upstream release said they would be.
The current set is tabulated in `../../ledger-app/knowledge/benchmarks.md`.
