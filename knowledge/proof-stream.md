# The proof stream and its verifier

## Wire encoding

A device streams a ZKBoo proof as a flat byte sequence.
Per response: `challenge(1) || seed_challenge(32) || seed_next(32)`, then the AND-message and party-2 input-share words in circuit order, little-endian, then the unopened commitment digest (32 bytes).

`proofofseed-host` replays the circuit against that stream through a `ReplaySource` reading a byte cursor, mirroring `zkboo-harness`'s streaming pipe with the channel replaced by the bytes the host pulled over APDU, and checks the Fiat-Shamir challenges.
The host prover harness emits the same encoding, so a proof can be produced and verified entirely off-device, and `gen_stream_to` streams it into any writer at constant memory so a proof larger than RAM is not a special case.

## The response count is part of the statement

Soundness error is `(2/3)^num_iters`, so a caller must pass the count it *demands* and never one derived from the proof's own length.
A zero count would make every check vacuous — an empty proof would verify — so it is refused outright.

The stream must be exactly `num_iters` responses, with no trailing bytes.
Without that check a longer proof verifies under a shorter count: a relayer could downgrade a 438-response proof to a three-response one by claiming a smaller count and leaving the rest unread.

A malformed or truncated stream is treated as invalid and returns `false` rather than panicking.
That is implemented with `catch_unwind`, which is why consumers must build with `panic = "unwind"`.

## Per-response size is bimodal

A response carries party 2's input share only for two of the three challenges, so a one-response proof has exactly two possible sizes and they differ by one input share.
This is not noise and not drift: an off-device size estimate drawn from one fixed seed will disagree with a device that drew the other branch, by that exact amount.
The magnitude is a property of the circuit's witness and is predictable, so recording it as run-to-run variation understates it.

## Soundness parameter

A cheating prover survives one repetition with probability 2/3: of the three view pairs the verifier opens one, and for a false statement at most two of the three can be made consistent.
`n` independent repetitions leave soundness error `(2/3)^n`, and `(2/3)^n <= 2^-bits` requires `n >= bits / log2(3/2)`.

The deployment parameter targets 128-bit post-quantum soundness.
Grover search over the Fiat-Shamir challenge space gives a quadratic speedup, so the classical soundness error must be `2^-256`, and `n_eps(256) = 438` responses.
That is the whitepaper's N_epsilon and the only setting these crates use; lower arguments are meaningful to the formula but are not deployment parameters here.
