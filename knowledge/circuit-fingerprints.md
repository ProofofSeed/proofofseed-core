# Circuit fingerprints

`statement_fingerprint` returns the structural fingerprint of the circuit a prover would run for a given family and statement, computed from the public parameters alone.
It is the same digest the ranged prover binds its entropy to.

## Why it is well defined without a witness

The fingerprinting backend ingests an input's *type* and not its value, while an allocated constant contributes its value.
The chain code, index and round count therefore move the digest and the secret never does.
That is what makes the fingerprint safe to ask a device for: the answer carries no information about the seed.

The point of asking is to check that the circuit a device actually compiled is the circuit the host thinks it is.
Byte-equality of a ranged proof already implies that for whatever statement was proved, but only for that statement, and only at the cost of proving it.

## The watchdog constraint

The pass is a full execution of the circuit through a hashing backend, and it is silent: it emits no proof bytes and, unhooked, hands control back to nobody until it finishes.
On a secure element that is not merely slow but fatal, because the operating system's watchdog reboots the device out from under a command that stops answering, and this pass runs before the prover has emitted its first byte.

Its cost is linear in the gate count, so the round count of a PBKDF2 circuit scales it without bound while leaving its memory flat.
A BIP-39 circuit at 2048 rounds fingerprints in 553 times the time of one at 2 rounds, and 221 times that of a single-HMAC circuit, on the same heap.

A caller that can yield must therefore hook the pass rather than the prover alone, through `statement_fingerprint_hooked`.
The hook is transcript-neutral: it observes backend operations and never touches the hasher, so the digest and the derived entropy are identical to the unhooked path.
`circuits/tests/hooked_fingerprint.rs` pins that, and pins that the hook fires at all.
