# What a verifier must know to rebuild a circuit

The ZKBoo verifier replays the two opened parties from the proof and never reads witness *values*: the replayer ignores the value passed to `Frontend::input`.
It does read the witness *shape*, and it must agree with the prover on every public circuit constant.
A circuit built with a dummy witness of the correct length therefore suffices, which is what makes it possible to verify a proof about a device's real seed while knowing only the public parameters the request asserts.

## Public parameters

- The chain code and derivation index of the child statements, asserted by the verifier and carried in the request.
- The PBKDF2 round count of the BIP-39 statement.
- The derivation family: the two families build different circuits, so a proof made in one never verifies in the other.

Sharing one constructor per statement between prover and verifier is what keeps these from drifting.

## Witness shape

The master-key and BIP-39 statements allocate one circuit input per witness byte, so the witness length is a public parameter of the statement rather than an internal detail.
A proof over a 64-byte BIP-39 seed and one over the 16-byte BIP-32 test vector are structurally different circuits.
A verifier given no length falls back to the canonical test vector, which is what a stock device proves, so the fallback looks correct while rejecting every real seed proof.
`verify_with_shape` is the entry point that takes the shape; `witness_len` and `salt_len` are what travel with a proof.

Neither length has a default that is safe to assume, so one without the other is refused rather than guessed.

## The BIP-39 salt is witness

The salt is `"mnemonic"` followed by the passphrase.
Allocating it as a public constant, which is what the statement originally did, published the user's passphrase to whoever verified the proof.
Supplying it as witness costs one circuit input per salt byte — around 20 B on a 52 MB response, measured by `host/examples/salt_secrecy_cost.rs` — and discloses only the salt's length.

What that gives up is the verifier's certainty that the salt's first eight bytes spell `"mnemonic"`.
Nothing rests on it: a prover using some other eight-byte salt derives a different seed, the seed is pinned by whatever consumes it, and PBKDF2 is one-way so it cannot be steered to a target.
The length still separates "no passphrase" (8 B) from "passphrase" in practice.

The canonical test vector's salt is not the default one — it carries the passphrase `"TREZOR"` — so `bip39_salt_for(b"")` and the salt baked into `bip39_seed_circuit` differ, and a verifier reaching for the wrong one rebuilds the wrong circuit.

## Prover and verifier constructors of the curve statements

The curve statements' comb derives one chord slope per window from the secret scalar.
A verifier cannot compute those and does not need to: they are witness values, and a replayed view discards them as it discards every other input value.
`shaped` therefore hands the comb no scalar to follow, and `new` hands it the real one.
The two build the same circuit, gate for gate — only where a slope's value comes from differs — so their fingerprints agree, which `circuits/tests/fingerprint.rs` pins.

## A wrong circuit is refused by soundness, not by structure

Rebuilding the wrong circuit — the wrong witness shape, the wrong chain code, the wrong index, the wrong family — does not make verification fail outright.
The replay of a single response completes anyway often enough to matter, and the refusal is then only that the re-derived Fiat-Shamir challenges disagree.
Measured on the master key at one response: a wrong witness length is accepted about one time in nine, and a wrong expected output about one time in three; at four responses the second is about one in fifty, and at the deployment count of 438 neither is anything.

Two consequences.

A negative test written at a small response count is a coin flip, not a check, and a deterministic one: the entropy is fixed, so the same tree always gives the same answer and the dice are re-rolled only when a release moves the circuit.
Two such tests in this repository passed for months and turned red on the zkboo 1.3.0 port for no reason but that — one at two responses (1 in 81) and one lone-range refusal also at two (1 in 9).
Every refusal in this suite that is soundness rather than a length or parse check now runs at sixteen or twenty responses, and the two rates are pinned directly by `host/tests/seed_statements.rs` and `host/tests/ranged.rs`.

And it is why the software provers do not inherit the problem.
`proofofseed-cli` and the `proofofseed` Python package carry a sidecar that commits to the expected output, and they check that commitment before any replay, so a wrong output is refused structurally and at any response count.
The library's own `verify` has no sidecar and no such check.

## Statement outputs are taken from execution, never recomputed

`curve_statement_output` and `hardened_child_output` execute the real circuit with the supplied witness rather than recomputing what the circuit ought to produce.
The distinction is not academic: outputs carry the trailing assertion word, and any hand-written copy of the output framing omits it and rejects every honest proof.

Both helpers exist because a device proves against a key the host cannot compile in.
What has to be true of them is not that they return bytes but that they return *the* bytes a verifier holds, so their tests check both halves: a proof made with the supplied key verifies against them, and one made with a neighbouring key does not.
Without the second half the test passes for a helper returning any fixed circuit's output, which is the failure that left benchmark rows recorded as unverified.
