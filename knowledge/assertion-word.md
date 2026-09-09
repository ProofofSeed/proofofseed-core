# The assertion word

## The contract

Every statement circuit in this suite emits, as its last output word, the conjunction of the in-circuit assertions it made.
The word is a `u8`, so it is the last element of `Words::u8` whatever widths the payload uses — including for the curve statements, whose payload is entirely `u64` and whose `u8` section therefore holds nothing else.
`ASSERTION_TRUE` is the value it carries when every assertion held.

Read a circuit's outputs through `checked_payload`, which removes the word and returns `None` when it is false.
A zero secp256k1 scalar is the reachable false case: the comb asserts that `d·G` is finite, and no proof of a violated assertion verifies.

The serialised form a verifier pins, `serialize_words`, keeps the word, because it is part of what the proof commits to.
Only a caller consuming outputs as values — a derivation walk — wants it removed.

## Why raw slicing is dangerous

Slicing the raw outputs reads the assertion word as payload, and the failure is silent.
A 64-byte BIP-39 seed reads as 65 bytes, the master key derived from it is some other wallet's, and the proof about it still verifies, being self-consistent.
That is what happened when the word was introduced: `derive::bip39_seed` returned it as a 65th seed byte, so every statement resolved from a mnemonic was about a different wallet.

## Uniformity is this suite's discipline, not the library's

`zkboo` emits the word only where a circuit opens an `Assertions::scope`, which emits the flag when its body returns.
That makes "asserted but never emitted" unrepresentable, but it does not make the word universal: a circuit that asserts nothing opens no scope and emits no word. zkboo declined to make the word universal, on the grounds that it is part of the output contract of the circuits that have one rather than a fixed cost on all of them.

`checked_payload` strips the word without knowing which statements assert, so the shape has to be uniform for it to be correct.
Every `exec` in this repository therefore ends in a scope, and the ones with nothing to assert end in `assert_nothing`, which finishes the accumulator as the constant one at a cost of a single output word — no AND gate and no input share.
A new circuit that forgets loses a payload byte instead.
`circuits/tests/assertion_word.rs` is what makes forgetting fail.

## What none of this fixes

Advice not covered by an assertion is unconstrained, and nothing in the library can detect that.
A circuit that asserts nothing in the first place emits a word that means nothing.
The scope guarantees that assertions made are assertions emitted, and no more.
