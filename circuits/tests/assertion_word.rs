// SPDX-License-Identifier: LGPL-3.0-or-later

//! Where the assertion word lands in a circuit's outputs, and what happens to code that
//! does not know it is there.
//!
//! Every statement circuit emits, as its last output word, the conjunction of the
//! in-circuit assertions it made. zkboo emits that word only where a circuit opens an
//! assertion scope, so the uniformity is this suite's own discipline: a statement with
//! nothing to assert ends in `assert_nothing`, and this test is what makes forgetting
//! that go red rather than silent. It is a `u8`, so it lands at the end of `Words::u8` —
//! including for the curve statements, whose payload is entirely `u64` and whose `u8`
//! section therefore holds *nothing but* the assertion word. Code that slices the raw
//! outputs reads it as payload, and the failure is silent: a 64-byte BIP-39 seed reads as
//! 65 bytes and every key derived from it belongs to a different wallet.

use proofofseed_circuits::comb::ComputedComb;
use proofofseed_circuits::{
    ASSERTION_TRUE, PubKeyCircuit, bip39_seed_circuit, checked_payload, ethereum_address_circuit,
    hardened_child_circuit, master_key_circuit, normal_child_circuit, public_key_circuit,
    serialize_words, slip10_child_circuit, slip10_master_circuit,
};
use zkboo::circuit::Circuit;
use zkboo::executor::{ExecOptions, OwnedFlexibleWordPool, exec};
use zkboo::word::Words;

type WP = OwnedFlexibleWordPool<usize>;

fn run<C: Circuit>(circuit: &C) -> Words {
    exec::<C, WP, _>(circuit, ExecOptions::new())
}

#[test]
fn every_statement_ends_its_u8_section_with_a_true_assertion_word() {
    // (name, u8 payload bytes, u32 payload words, u64 payload words) — the shape a
    // consumer sees *after* the assertion word is removed. The elephants' `1` u8 word is
    // the assertion word alone, which is what makes "pop the last u8" the right rule
    // rather than "the payload is the u8 section".
    let cases: [(&str, Words, usize, usize, usize); 8] = [
        ("master_key", run(&master_key_circuit()), 64, 0, 0),
        ("hardened_child", run(&hardened_child_circuit()), 32, 0, 4),
        ("bip39_seed", run(&bip39_seed_circuit(2)), 64, 0, 0),
        ("public_key", run(&public_key_circuit()), 0, 0, 8),
        ("normal_child", run(&normal_child_circuit()), 32, 0, 4),
        ("ethereum_address", run(&ethereum_address_circuit()), 20, 0, 0),
        ("slip10_master", run(&slip10_master_circuit()), 64, 0, 0),
        ("slip10_child", run(&slip10_child_circuit()), 64, 0, 0),
    ];
    for (name, words, u8s, u32s, u64s) in cases {
        assert_eq!(words.u8.last(), Some(&ASSERTION_TRUE), "{name}: trailing assertion word");
        let payload = checked_payload(words).expect("assertions hold");
        assert_eq!((payload.u8.len(), payload.u32.len(), payload.u64.len()), (u8s, u32s, u64s),
            "{name}: payload shape");
    }
}

#[test]
fn a_violated_assertion_is_refused_rather_than_returned_as_payload() {
    // A scalar of zero has no public key: `d·G` is the point at infinity, and the comb
    // asserts the product is finite. This is the reachable case that makes the word false
    // — without it the check would be untestable, and an untestable check is not one.
    let words = run(&PubKeyCircuit::<ComputedComb>::new(vec![0u8; 32]));
    assert_eq!(words.u8.last(), Some(&0u8), "a zero scalar violates the comb's assertion");
    assert!(checked_payload(words).is_none(), "a violated assertion must not yield a payload");
    // The control: the same circuit on a valid scalar does yield one.
    assert!(checked_payload(run(&public_key_circuit())).is_some(), "control");
}

#[test]
fn the_serialized_statement_keeps_the_assertion_word() {
    // What a verifier pins is the whole output, assertion word included: it is part of
    // what the proof commits to, so stripping it there would reject every honest proof.
    // Only a consumer reading the outputs as *values* wants it gone.
    let words = run(&master_key_circuit());
    let serialized = serialize_words(&words);
    let u8_len = u16::from_be_bytes([serialized[0], serialized[1]]) as usize;
    assert_eq!(u8_len, 65, "serialized u8 section length");
    assert_eq!(serialized[2 + u8_len - 1], ASSERTION_TRUE, "assertion word survives serialization");
}
