// SPDX-License-Identifier: LGPL-3.0-or-later

//! The fingerprinting pass, hooked.
//!
//! A ranged proof binds its prover entropy to the circuit's structural fingerprint, and
//! computing that fingerprint means executing the whole circuit through a hashing
//! backend before the prover emits its first byte. On a secure element the pass must
//! service the OS watchdog while it runs, which means wrapping it in a hook — and a hook
//! that changed the digest would change the derived entropy, so the two paths have to
//! agree byte for byte.
//!
//! Both halves are checked here, because either alone would pass for the wrong reason: a
//! hook that never fired would agree with the unhooked path trivially, and a hook that
//! fired but perturbed the hasher would be caught only by the comparison.

use core::cell::Cell;

use proofofseed_circuits::ranged::{
    circuit_fingerprint_hooked, deterministic_seed_entropy, deterministic_seed_entropy_hooked,
};
use proofofseed_circuits::comb::ComputedComb;
use proofofseed_circuits::request::Family;
use proofofseed_circuits::{
    BIP39_SEED, HARDENED_CHILD, bip39_seed_circuit, hardened_child_circuit,
    statement_fingerprint, statement_fingerprint_hooked,
};
use zeroize::Zeroizing;
use zkboo::backend::BackendHook;
use zkboo_circuit_hash::hash_circuit;

/// Counts backend operations. Does nothing else — the point is to observe that the hook
/// is reached, without giving it any way to influence the pass.
struct Counting<'a> {
    ops: &'a Cell<usize>,
}

macro_rules! counting_post {
    ($($m:ident),* $(,)?) => {
        $(
            fn $m(&mut self) {
                self.ops.set(self.ops.get() + 1);
            }
        )*
    };
}

impl<'a> BackendHook for Counting<'a> {
    type InitArg = &'a Cell<usize>;

    fn new(arg: Self::InitArg) -> Self {
        Self { ops: arg }
    }

    counting_post!(
        post_input,
        post_alloc,
        post_constant,
        post_output,
        post_not,
        post_bitxor,
        post_bitand,
        post_bitxor_const,
        post_bitand_const,
        post_carry,
    );
}

#[test]
fn the_hooked_fingerprint_equals_the_unhooked_one() {
    let circuit = hardened_child_circuit();
    let ops = Cell::new(0);
    let hooked = circuit_fingerprint_hooked::<_, Counting>(&circuit, &ops);
    let plain: [u8; 32] = hash_circuit::<_, zkboo::crypto::Keccak256Hasher>(&circuit);
    assert_eq!(hooked, plain, "the hook must not perturb the digest");
}

#[test]
fn the_hook_actually_fires() {
    // Without this the equality above would pass for a hook that was never reached.
    let ops = Cell::new(0);
    let _ = circuit_fingerprint_hooked::<_, Counting>(&hardened_child_circuit(), &ops);
    assert!(ops.get() > 1000, "hook fired {} times", ops.get());
}

#[test]
fn the_hooked_entropy_equals_the_unhooked_entropy() {
    let circuit = hardened_child_circuit();
    let digest = Zeroizing::new([7u8; 32]);
    let ops = Cell::new(0);
    let hooked = deterministic_seed_entropy_hooked::<_, Counting>(&circuit, &digest, &ops);
    let plain = deterministic_seed_entropy(&circuit, &digest);
    assert_eq!(*hooked, *plain);
    assert!(ops.get() > 1000, "hook fired {} times", ops.get());
}

#[test]
fn the_pass_scales_with_the_round_count_while_the_hook_count_tracks_it() {
    // The reason the unhooked pass is dangerous at all: work grows with `rounds`. The
    // operation count is the same quantity the watchdog cadence is measured against, so
    // this is the scaling that the refusal bound exists to cap.
    let counts: Vec<usize> = [2usize, 8, 64]
        .into_iter()
        .map(|rounds| {
            let ops = Cell::new(0);
            let _ = circuit_fingerprint_hooked::<_, Counting>(&bip39_seed_circuit(rounds), &ops);
            ops.get()
        })
        .collect();
    assert!(counts[1] > counts[0], "8 rounds must cost more than 2: {counts:?}");
    assert!(counts[2] > 4 * counts[1], "64 rounds must cost far more than 8: {counts:?}");
}

#[test]
fn the_hooked_statement_fingerprint_equals_the_unhooked_one() {
    // The dispatch a device actually calls, not just the primitive underneath it.
    for (statement, rounds) in [(HARDENED_CHILD, 2048usize), (BIP39_SEED, 8)] {
        let ops = Cell::new(0);
        let hooked = statement_fingerprint_hooked::<ComputedComb, Counting>(
            Family::Bip32Secp256k1,
            statement,
            rounds,
            None,
            None,
            &ops,
        );
        let plain = statement_fingerprint::<ComputedComb>(
            Family::Bip32Secp256k1,
            statement,
            rounds,
            None,
            None,
        );
        assert_eq!(hooked, plain, "statement {statement}");
        assert!(hooked.is_some());
        assert!(ops.get() > 1000, "hook fired {} times", ops.get());
    }
}
