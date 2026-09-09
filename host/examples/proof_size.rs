// SPDX-License-Identifier: LGPL-3.0-or-later
//
//! Off-device proof-size estimator: the streamed proof size per statement, and the
//! device streaming time it predicts.
//!
//! ⚠️ The streaming phase only, and the rate is a property of the statement rather than
//! of the device; see `knowledge/measurement-instruments.md`.
//!
//! Run: `cargo run --release -p proofofseed-host --example proof_size`

use core::cell::RefCell;

use proofofseed_circuits::{
    bip39_seed_circuit, ethereum_address_circuit, hardened_child_circuit, master_key_circuit,
    normal_child_circuit, public_key_circuit,
};
use proofofseed_circuits::hasher::Keccak256Hasher;
use zkboo::circuit::Circuit;
use zkboo::crypto::HashPRG;
use zkboo::prover::challenge::{ChallengeBuilder, Party};
use zkboo::prover::proof::{ProofOptions, build_proof};
use zkboo::prover::proof::collectors::ResponseDataCollector;
use zkboo::prover::views::OwnedFlexibleWordTriplePool;
use zkboo::word::{CompositeWord, Word};

type H = Keccak256Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = [u8; 32];
type RC = usize;
type WTP = OwnedFlexibleWordTriplePool<RC>;

/// A sink counting the bytes the device would stream, in the app's framing, without
/// storing them.
#[derive(Debug)]
struct CountSink<'a> {
    out: &'a RefCell<usize>,
    include_input_share2: bool,
}

impl<'a> CountSink<'a> {
    fn add<W: Word, const N: usize>(&self, _w: CompositeWord<W, N>) {
        *self.out.borrow_mut() += core::mem::size_of::<W>() * N;
    }
}

impl<'a> ResponseDataCollector<[u8; 32], [u8; 32]> for CountSink<'a> {
    type InitArg = &'a RefCell<usize>;
    type FinalizeRes = ();
    fn new(challenge: Party, _sc: [u8; 32], _sn: [u8; 32], arg: Self::InitArg) -> Self {
        *arg.borrow_mut() += 1 + 32 + 32;
        Self {
            out: arg,
            include_input_share2: challenge.index() != 0,
        }
    }
    fn push_input_share2<W: Word, const N: usize>(&mut self, w: CompositeWord<W, N>) {
        if self.include_input_share2 {
            self.add(w);
        }
    }
    fn push_and_msg<W: Word, const N: usize>(&mut self, w: CompositeWord<W, N>) {
        self.add(w);
    }
    fn finalize(self, _digest: [u8; 32]) {
        *self.out.borrow_mut() += 32;
    }
}

fn proof_size<C: Circuit>(circuit: &C, n: usize) -> usize {
    let total = RefCell::new(0usize);
    let mut builder = ChallengeBuilder::<H, PS, PV, S, WTP>::new(b"seed", b"");
    for _ in 0..n {
        let it = builder.next_iter();
        circuit.exec(it.view_builder());
        it.finalize();
    }
    let challenge_entropy = builder.finalize();
    let _: Vec<()> = build_proof::<C, H, PS, PV, S, CountSink, WTP, _>(
        circuit,
        b"seed",
        challenge_entropy,
        n,
        ProofOptions::new().with_collector_arg::<CountSink>(&total),
    );
    total.into_inner()
}

/// Mean streamed bytes per second on the Flex for a statement without curve arithmetic,
/// over 36 verified rows spanning 3,171–3,367 B/s (2026-09-09).
const HASH_RATE: f64 = 3279.0;

/// Mean streamed bytes per second on the Flex for a statement with curve arithmetic,
/// over 6 verified rows spanning 3,527–3,547 B/s that do not overlap the hash rows
/// (2026-09-09).
const CURVE_RATE: f64 = 3532.0;

fn main() {
    println!(
        "statement           bytes/response   streaming s/response (excludes the challenge phase)"
    );
    // ⚠️ The rate is a property of the statement, not of the device.
    let rows: [(&str, usize, f64); 6] = [
        ("master_key", proof_size(&master_key_circuit(), 1), HASH_RATE),
        ("hardened_child", proof_size(&hardened_child_circuit(), 1), HASH_RATE),
        ("bip39_seed(r=2)", proof_size(&bip39_seed_circuit(2), 1), HASH_RATE),
        ("public_key", proof_size(&public_key_circuit(), 1), CURVE_RATE),
        ("normal_child", proof_size(&normal_child_circuit(), 1), CURVE_RATE),
        (
            "ethereum_address",
            proof_size(&ethereum_address_circuit(), 1),
            CURVE_RATE,
        ),
    ];
    for (name, sz, rate) in rows {
        println!("{name:18} {sz:>10}      ~{:.0} s  @{rate:.0} B/s", sz as f64 / rate);
    }
}
