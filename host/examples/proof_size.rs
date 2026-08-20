// SPDX-License-Identifier: LGPL-3.0-or-later
//
//! Off-device proof-size estimator. Generates the streamed proof for each statement
//! (host CPU, no device) and reports bytes per response, then predicts the on-device
//! runtime from the measured ~1.9 KB/s effective rate (proof bytes / wall-clock,
//! validated against master/hardened/bip39 on the Flex). Proof size is deterministic
//! in the circuit and independent of the seed, so this predicts device timing.
//!
//!     cargo run -p proofofseed-host --example proof_size --release

use core::cell::RefCell;

use proofofseed_circuits::{
    bip39_seed_circuit, ethereum_address_circuit, hardened_child_circuit, master_key_circuit,
    normal_child_circuit, public_key_circuit,
};
use zkboo::circuit::Circuit;
use zkboo::crypto::{HashPRG, Keccak256Hasher};
use zkboo::prover::challenge::{ChallengeBuilder, Party};
use zkboo::prover::proof::build_proof_custom;
use zkboo::prover::proof::collectors::ResponseDataCollector;
use zkboo::prover::views::OwnedFlexibleWordTriplePool;
use zkboo::word::{CompositeWord, Word};

type H = Keccak256Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = [u8; 32];
type RC = usize;
type WTP = OwnedFlexibleWordTriplePool<RC>;

/// A sink that only counts the bytes the device would stream (same framing as the
/// app: per response 1 + 32 + 32 header, each AND-message / input-share word, 32-byte
/// digest), without storing them.
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
    let _: Vec<()> = build_proof_custom::<C, H, PS, PV, S, CountSink, WTP>(
        circuit,
        b"seed",
        challenge_entropy,
        n,
        &total,
    );
    total.into_inner()
}

fn main() {
    const RATE: f64 = 1900.0; // bytes/sec effective, from the Flex benchmark
    println!("statement           bytes/response   predicted s/response (@1.9 KB/s)");
    let rows: [(&str, usize); 6] = [
        ("master_key", proof_size(&master_key_circuit(), 1)),
        ("hardened_child", proof_size(&hardened_child_circuit(), 1)),
        ("bip39_seed(r=2)", proof_size(&bip39_seed_circuit(2), 1)),
        ("public_key", proof_size(&public_key_circuit(), 1)),
        ("normal_child", proof_size(&normal_child_circuit(), 1)),
        (
            "ethereum_address",
            proof_size(&ethereum_address_circuit(), 1),
        ),
    ];
    for (name, sz) in rows {
        println!("{name:18} {sz:>10}      ~{:.0} s", sz as f64 / RATE);
    }
}
