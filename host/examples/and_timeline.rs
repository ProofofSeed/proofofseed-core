// SPDX-License-Identifier: LGPL-3.0-or-later
//
//! Locates AND-message-silent stretches in a single challenge-phase circuit pass.
//!
//! The on-device watchdog keepalive fires on `push_and_msgs` (per AND-gate). A stretch
//! of circuit with NO AND-messages emits no keepalive, so if it runs longer than the
//! watchdog window the device reboots. This measures, off-device, the fraction of one
//! pass that precedes the first AND-message and the largest inter-AND gap — to find
//! keepalive-silent regions (e.g. the secp256k1 fixed-base comb precompute on the
//! public base point, which involves no secret AND-gates).
//!
//!     cargo run -p proofofseed-host --example and_timeline --release

use core::cell::RefCell;
use std::time::Instant;

use proofofseed_circuits::{ethereum_address_circuit, master_key_circuit, public_key_circuit};
use proofofseed_circuits::hasher::Keccak256Hasher;
use zkboo::circuit::Circuit;
use zkboo::crypto::HashPRG;
use zkboo::prover::challenge::ChallengeBuilder;
use zkboo::prover::views::collectors::{ViewCommitmentsRelayer, ViewsDataCollector};
use zkboo::prover::views::{OwnedFlexibleWordTriplePool, ViewCommitment};
use zkboo::word::{CompositeWord, Word};

type H = Keccak256Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = [u8; 32];
type RC = usize;
type WTP = OwnedFlexibleWordTriplePool<RC>;

#[derive(Debug, Default)]
struct Timeline {
    start: Option<Instant>,
    last_and: Option<Instant>,
    first_and_s: f64,
    max_gap_s: f64,
    count: usize,
    /// Number of inter-AND gaps exceeding 5 ms / 20 ms / 50 ms off-device
    /// (×~200 on-device ≈ 1 s / 4 s / 10 s).
    gaps_5ms: usize,
    gaps_20ms: usize,
    gaps_50ms: usize,
    /// AND-index of the single largest gap, to locate it in the pass.
    max_gap_at: usize,
}

#[derive(Debug)]
struct TimingRelayer<'a> {
    inner: ViewCommitmentsRelayer<[u8; 32], [u8; 32]>,
    tl: &'a RefCell<Timeline>,
}

impl<'a> ViewsDataCollector<[u8; 32], [u8; 32]> for TimingRelayer<'a> {
    type InitArg = &'a RefCell<Timeline>;
    type FinalizeRes = [ViewCommitment<[u8; 32]>; 3];

    fn new(seeds: &[[u8; 32]; 3], arg: Self::InitArg) -> Self {
        arg.borrow_mut().start = Some(Instant::now());
        Self {
            inner: ViewCommitmentsRelayer::new(seeds, ()),
            tl: arg,
        }
    }

    fn push_input_share2<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) {
        self.inner.push_input_share2(word);
    }

    fn push_and_msgs<W: Word, const N: usize>(&mut self, and_msgs: [CompositeWord<W, N>; 3]) {
        let now = Instant::now();
        let mut tl = self.tl.borrow_mut();
        let start = tl.start.unwrap();
        if tl.count == 0 {
            tl.first_and_s = now.duration_since(start).as_secs_f64();
        } else {
            let gap = now.duration_since(tl.last_and.unwrap()).as_secs_f64();
            if gap > tl.max_gap_s {
                tl.max_gap_s = gap;
                tl.max_gap_at = tl.count;
            }
            if gap > 0.005 {
                tl.gaps_5ms += 1;
            }
            if gap > 0.020 {
                tl.gaps_20ms += 1;
            }
            if gap > 0.050 {
                tl.gaps_50ms += 1;
            }
        }
        tl.last_and = Some(now);
        tl.count += 1;
        drop(tl);
        self.inner.push_and_msgs(and_msgs);
    }

    fn finalize(self, commitments: [ViewCommitment<[u8; 32]>; 3]) -> Self::FinalizeRes {
        self.inner.finalize(commitments)
    }
}

fn measure<C: Circuit>(name: &str, circuit: &C) {
    let tl = RefCell::new(Timeline::default());
    let t0 = Instant::now();
    let mut builder = ChallengeBuilder::<H, PS, PV, S, WTP>::new(b"seed-entropy-demo", b"");
    let iter = builder.next_iter_custom::<TimingRelayer>(&tl);
    circuit.exec(iter.view_builder());
    iter.finalize();
    let total = t0.elapsed().as_secs_f64();
    let t = tl.borrow();
    let pct = if total > 0.0 {
        100.0 * t.first_and_s / total
    } else {
        0.0
    };
    let gap_pos = if t.count > 0 {
        100.0 * t.max_gap_at as f64 / t.count as f64
    } else {
        0.0
    };
    println!(
        "{name:18} pass {total:6.2}s  1st AND @ {:5.2}s ({pct:4.1}%)  total ANDs {}\n    \
         max gap {:6.3}s @ AND#{} ({gap_pos:4.1}% in)   gaps>5ms: {}  >20ms: {}  >50ms: {}",
        t.first_and_s, t.count, t.max_gap_s, t.max_gap_at, t.gaps_5ms, t.gaps_20ms, t.gaps_50ms
    );
}

fn main() {
    println!("one challenge-phase pass; where do AND-messages (keepalive triggers) appear?");
    measure("master_key", &master_key_circuit());
    measure("public_key", &public_key_circuit());
    measure("ethereum_address", &ethereum_address_circuit());
}
