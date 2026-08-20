// SPDX-License-Identifier: LGPL-3.0-or-later
//
//! Confirms (a) the BackendHook fires per backend operation and (b) where the wall-clock
//! gaps with NO backend op are — i.e. native (non-circuit) compute the hook can't service.
//!
//! Runs one challenge-phase pass of a circuit through `next_iter_hooked` with a hook that
//! timestamps every op. The secp256k1 fixed-base comb builds each window's point table with
//! *native* arithmetic (no backend ops), so a long max inter-op gap localises that build.
//!
//!     cargo run -p proofofseed-host --example op_timeline --release

use core::cell::RefCell;
use std::time::Instant;

use proofofseed_circuits::{master_key_circuit, public_key_circuit};
use zkboo::backend::BackendHook;
use zkboo::circuit::Circuit;
use zkboo::crypto::{HashPRG, Keccak256Hasher};
use zkboo::prover::challenge::ChallengeBuilder;
use zkboo::prover::views::collectors::ViewCommitmentsRelayer;
use zkboo::prover::views::OwnedFlexibleWordTriplePool;

type H = Keccak256Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = [u8; 32];
type RC = usize;
type WTP = OwnedFlexibleWordTriplePool<RC>;

#[derive(Debug, Default)]
struct OpStats {
    start: Option<Instant>,
    last: Option<Instant>,
    ops: usize,
    first_op_s: f64,
    max_gap_s: f64,
    max_gap_at: usize,
    gaps_1s: usize, // inter-op gaps > 1s (native stretches)
    // Inter-op gaps > 10 ms isolate the native (no-backend-op) table builds from the
    // microsecond-spaced circuit ops: their count ~ number of windows, their sum ~ total
    // native table-build time in the pass.
    native_gaps: usize,
    native_sum_s: f64,
}

struct CountHook<'a> {
    stats: &'a RefCell<OpStats>,
}

impl<'a> CountHook<'a> {
    #[inline(always)]
    fn tick(&mut self) {
        let now = Instant::now();
        let mut s = self.stats.borrow_mut();
        match s.last {
            None => {
                s.first_op_s = now.duration_since(s.start.unwrap()).as_secs_f64();
            }
            Some(last) => {
                let gap = now.duration_since(last).as_secs_f64();
                if gap > s.max_gap_s {
                    s.max_gap_s = gap;
                    s.max_gap_at = s.ops;
                }
                if gap > 1.0 {
                    s.gaps_1s += 1;
                }
                if gap > 0.010 {
                    s.native_gaps += 1;
                    s.native_sum_s += gap;
                }
            }
        }
        s.last = Some(now);
        s.ops += 1;
    }
}

macro_rules! count_post {
    ($($m:ident),* $(,)?) => { $( #[inline(always)] fn $m(&mut self) { self.tick(); } )* };
}

impl<'a> BackendHook for CountHook<'a> {
    type InitArg = &'a RefCell<OpStats>;
    #[inline(always)]
    fn new(arg: Self::InitArg) -> Self {
        arg.borrow_mut().start = Some(Instant::now());
        Self { stats: arg }
    }
    count_post!(
        post_input, post_alloc, post_constant, post_from_le_words, post_to_le_words,
        post_output, post_increase_refcount, post_decrease_refcount, post_not, post_bitxor,
        post_bitand, post_bitxor_const, post_bitand_const, post_unbounded_shl,
        post_unbounded_shr, post_rotate_left, post_rotate_right, post_reverse_bits,
        post_swap_bytes, post_cast, post_carry,
    );
}

fn measure<C: Circuit>(name: &str, circuit: &C) {
    let stats = RefCell::new(OpStats::default());
    let t0 = Instant::now();
    let mut builder = ChallengeBuilder::<H, PS, PV, S, WTP>::new(b"seed-entropy-demo", b"");
    let iter = builder
        .next_iter_hooked::<ViewCommitmentsRelayer<[u8; 32], [u8; 32]>, CountHook>((), &stats);
    circuit.exec(iter.view_builder());
    iter.finalize();
    let total = t0.elapsed().as_secs_f64();
    let s = stats.borrow();
    println!(
        "{name:18} pass {total:6.2}s  total backend ops {}\n    \
         1st op @ {:.3}s   max inter-op gap {:6.3}s @ op#{} ({:4.1}% in)\n    \
         native builds (gaps>10ms): {} totalling {:5.2}s  ({:4.1}% of pass)",
        s.ops,
        s.first_op_s,
        s.max_gap_s,
        s.max_gap_at,
        100.0 * s.max_gap_at as f64 / s.ops.max(1) as f64,
        s.native_gaps,
        s.native_sum_s,
        100.0 * s.native_sum_s / total,
    );
}

fn main() {
    println!("backend-op timeline (does the hook fire? where are the native gaps?)");
    measure("master_key", &master_key_circuit());
    measure("public_key", &public_key_circuit());
}
