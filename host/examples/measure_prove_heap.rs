// SPDX-License-Identifier: LGPL-3.0-or-later

//! Measures peak heap of the streaming master_key prover at increasing iteration
//! counts, using the EXACT on-device config (RC = u8, Keccak-256, a discarding
//! streaming sink). Tells us whether device-heap peak is constant per iteration
//! (good — a fixed budget suffices) or grows (a retention bug to fix).
//!
//! Run: `cargo run --release -p zkboo-bip32 --example measure_prove_heap`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use proofofseed_circuits::hasher::Keccak256Hasher;
use zkboo::backend::{Backend, Frontend};
use zkboo::circuit::{Assertions, Circuit};
use zkboo::crypto::HashPRG;
use zkboo::prover::challenge::Party;
use zkboo::prover::proof::collectors::ResponseDataCollector;
use zkboo::prover::proof::ProofOptions;
use zkboo::prover::prove;
use zkboo::prover::views::OwnedFlexibleWordTriplePool;
use zkboo::word::{CompositeWord, Word};
use zkboo_bip32::master_key;

// ---- tracking allocator ----
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Tracking;
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let cur = CURRENT.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(cur, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        CURRENT.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) };
    }
}
#[global_allocator]
static A: Tracking = Tracking;

// ---- device config ----
type H = Keccak256Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = [u8; 32];
type RC = u8;
type WTP = OwnedFlexibleWordTriplePool<RC>;

struct MasterKeyCircuit {
    seed: Vec<u8>,
}
impl Circuit for MasterKeyCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let seed = self
            .seed
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let (il, ir) = master_key(frontend.allocator(), seed);
        il.into_iter().for_each(|w| frontend.output(w));
        ir.into_iter().for_each(|w| frontend.output(w));
        Assertions::new().output(frontend);
    }
}

// A discarding streaming sink: replicates the device DigestSink's lifecycle
// (per-response new/push/finalize) without retaining anything.
#[derive(Debug)]
struct DiscardSink;
impl ResponseDataCollector<[u8; 32], [u8; 32]> for DiscardSink {
    type InitArg = ();
    type FinalizeRes = ();
    fn new(_c: Party, _a: [u8; 32], _b: [u8; 32], _arg: ()) -> Self {
        DiscardSink
    }
    fn push_input_share2<W: Word, const N: usize>(&mut self, _w: CompositeWord<W, N>) {}
    fn push_and_msg<W: Word, const N: usize>(&mut self, _w: CompositeWord<W, N>) {}
    fn finalize(self, _d: [u8; 32]) {}
}

fn main() {
    let circuit = MasterKeyCircuit {
        seed: (0u8..16).collect(),
    };
    println!("peak heap of streaming master_key prover (RC=u8, Keccak), by num_iters:");
    for n in [1usize, 2, 3, 4, 8, 16] {
        PEAK.store(CURRENT.load(Ordering::Relaxed), Ordering::Relaxed);
        let _: Vec<()> = prove::<MasterKeyCircuit, H, PS, PV, S, DiscardSink, WTP, _>(
            &circuit,
            n,
            b"proofofseed-ledger-app M0 seed entropy",
            &[],
            ProofOptions::new().with_collector_arg::<DiscardSink>(()),
        );
        let peak = PEAK.load(Ordering::Relaxed);
        let base = CURRENT.load(Ordering::Relaxed);
        println!("  iters={:2}  peak heap = {:6} B ({:.1} KiB)   [resident after = {} B]", n, peak, peak as f64 / 1024.0, base);
    }
}
