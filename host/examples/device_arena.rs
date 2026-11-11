// SPDX-License-Identifier: LGPL-3.0-or-later

//! Charges a prove against a heap of the device's exact size, using the device's exact
//! allocator, and reports whether it is served.
//!
//! Withdrawn as a source of device figures (2026-08-24), and readable in one
//! direction only even before that; see `knowledge/measurement-instruments.md`.
//!
//! Run: `cargo run --release -p proofofseed-host --example device_arena`

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use linked_list_allocator::Heap;
use proofofseed_circuits::{MasterKeyCircuit, SeedCircuit, bip39_salt_for, hardened_child_circuit};
use proofofseed_circuits::hasher::Keccak256Hasher;
use zkboo::circuit::Circuit;
use zkboo::crypto::HashPRG;
use zkboo::prover::challenge::Party;
use zkboo::prover::proof::collectors::ResponseDataCollector;
use zkboo::prover::proof::ProofOptions;
use zkboo::prover::prove;
use zkboo::prover::views::OwnedFlexibleWordTriplePool;
use zkboo::word::{CompositeWord, Word};

/// Upper bound on any arena this sweep installs; the live size is set per run.
const ARENA_CAP: usize = 64 * 1024;

#[repr(align(16))]
struct Arena(UnsafeCell<[u8; ARENA_CAP]>);
unsafe impl Sync for Arena {}
static ARENA: Arena = Arena(UnsafeCell::new([0u8; ARENA_CAP]));

struct HeapCell(UnsafeCell<Heap>);
unsafe impl Sync for HeapCell {}
static HEAP: HeapCell = HeapCell(UnsafeCell::new(Heap::empty()));

/// Route allocations into the arena only while a measured run is in flight; everything
/// else (argument parsing, printing, the circuit's own construction) goes to the system
/// heap, exactly as it does on the device, where those costs are not the prover's.
static ARMED: AtomicBool = AtomicBool::new(false);
static PEAK_USED: AtomicUsize = AtomicUsize::new(0);
static OOM_COUNT: AtomicUsize = AtomicUsize::new(0);
static OOM_SIZE: AtomicUsize = AtomicUsize::new(0);
static OOM_ALIGN: AtomicUsize = AtomicUsize::new(0);
static OOM_FREE: AtomicUsize = AtomicUsize::new(0);
static OOM_USED: AtomicUsize = AtomicUsize::new(0);

fn arena_range() -> (usize, usize) {
    let base = ARENA.0.get() as usize;
    return (base, base + ARENA_CAP);
}

struct DeviceAlloc;

unsafe impl GlobalAlloc for DeviceAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            let heap = unsafe { &mut *HEAP.0.get() };
            match heap.allocate_first_fit(l) {
                Ok(p) => {
                    PEAK_USED.fetch_max(heap.used(), Ordering::Relaxed);
                    return p.as_ptr();
                }
                Err(()) => {
                    // Record the first refusal in full, then fall back so the run
                    // finishes and reports rather than aborting on the spot.
                    if OOM_COUNT.fetch_add(1, Ordering::Relaxed) == 0 {
                        OOM_SIZE.store(l.size(), Ordering::Relaxed);
                        OOM_ALIGN.store(l.align(), Ordering::Relaxed);
                        OOM_FREE.store(heap.free(), Ordering::Relaxed);
                        OOM_USED.store(heap.used(), Ordering::Relaxed);
                    }
                }
            }
        }
        return unsafe { System.alloc(l) };
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        let (lo, hi) = arena_range();
        let addr = p as usize;
        if addr >= lo && addr < hi {
            let heap = unsafe { &mut *HEAP.0.get() };
            unsafe { heap.deallocate(NonNull::new_unchecked(p), l) };
            return;
        }
        unsafe { System.dealloc(p, l) };
    }
}

#[global_allocator]
static A: DeviceAlloc = DeviceAlloc;

type H = Keccak256Hasher;
type S = [u8; 32];
type RC = u8;
type WTP = OwnedFlexibleWordTriplePool<RC>;

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

/// What the device holds live alongside the prover: the streaming chunk buffer, the
/// host-supplied witness and its salt, and the binding. Modelled as real allocations so
/// they fragment the arena the way they do on hardware.
fn ballast() -> Vec<Vec<u8>> {
    return vec![vec![0u8; 512], vec![0u8; 132], vec![0u8; 8], vec![0u8; 32]];
}

struct Outcome {
    served: bool,
    peak_used: usize,
    oom_count: usize,
    oom_size: usize,
    oom_align: usize,
    oom_free: usize,
}

fn run<C: Circuit>(arena_bytes: usize, num_iters: usize, binding: &[u8], circuit: &C) -> Outcome {
    PEAK_USED.store(0, Ordering::Relaxed);
    OOM_COUNT.store(0, Ordering::Relaxed);
    unsafe {
        let heap = &mut *HEAP.0.get();
        *heap = Heap::empty();
        heap.init(ARENA.0.get() as *mut u8, arena_bytes);
    }
    ARMED.store(true, Ordering::Relaxed);
    let held = ballast();
    let _: Vec<()> = prove::<C, H, HashPRG<H>, HashPRG<H>, S, DiscardSink, WTP, _>(
        circuit,
        num_iters,
        binding,
        &[],
        ProofOptions::new().with_collector_arg::<DiscardSink>(()),
    );
    drop(held);
    ARMED.store(false, Ordering::Relaxed);
    let oom_count = OOM_COUNT.load(Ordering::Relaxed);
    return Outcome {
        served: oom_count == 0,
        peak_used: PEAK_USED.load(Ordering::Relaxed),
        oom_count,
        oom_size: OOM_SIZE.load(Ordering::Relaxed),
        oom_align: OOM_ALIGN.load(Ordering::Relaxed),
        oom_free: OOM_FREE.load(Ordering::Relaxed),
    };
}

fn main() {
    // The exact call the device died on, plus the two other statements whose SRAM budget
    // this has to settle. Each is charged against a real arena and its minimum served size
    // found by bisection, so the answer is a threshold rather than a verdict at one size.
    let mnemonic = b"abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon about"
        .to_vec();
    let salt = bip39_salt_for(b"");
    let binding = [0x11u8; 32];

    println!(
        "Minimum heap that serves each statement, using the device's own allocator, with\n\
         its non-prover allocations held live. Host holes cost 16 B and the device's 8 B,\n\
         so each threshold is an upper bound on the device's true need.\n"
    );
    println!("  {:<40} {:>12}  {:>10}", "statement", "min heap", "peak used");

    let bip39 = SeedCircuit { mnemonic, salt, rounds: 2 };
    let mk = MasterKeyCircuit { seed: alloc_seed() };
    let hc = hardened_child_circuit();

    let rows: Vec<(&str, usize, usize)> = vec![
        threshold("BIP-39 mock, 12 words, 2 rounds", &bip39, &binding),
        threshold("master key, 64-byte seed", &mk, &binding),
        threshold("hardened child (the shipping statement)", &hc, &binding),
    ];
    for (label, min_heap, peak) in &rows {
        println!("  {label:<40} {min_heap:>10} B  {peak:>8} B");
    }

    // Deliberately no per-statement fit/no-fit verdict here. These thresholds are upper
    // bounds on the device's need, not the need itself, and the gap is large: this arena
    // puts master key at 19,200 B, while the device served that same statement in a
    // 15,872 B heap on 2026-08-23. The circuit's own Vec<WordRef> buffers are
    // pointer-width dependent even though the prover's internal pools are not, so a
    // 64-bit host inflates them.
    //
    // What the numbers above are good for is the ORDER (BIP-39 is much the cheapest, the
    // two HMAC statements are close to each other) and for proving a fit: anything served
    // here is served on the device. To learn what a statement actually needs, shrink
    // HEAP_SIZE on hardware until it stops -- which is safe, because a heap shortfall
    // raises a Rust allocation failure, and this app's io_new panic handler answers the
    // APDU with 0xE000 and exits cleanly. A stack shortfall is the one that wipes.
    println!(
        "\nThese are UPPER BOUNDS, not requirements. The device served master key in a\n\
         15,872 B heap while this arena demands {} B for it, so do not read a threshold\n\
         here as what the device needs -- only as a size that certainly works.",
        rows[1].1,
    );
}

/// A 64-byte seed, the realistic witness length rather than the compiled-in test vector.
fn alloc_seed() -> Vec<u8> {
    return (0..64).map(|i| ((i * 7 + 3) & 0xFF) as u8).collect();
}

/// Smallest arena that serves `circuit`, by bisection, with the peak it used there.
fn threshold<C: Circuit>(label: &'static str, circuit: &C, binding: &[u8]) -> (&'static str, usize, usize) {
    let (mut lo, mut hi) = (4_096usize, 40_960usize);
    // Establish that the upper bound really is served, so a bisection that never finds a
    // served size is visible as such instead of returning the bound itself. The refusal
    // carries its own diagnosis, since the allocation that failed is the whole story and
    // an assertion saying only "refused" would send the next reader back here to add this.
    let top = run(hi, 2, binding, circuit);
    assert!(
        top.served,
        "{label}: even {hi} B was refused — {} allocations failed, the last wanting {} B \
         at alignment {} with {} B free",
        top.oom_count, top.oom_size, top.oom_align, top.oom_free,
    );
    let mut peak_at_hi = top.peak_used;
    while hi - lo > 256 {
        let mid = (lo + hi) / 2 / 256 * 256;
        let o = run(mid, 2, binding, circuit);
        if o.served {
            hi = mid;
            peak_at_hi = o.peak_used;
        } else {
            lo = mid;
        }
    }
    return (label, hi, peak_at_hi);
}
