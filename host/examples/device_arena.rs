// SPDX-License-Identifier: LGPL-3.0-or-later

//! Charges a prove against a heap of the device's exact size, using the device's exact
//! allocator, and reports whether it is served.
//!
//! Every previous heap measurement here counted *bytes requested*, with a tracking
//! allocator wrapped around the system heap. That number is blind to three things the
//! secure element cannot avoid: the per-allocation header `linked_list_allocator` keeps,
//! the padding it adds to satisfy alignment, and first-fit fragmentation — a request can
//! fail for want of a contiguous hole while the total free space is ample. The device
//! runs `embedded_alloc::Heap`, which is that allocator over a fixed static array, so the
//! way to see those three is to run the same allocator over an array of the same size.
//!
//! Read the verdict in one direction only. The host is 64-bit and the device 32-bit, so
//! a hole header costs 16 B here and 8 B there, and minimum alignment is 8 B here and
//! 4 B there. The allocation *sizes* are pointer-width independent (the prover holds no
//! `Vec<usize>`), so this arena is strictly more wasteful than the device's: **fitting
//! here proves fitting there; failing here does not by itself prove failing there.**
//!
//! Run: `cargo run --release -p proofofseed-host --example device_arena`

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use linked_list_allocator::Heap;
use proofofseed_circuits::{SeedCircuit, bip39_salt_for};
use zkboo::circuit::Circuit;
use zkboo::crypto::{HashPRG, Keccak256Hasher};
use zkboo::prover::challenge::Party;
use zkboo::prover::proof::collectors::ResponseDataCollector;
use zkboo::prover::prove_custom;
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
    let _: Vec<()> = prove_custom::<C, H, HashPRG<H>, HashPRG<H>, S, DiscardSink, WTP>(
        circuit,
        num_iters,
        binding,
        &[],
        (),
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
    // The exact call the device died on: the host-supplied mock witness, the published
    // 12-word test mnemonic, the default empty passphrase, two PBKDF2 rounds, two
    // iterations, the gate's 32-byte binding.
    let mnemonic = b"abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon about"
        .to_vec();
    let salt = bip39_salt_for(b"");
    let binding = [0x11u8; 32];
    let circuit = SeedCircuit { mnemonic, salt, rounds: 2 };

    println!(
        "BIP-39 mock prove (12 words, 2 rounds, 2 iterations) charged against a real\n\
         linked_list_allocator arena, with the device's non-prover allocations held live.\n\
         Host holes cost 16 B each; the device's cost 8 B — so this is the pessimistic side.\n"
    );
    println!("  {:>8}  {:>10}  {:>10}  {}", "arena", "peak used", "headroom", "verdict");
    for arena in [12_288usize, 13_312, 14_336, 15_360, 15_872, 16_896, 17_920, 18_944, 20_480] {
        let o = run(arena, 2, &binding, &circuit);
        let tag = if arena == 15_872 {
            "  <- the widened build that died"
        } else if arena == 18_944 {
            "  <- the production split"
        } else {
            ""
        };
        if o.served {
            println!(
                "  {arena:>8}  {:>10}  {:>10}  SERVED{tag}",
                o.peak_used,
                arena - o.peak_used,
            );
        } else {
            println!(
                "  {arena:>8}  {:>10}  {:>10}  REFUSED {} allocation(s); first was {} B \
                 (align {}) with {} B free{tag}",
                o.peak_used,
                arena.saturating_sub(o.peak_used),
                o.oom_count,
                o.oom_size,
                o.oom_align,
                o.oom_free,
            );
        }
    }
}
