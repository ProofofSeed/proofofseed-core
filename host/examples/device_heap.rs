// SPDX-License-Identifier: LGPL-3.0-or-later

//! Peak prover heap per statement, in the device's exact configuration, for both comb
//! table sources.
//!
//! The device reads its secp256k1 comb tables from a precomputed table instead of
//! recomputing them with native point arithmetic. That is a different heap profile from
//! the one every previous measurement recorded, because those measured the recomputing
//! variant — the flash variant lived only inside the app, where no host allocator could
//! see it. It is now the same circuit with a different table source, so it can be
//! measured here, which is what this does.
//!
//! It also measures the seed statements at a realistic witness length. Their witness
//! length is a public circuit parameter, so the compiled-in 16-byte test vector is not
//! the circuit a software wallet runs on a 64-byte BIP-39 seed.
//!
//! Run: `cargo run --release -p proofofseed-host --example device_heap`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use proofofseed_circuits::comb::{ComputedComb, FlashComb};
use proofofseed_circuits::{
    AddressCircuit, MasterKeyCircuit, NormalChildCircuit, PubKeyCircuit, SeedCircuit,
    Slip10MasterCircuit, bip39_salt_for, hardened_child_circuit, normal_child_circuit,
};
use proofofseed_circuits::hasher::Keccak256Hasher;
use zkboo::circuit::Circuit;
use zkboo::crypto::HashPRG;
use zkboo::prover::challenge::Party;
use zkboo::prover::proof::collectors::ResponseDataCollector;
use zkboo::prover::proof::ProofOptions;
use zkboo::prover::prove;
use zkboo::prover::views::OwnedFlexibleWordTriplePool;
use zkboo::word::{CompositeWord, Word};

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// Live allocation count, and the count at the moment the peak was set. Together with
/// the peak these bound how much of the figure can depend on pointer width: a peak made
/// of a few large word buffers is nearly pointer-independent, while one made of thousands
/// of small nodes is not.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static LIVE_AT_PEAK: AtomicUsize = AtomicUsize::new(0);

/// A slot table of the currently-live allocations, so the *sizes* making up the peak can
/// be read off. There are only a few dozen of them, and knowing which buffers they are is
/// what decides whether the figure depends on pointer width: a buffer of circuit words is
/// the same size on a 32-bit device, while a buffer of `usize` indices halves.
const SLOTS: usize = 512;
static SLOT_PTR: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];
static SLOT_SIZE: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];
static SNAPSHOT: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];

struct Tracking;
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let cur = CURRENT.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            let live = LIVE.fetch_add(1, Ordering::Relaxed) + 1;
            for i in 0..SLOTS {
                if SLOT_PTR[i].load(Ordering::Relaxed) == 0 {
                    SLOT_PTR[i].store(p as usize, Ordering::Relaxed);
                    SLOT_SIZE[i].store(l.size(), Ordering::Relaxed);
                    break;
                }
            }
            if cur > PEAK.load(Ordering::Relaxed) {
                PEAK.store(cur, Ordering::Relaxed);
                LIVE_AT_PEAK.store(live, Ordering::Relaxed);
                for i in 0..SLOTS {
                    SNAPSHOT[i].store(SLOT_SIZE[i].load(Ordering::Relaxed), Ordering::Relaxed);
                }
            }
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        CURRENT.fetch_sub(l.size(), Ordering::Relaxed);
        LIVE.fetch_sub(1, Ordering::Relaxed);
        for i in 0..SLOTS {
            if SLOT_PTR[i].load(Ordering::Relaxed) == p as usize {
                SLOT_PTR[i].store(0, Ordering::Relaxed);
                SLOT_SIZE[i].store(0, Ordering::Relaxed);
                break;
            }
        }
        unsafe { System.dealloc(p, l) };
    }
}
#[global_allocator]
static A: Tracking = Tracking;

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

/// The heap the committed SRAM split gives the prover (`HEAP_SIZE` in the app's
/// `.cargo/config.toml`).
///
/// 🔴 **The peaks below do not transfer to the device, and the verdicts against this
/// budget are screening only.** Measured on hardware on 2026-08-24, a one-response
/// master-key proof peaks at 11,747 B where this example reports 16,932 B — the host
/// overstates by 44%. The configuration is not the cause: this example already uses the
/// device's own `RC = u8`, Keccak-256, flash comb tables and discarding sink, and it
/// reproduces exactly against current sources. The allocation *counts* agree (24 here,
/// 26 on the device) while the sizes do not, which points at buffer lengths counted in
/// pointer-sized units on a 64-bit host.
///
/// Because the effect depends on how much of a given statement's peak is pointer-indexed,
/// it is not a fixed offset and not a fixed ratio, so these figures **cannot be rescaled**
/// into device figures. Use them to rank and to screen; take every number that reaches a
/// document from the device's own `heap_peak` telemetry (`ledger-app/host/bench_matrix.py`,
/// rows under `ledger-app/docs/bench/`).
///
/// A conclusion previously drawn from these figures — that the normal-child statement
/// cannot fit — was withdrawn for exactly this reason.
const DEVICE_HEAP: usize = 13_312;

fn peak_of<C: Circuit>(label: &str, circuit: &C) {
    PEAK.store(CURRENT.load(Ordering::Relaxed), Ordering::Relaxed);
    LIVE_AT_PEAK.store(0, Ordering::Relaxed);
    let _: Vec<()> = prove::<C, H, HashPRG<H>, HashPRG<H>, S, DiscardSink, WTP, _>(
        circuit,
        1,
        b"device-heap-measurement",
        &[],
        ProofOptions::new().with_collector_arg::<DiscardSink>(()),
    );
    let peak = PEAK.load(Ordering::Relaxed);
    let live = LIVE_AT_PEAK.load(Ordering::Relaxed);
    let verdict = if peak < DEVICE_HEAP {
        format!("fits, {} B spare", DEVICE_HEAP - peak)
    } else {
        format!("OVER by {} B", peak - DEVICE_HEAP)
    };
    println!(
        "  {label:<40} {peak:>7} B  {live:>4} live ({:>4} B avg)  {verdict}",
        if live > 0 { peak / live } else { 0 },
    );
    if label.starts_with("normal child, precomputed") {
        let mut sizes: Vec<usize> =
            SNAPSHOT.iter().map(|s| s.load(Ordering::Relaxed)).filter(|&n| n > 0).collect();
        sizes.sort_unstable_by(|a, b| b.cmp(a));
        println!("      the buffers making up that peak, largest first:");
        println!("      {sizes:?}");
        println!("      sum {} B over {} buffers", sizes.iter().sum::<usize>(), sizes.len());
    }
}

fn main() {
    println!(
        "Peak prover heap, one response, device config (RC=u8, Keccak-256, discarding sink).\n\
         Device heap budget: {DEVICE_HEAP} B. The prover is not the only claimant — the\n\
         512-byte stream buffer, the binding, the path and the progress strings are also\n\
         live at the peak — so 'fits' here is necessary, not sufficient.\n"
    );

    println!("Elliptic-curve statements, by comb table source:");
    let priv_key = vec![0x11u8; 32];
    peak_of("public key, tables recomputed", &PubKeyCircuit::<ComputedComb>::new(priv_key.clone()));
    peak_of("public key, tables precomputed (device)", &PubKeyCircuit::<FlashComb>::new(priv_key.clone()));
    peak_of("ethereum address, tables recomputed", &AddressCircuit::<ComputedComb>::new(priv_key.clone()));
    peak_of("ethereum address, precomputed (device)", &AddressCircuit::<FlashComb>::new(priv_key.clone()));
    let nc = normal_child_circuit();
    peak_of(
        "normal child, tables recomputed",
        &NormalChildCircuit::<ComputedComb>::new(nc.chain_code.clone(), nc.parent_priv.clone(), nc.index),
    );
    peak_of(
        "normal child, precomputed (device)",
        &NormalChildCircuit::<FlashComb>::new(nc.chain_code.clone(), nc.parent_priv.clone(), nc.index),
    );

    println!("\nSeed statements, by witness length (the length is a public circuit parameter):");
    peak_of("master key, 16-byte test vector", &MasterKeyCircuit { seed: vec![0u8; 16] });
    peak_of("master key, 64-byte BIP-39 seed", &MasterKeyCircuit { seed: vec![0u8; 64] });
    peak_of("SLIP-10 master, 64-byte BIP-39 seed", &Slip10MasterCircuit { seed: vec![0u8; 64] });
    let salt = bip39_salt_for(b"");
    for rounds in [2usize, 64, 2048] {
        peak_of(
            &format!("BIP-39 seed, 12-word mnemonic, {rounds} rounds"),
            &SeedCircuit { mnemonic: vec![b'a'; 92], salt: salt.clone(), rounds },
        );
    }

    println!("\nFor reference, the statement the SRAM split was chosen against:");
    peak_of("hardened child (test-vector params)", &hardened_child_circuit());
}
