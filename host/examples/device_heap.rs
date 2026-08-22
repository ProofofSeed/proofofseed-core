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
use zkboo::circuit::Circuit;
use zkboo::crypto::{HashPRG, Keccak256Hasher};
use zkboo::prover::challenge::Party;
use zkboo::prover::proof::collectors::ResponseDataCollector;
use zkboo::prover::prove_custom;
use zkboo::prover::views::OwnedFlexibleWordTriplePool;
use zkboo::word::{CompositeWord, Word};

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
/// `.cargo/config.toml`). Everything measured here has to fit under it, alongside the
/// non-prover allocations the device also holds live at the peak.
const DEVICE_HEAP: usize = 18_944;

fn peak_of<C: Circuit>(label: &str, circuit: &C) {
    PEAK.store(CURRENT.load(Ordering::Relaxed), Ordering::Relaxed);
    let _: Vec<()> = prove_custom::<C, H, HashPRG<H>, HashPRG<H>, S, DiscardSink, WTP>(
        circuit,
        1,
        b"device-heap-measurement",
        &[],
        (),
    );
    let peak = PEAK.load(Ordering::Relaxed);
    let verdict = if peak < DEVICE_HEAP {
        format!("fits, {} B spare", DEVICE_HEAP - peak)
    } else {
        format!("OVER by {} B", peak - DEVICE_HEAP)
    };
    println!("  {label:<44} {peak:>7} B ({:>5.1} KiB)  {verdict}", peak as f64 / 1024.0);
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
