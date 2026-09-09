// SPDX-License-Identifier: LGPL-3.0-or-later

//! What the circuit-fingerprinting pass costs, in heap and in time, as a function of the
//! one public parameter that scales it: the BIP-39 round count.
//!
//! The pass exists because a ranged proof binds its deterministic prover entropy to the
//! circuit's structural digest, and because the device can be asked for that digest
//! directly. It runs the whole circuit through a hashing backend and — unlike the prover
//! — services no io while it does, so its cost is a hard constraint rather than merely a
//! slow operation: past some size the secure element's watchdog reboots the device.
//!
//! The two failure modes are told apart by this measurement. If the peak heap grows with
//! the round count, a large fingerprint is a memory problem and the reboot would be
//! memory-corruption-class. If the heap is flat and only the time grows, it is a watchdog
//! problem, which is recoverable and fixable by feeding the watchdog.
//!
//! Run: `cargo run --release -p proofofseed-host --example fingerprint_cost`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use proofofseed_circuits::{SeedCircuit, bip39_salt_for, hardened_child_circuit};
use proofofseed_circuits::hasher::Keccak256Hasher;
use zkboo::circuit::Circuit;

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
        return p;
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        CURRENT.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) };
    }
}

#[global_allocator]
static ALLOC: Tracking = Tracking;

fn cost<C: Circuit>(label: &str, circuit: &C) -> (usize, f64) {
    PEAK.store(CURRENT.load(Ordering::Relaxed), Ordering::Relaxed);
    let t0 = Instant::now();
    let _ = zkboo_circuit_hash::hash_circuit::<C, Keccak256Hasher>(circuit);
    let secs = t0.elapsed().as_secs_f64();
    let peak = PEAK.load(Ordering::Relaxed);
    println!("  {label:<34} {peak:>7} B   {:>9.1} ms", secs * 1000.0);
    return (peak, secs);
}

fn main() {
    println!(
        "Fingerprinting cost (host, release). The pass services no io, so its duration is\n\
         a watchdog constraint on the device; its heap is a memory constraint.\n"
    );
    println!("  {:<34} {:>9}   {:>12}", "circuit", "peak heap", "wall time");
    let (hc_peak, hc_secs) = cost("hardened child (one HMAC)", &hardened_child_circuit());
    let mnemonic = b"abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon about"
        .to_vec();
    let salt = bip39_salt_for(b"");
    let mut rows = Vec::new();
    for rounds in [1usize, 2, 8, 64, 256, 2048] {
        let c = SeedCircuit { mnemonic: mnemonic.clone(), salt: salt.clone(), rounds };
        let (peak, secs) = cost(&format!("BIP-39 seed, {rounds} rounds"), &c);
        rows.push((rounds, peak, secs));
    }

    let heaps: Vec<usize> = rows.iter().map(|r| r.1).collect();
    let flat = heaps.iter().all(|&h| h == heaps[0]);
    println!(
        "\nHeap across round counts: {}",
        if flat {
            format!("FLAT at {} B — the round count buys time, not memory", heaps[0])
        } else {
            format!("VARIES: {heaps:?}")
        }
    );
    let (r_lo, _, t_lo) = rows[1];
    let (r_hi, _, t_hi) = rows[rows.len() - 1];
    println!(
        "Time: {:.1} ms at {r_lo} rounds to {:.1} ms at {r_hi} rounds ({:.0}x for {:.0}x the rounds)",
        t_lo * 1000.0,
        t_hi * 1000.0,
        t_hi / t_lo,
        r_hi as f64 / r_lo as f64,
    );
    println!(
        "Relative to the hardened child, which the device fingerprints without incident:\n  \
         {:.0}x at {r_hi} rounds (hardened child {:.1} ms, peak {hc_peak} B)",
        t_hi / hc_secs,
        hc_secs * 1000.0,
    );
}
