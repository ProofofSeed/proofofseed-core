// SPDX-License-Identifier: LGPL-3.0-or-later

//! The prover's peak heap for each statement, with the on-device refcount type, measured
//! through a tracking global allocator — which is why this is an example rather than a
//! test: the counter is process-wide, so tests running in parallel would read each
//! other's allocations.
//!
//! The output checks it also prints are a convenience view of what
//! `circuits/tests/statement_outputs.rs` asserts. They used to live *only* here, which is
//! how five of the six came to be failing, unnoticed, from the day ZKBoo 2.0.0 appended
//! the assertion word: nothing ran them. This binary now exits non-zero when one
//! mismatches, so a stale expectation cannot be read past.
//!
//! Run: `cargo run --release -p proofofseed-host --example validate_statements`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use proofofseed_circuits::*;
use std::process::ExitCode;
use zkboo::circuit::Circuit;
use zkboo::crypto::{HashPRG, Keccak256Hasher};
use zkboo::executor::{exec, OwnedFlexibleWordPool};
use zkboo::prover::challenge::Party;
use zkboo::prover::proof::build_proof_custom;
use zkboo::prover::proof::collectors::ResponseDataCollector;
use zkboo::prover::challenge::ChallengeBuilder;
use zkboo::prover::views::OwnedFlexibleWordTriplePool;
use zkboo::word::{CompositeWord, Word, Words};

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
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = [u8; 32];
type RC = u8;
type WP = OwnedFlexibleWordPool<RC>;
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

fn u8_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 4 little-endian u64 limbs -> 32-byte big-endian hex.
fn u64x4_be_hex(limbs: &[u64]) -> String {
    format!(
        "{:016x}{:016x}{:016x}{:016x}",
        limbs[3], limbs[2], limbs[1], limbs[0]
    )
}

static FAILURES: AtomicUsize = AtomicUsize::new(0);

fn check(name: &str, got: &str, expected: &str) {
    let ok = got == expected;
    if !ok {
        FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    println!("  {name:<28} {}", if ok { "OK" } else { "MISMATCH" });
    if !ok {
        println!("     got      {got}");
        println!("     expected {expected}");
    }
}

/// Peak heap of one streaming prover pass (num_iters = 1) for `circuit`.
fn prover_peak_heap<C: Circuit>(circuit: &C) -> usize {
    PEAK.store(CURRENT.load(Ordering::Relaxed), Ordering::Relaxed);
    let mut builder = ChallengeBuilder::<H, PS, PV, S, WTP>::new(b"entropy", b"");
    let it = builder.next_iter();
    circuit.exec(it.view_builder());
    it.finalize();
    let entropy = builder.finalize();
    let _: Vec<()> =
        build_proof_custom::<C, H, PS, PV, S, DiscardSink, WTP>(circuit, b"entropy", entropy, 1, ());
    PEAK.load(Ordering::Relaxed)
}

/// Executes a circuit and removes the trailing assertion word, so what is compared is the
/// statement's payload rather than the payload plus one byte.
fn payload<C: Circuit>(circuit: &C) -> Words {
    checked_payload(exec::<C, WP>(circuit)).expect("assertions hold")
}

fn main() -> ExitCode {
    println!("Executing each statement on its test vector and checking the output:\n");

    // master_key
    let o = payload(&master_key_circuit());
    check("master_key", &u8_hex(&o.u8), EXPECTED_MASTER);

    // hardened_child
    let o = payload(&hardened_child_circuit());
    check("hardened_child priv", &u64x4_be_hex(&o.u64[0..4]), EXPECTED_HARDENED_PRIV);
    check("hardened_child cc", &u8_hex(&o.u8), EXPECTED_HARDENED_CC);

    // bip39_seed (full 2048 rounds for the canonical vector)
    let o = payload(&bip39_seed_circuit(2048));
    check("bip39_seed", &u8_hex(&o.u8), EXPECTED_BIP39_SEED);

    // public_key (elephant)
    let o = payload(&public_key_circuit());
    let pk = format!("{}{}", u64x4_be_hex(&o.u64[0..4]), u64x4_be_hex(&o.u64[4..8]));
    check("public_key", &pk, EXPECTED_PUBKEY);

    // normal_child (elephant)
    let o = payload(&normal_child_circuit());
    check("normal_child priv", &u64x4_be_hex(&o.u64[0..4]), EXPECTED_NORMAL_PRIV);
    check("normal_child cc", &u8_hex(&o.u8), EXPECTED_NORMAL_CC);

    // ethereum_address (elephant)
    let o = payload(&ethereum_address_circuit());
    check("ethereum_address", &u8_hex(&o.u8), EXPECTED_ETH_ADDRESS);

    // These screen and rank; they do not size the device. Hardware has falsified the
    // host tracker as a device bound — it overstates a one-response master-key proof by
    // 44% — and the figures that go into documents come from the device's own allocator.
    // The withdrawal that put this caveat on `device_heap` and `device_arena` did not
    // reach here, and this example was still claiming to bound HEAP_SIZE.
    println!("\nProver peak heap (RC=u8) — screens and ranks; does NOT bound device HEAP_SIZE:");
    println!("  master_key       {:6} B", prover_peak_heap(&master_key_circuit()));
    println!("  hardened_child   {:6} B", prover_peak_heap(&hardened_child_circuit()));
    println!("  bip39 (r=2)      {:6} B", prover_peak_heap(&bip39_seed_circuit(2)));
    println!("  bip39 (r=64)     {:6} B", prover_peak_heap(&bip39_seed_circuit(64)));
    println!("  public_key       {:6} B", prover_peak_heap(&public_key_circuit()));
    println!("  normal_child     {:6} B", prover_peak_heap(&normal_child_circuit()));
    println!("  ethereum_address {:6} B", prover_peak_heap(&ethereum_address_circuit()));
    let failed = FAILURES.load(Ordering::Relaxed);
    if failed == 0 {
        println!("\nPublic outputs above confirm all six circuits are correct.");
        ExitCode::SUCCESS
    } else {
        println!("\n{failed} output(s) MISMATCHED — see circuits/tests/statement_outputs.rs.");
        ExitCode::FAILURE
    }
}
