// SPDX-License-Identifier: LGPL-3.0-or-later

//! Relative call-stack depth of the prover, per statement, measured through the same
//! per-operation hook the device uses to feed its watchdog.
//!
//! ⚠️ The device's ordering must not be inferred from this table; the device falsified
//! it on 2026-08-23. See `knowledge/measurement-instruments.md`.
//!
//! Run: `cargo run --release -p proofofseed-host --example stack_profile`

use std::sync::atomic::{AtomicUsize, Ordering};

use proofofseed_circuits::{
    MasterKeyCircuit, SeedCircuit, bip39_salt_for, hardened_child_circuit, master_key_circuit,
};
use proofofseed_circuits::hasher::Keccak256Hasher;
use zkboo::backend::BackendHook;
use zkboo::circuit::Circuit;
use zkboo::crypto::HashPRG;
use zkboo::prover::challenge::{ChallengeBuilder, Party};
use zkboo::prover::proof::{ProofOptions, build_proof};
use zkboo::prover::proof::collectors::ResponseDataCollector;
use zkboo::prover::views::OwnedFlexibleWordTriplePool;
use zkboo::prover::views::collectors::ViewCommitmentsRelayer;
use zkboo::word::{CompositeWord, Word};

type H = Keccak256Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = [u8; 32];
type RC = u8;
type WTP = OwnedFlexibleWordTriplePool<RC>;

/// Lowest stack address seen since the last reset. The stack grows downward on every
/// platform this runs on, so "lowest" is "deepest".
static DEEPEST: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Number of samples taken, so a row that measured nothing is visible as such rather
/// than reported as a shallow stack.
static SAMPLES: AtomicUsize = AtomicUsize::new(0);

#[inline(never)]
fn sample() {
    let here = 0u8;
    let sp = &here as *const u8 as usize;
    DEEPEST.fetch_min(sp, Ordering::Relaxed);
    SAMPLES.fetch_add(1, Ordering::Relaxed);
}

struct StackProbe;

/// One sampling override per backend operation, mirroring the device's watchdog hook so
/// the sampling points are the same ones that service io there.
macro_rules! probe_post {
    ($($m:ident),* $(,)?) => {
        $(
            #[inline(always)]
            fn $m(&mut self) {
                sample();
            }
        )*
    };
}

impl BackendHook for StackProbe {
    type InitArg = ();
    fn new(_: ()) -> Self {
        return StackProbe;
    }
    probe_post!(
        post_input,
        post_alloc,
        post_constant,
        post_from_le_words,
        post_to_le_words,
        post_output,
        post_not,
        post_bitxor,
        post_bitand,
        post_bitxor_const,
        post_bitand_const,
        post_unbounded_shl,
        post_unbounded_shr,
        post_rotate_left,
        post_rotate_right,
        post_reverse_bits,
        post_swap_bytes,
        post_cast,
        post_carry,
    );
}

/// A sink that also samples: the response-writing path is where the device's streaming
/// flush (and, with it, a screen refresh) sits, so it must be represented.
#[derive(Debug)]
struct ProbeSink;
impl ResponseDataCollector<[u8; 32], [u8; 32]> for ProbeSink {
    type InitArg = ();
    type FinalizeRes = ();
    fn new(_c: Party, _a: [u8; 32], _b: [u8; 32], _arg: ()) -> Self {
        return ProbeSink;
    }
    fn push_input_share2<W: Word, const N: usize>(&mut self, _w: CompositeWord<W, N>) {
        sample();
    }
    fn push_and_msg<W: Word, const N: usize>(&mut self, _w: CompositeWord<W, N>) {
        sample();
    }
    fn finalize(self, _d: [u8; 32]) {}
}

/// Runs both phases exactly as the app's `run_phases` does, and returns the deepest
/// excursion below this frame, in bytes, with the sample count that produced it.
fn depth_of<C: Circuit>(circuit: &C, num_iters: usize) -> (usize, usize) {
    let anchor = 0u8;
    let top = &anchor as *const u8 as usize;
    DEEPEST.store(usize::MAX, Ordering::Relaxed);
    SAMPLES.store(0, Ordering::Relaxed);
    let seed_entropy = [0x5au8; 32];
    let binding = [0x11u8; 32];
    let mut builder = ChallengeBuilder::<H, PS, PV, S, WTP>::new(&seed_entropy, &binding);
    for _ in 0..num_iters {
        let iter = builder
            .next_iter_hooked::<ViewCommitmentsRelayer<[u8; 32], [u8; 32]>, StackProbe>((), ());
        circuit.exec(iter.view_builder());
        iter.finalize();
    }
    let challenge_entropy = builder.finalize();
    let _: Vec<()> = build_proof::<C, H, PS, PV, S, ProbeSink, WTP, _>(
        circuit,
        &seed_entropy,
        challenge_entropy,
        num_iters,
        ProofOptions::new()
            .with_collector_arg::<ProbeSink>(())
            .with_hook_arg::<StackProbe>(()),
    );
    let deepest = DEEPEST.load(Ordering::Relaxed);
    let samples = SAMPLES.load(Ordering::Relaxed);
    return (top.saturating_sub(deepest), samples);
}

fn main() {
    println!(
        "Prover call-stack depth by statement, both phases, sampled at every backend\n\
         operation. Ratios between rows are the signal; absolute bytes are host figures\n\
         and do not transfer to the device.\n"
    );
    println!("  {:<44} {:>9}  {:>12}", "statement", "depth", "samples");

    let mut rows: Vec<(String, usize)> = Vec::new();
    let row = |label: &str, depth: usize, samples: usize, rows: &mut Vec<(String, usize)>| {
        println!("  {label:<44} {depth:>7} B  {samples:>12}");
        rows.push((label.to_string(), depth));
    };

    // The statement the device's SRAM split was chosen against, and the deepest reading
    // it has ever produced on hardware (12,984 B, 2026-08-22).
    let (d, s) = depth_of(&hardened_child_circuit(), 2);
    row("hardened child (the split's reference)", d, s, &mut rows);

    let (d, s) = depth_of(&master_key_circuit(), 2);
    row("master key, compiled-in test vector", d, s, &mut rows);

    let (d, s) = depth_of(&MasterKeyCircuit { seed: vec![0u8; 64] }, 2);
    row("master key, 64-byte seed", d, s, &mut rows);

    // The exact circuit the device died proving.
    let mnemonic = b"abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon about"
        .to_vec();
    let salt = bip39_salt_for(b"");
    let (d, s) = depth_of(&SeedCircuit { mnemonic: mnemonic.clone(), salt: salt.clone(), rounds: 2 }, 2);
    row("BIP-39 mock, 12 words, 2 rounds  <- died", d, s, &mut rows);

    // Whether the round count moves the stack at all, the same question the heap
    // measurement answered for memory.
    for rounds in [1usize, 4, 16] {
        let c = SeedCircuit { mnemonic: mnemonic.clone(), salt: salt.clone(), rounds };
        let (d, s) = depth_of(&c, 2);
        row(&format!("BIP-39 mock, 12 words, {rounds} rounds"), d, s, &mut rows);
    }

    let (base_label, base) = rows[0].clone();
    println!("\nRelative to the reference ({base_label}, {base} B):");
    for (label, depth) in rows.iter().skip(1) {
        let pct = (*depth as f64 - base as f64) / base as f64 * 100.0;
        println!("  {label:<44} {pct:+7.1}%");
    }
}
