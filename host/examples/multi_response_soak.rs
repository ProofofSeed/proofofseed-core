// SPDX-License-Identifier: LGPL-3.0-or-later

//! Does a multi-response proof succeed every time, or only sometimes?
//!
//! On the Flex a two-response master-key proof succeeds about a third of the time and
//! otherwise dies with the SDK's panic status word, at the same point in the run each
//! time. Polling was ruled out as the cause (it fails identically unpolled), and so were
//! heap and stack — free space never fell below 3.6 KB, the heap peak never moved, and
//! stack headroom stayed above 4 KB. What is left is the prover path.
//!
//! The observed rates fit one model closely: the first response always succeeds and each
//! later one succeeds about one time in three.
//!
//!     x1  6/6      x2  2/6 (33%)      x4  0/2
//!
//! One in three is the number of ZKBoo challenge values, which is what makes this worth
//! running rather than reasoning about: if some challenge values break responses after the
//! first, it is a prover fault, and whether it lives in shared code or only on the device
//! decides who is affected. The proofs the standalone CLI and the Python package produce
//! come from this same path.
//!
//! Each trial draws fresh entropy, so the challenge differs between trials exactly as it
//! does on the device. A trial that panics is caught rather than aborting the run, since
//! the panic is the observation.
//!
//! Run: `cargo run --release -p proofofseed-host --example multi_response_soak`

use std::panic;

use proofofseed_circuits::master_key_circuit;
use proofofseed_host::harness::gen_stream;
use proofofseed_host::{seed_statement_output, verify};

/// The BIP-32 test vector's 16-byte seed, which is what `master_key_circuit` proves.
const SEED: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const BINDING: &[u8] = b"multi-response-soak";
const TRIALS: usize = 24;

fn trial(n: usize, entropy: &[u8]) -> Result<bool, String> {
    let circuit = master_key_circuit();
    let stream = panic::catch_unwind(|| gen_stream(&circuit, n, entropy, BINDING))
        .map_err(|e: Box<dyn std::any::Any + Send>| {
            let msg = e
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string());
            format!("PANIC: {msg}")
        })?;
    let output = seed_statement_output(0, 0, &SEED, &[], 0).expect("master key output");
    Ok(verify(0, &output, &stream, n, BINDING, 0, None, None, 0))
}

fn main() {
    // The panic hook is silenced so that a caught panic does not print a backtrace per
    // trial; the message is reported through the result instead.
    let previous = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    println!(
        "Master-key proofs with fresh entropy per trial, {TRIALS} trials per response count.\n\
         'panic' means the prover itself died; 'invalid' means it produced a proof the\n\
         verifier rejects, which would be the worse of the two.\n"
    );
    println!("| responses | verified | invalid | panicked |");
    println!("|---|--:|--:|--:|");
    let mut detail: Vec<String> = Vec::new();
    for n in [1usize, 2, 4, 8] {
        let (mut ok, mut bad, mut boom) = (0, 0, 0);
        for t in 0..TRIALS {
            // Entropy varies per trial and per response count, so no two trials share a
            // challenge. Derived rather than drawn from the OS so a failure can be replayed.
            let entropy: Vec<u8> = (0..32u8)
                .map(|i| i.wrapping_mul(31).wrapping_add((t * 7 + n * 101) as u8))
                .collect();
            match trial(n, &entropy) {
                Ok(true) => ok += 1,
                Ok(false) => {
                    bad += 1;
                    if detail.len() < 6 {
                        detail.push(format!("  n={n} trial={t}: produced an INVALID proof"));
                    }
                }
                Err(message) => {
                    boom += 1;
                    if detail.len() < 6 {
                        detail.push(format!("  n={n} trial={t}: {message}"));
                    }
                }
            }
        }
        println!("| {n} | {ok}/{TRIALS} | {bad} | {boom} |");
    }
    panic::set_hook(previous);
    if !detail.is_empty() {
        println!("\nFirst failures:");
        for line in &detail {
            println!("{line}");
        }
    } else {
        println!(
            "\nEvery trial verified. The host path is clean at these response counts, so the\n\
             device failure is not reproduced here and is device-specific — or depends on a\n\
             configuration this example does not share (the device uses RC = u8; this uses\n\
             the host library's RC = usize)."
        );
    }
}
