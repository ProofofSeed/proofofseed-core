// SPDX-License-Identifier: LGPL-3.0-or-later

//! What the affine comb's advice pass costs, against one response of the same statement.
//!
//! Since zkboo v1.2.0 the fixed-base comb takes its chord slopes as circuit inputs the caller
//! computes, rather than asking the backend for them mid-pass. On a host that is bookkeeping.
//! On a secure element it is a stretch of native field arithmetic — one Fermat inversion per
//! comb window — that runs before any backend exists, and therefore outside the reach of the
//! app's `BackendHook`: exactly the shape that reboots a Ledger through its OS watchdog.
//!
//! This puts a number on it in the only terms that transfer, as a fraction of a response of
//! the statement it belongs to. Scaling that fraction by the device's measured per-response
//! time assumes the two workloads slow down alike, which they need not — one is native
//! arithmetic and the other is gate work — so the result is an estimate, and the pass still
//! wants measuring on hardware.
//!
//! Run: `cargo run --release -p proofofseed-host --example advice_cost`

use std::time::Instant;

use proofofseed_circuits::comb::{CombTableSource, ComputedComb, FlashComb};
use proofofseed_circuits::public_key_circuit;
use proofofseed_host::harness::gen_stream;
use zkboo::word::CompositeWord;
use zkboo_bip32::public_key_advice_with_tables;

/// Mean seconds per call over `n` calls, after one warm-up.
fn time<T>(n: usize, mut f: impl FnMut() -> T) -> f64 {
    std::hint::black_box(f());
    let start = Instant::now();
    for _ in 0..n {
        std::hint::black_box(f());
    }
    start.elapsed().as_secs_f64() / n as f64
}

fn main() {
    let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let scalar = CompositeWord::<u64, 4>::from_be_bytes(core::array::from_fn(|i| {
        core::array::from_fn(|j| key[8 * i + j])
    }));
    let computed = time(50, || {
        let mut tables = ComputedComb::make();
        public_key_advice_with_tables(scalar, &mut tables)
    });
    let flash = time(50, || {
        let mut tables = FlashComb::make();
        public_key_advice_with_tables(scalar, &mut tables)
    });
    let response = time(3, || gen_stream(&public_key_circuit(), 1, b"entropy", b"binding"));
    println!("advice, comb tables recomputed : {:9.3} ms", computed * 1e3);
    println!("advice, comb tables from flash : {:9.3} ms   (the device's configuration)", flash * 1e3);
    println!("one public_key response        : {:9.3} ms", response * 1e3);
    println!(
        "\nadvice is {:.3}% of a response; at the Flex's 1,508 s/response that is ~{:.1} s,\n\
         against a watchdog window of 30-50 s.",
        100.0 * flash / response,
        1508.0 * flash / response,
    );
}
