// SPDX-License-Identifier: LGPL-3.0-or-later
//
//! Off-device prover-memory estimator. Reports the ZKBoo streaming prover's heap and
//! stack footprint for each statement using the `u8` refcount type (the on-device
//! estimate), so we can pick a HEAP_SIZE for the elephant build after the fixed-base
//! comb scalar-mult landed (the comb's precomputed table may move the heap).
//!
//!     cargo run -p proofofseed-host --example profile_mem --release

use proofofseed_circuits::{
    bip39_seed_circuit, ethereum_address_circuit, hardened_child_circuit, master_key_circuit,
    normal_child_circuit, public_key_circuit,
};
use zkboo::circuit::Circuit;
use zkboo_profiling::profile;

type RC = u8;

fn row<C: Circuit>(name: &str, circuit: &C) {
    let p = profile(circuit);
    let prover = p.prover_mem_usage::<RC>();
    let state = p.state_mem_usage();
    println!(
        "{name:18} heap {:>8}  stack {:>8}   (state heap {:>7})",
        prover.heap, prover.stack, state.heap
    );
}

fn main() {
    println!("statement           prover RAM (u8 refcounts)");
    row("master_key", &master_key_circuit());
    row("hardened_child", &hardened_child_circuit());
    row("bip39_seed(r=2)", &bip39_seed_circuit(2));
    row("public_key", &public_key_circuit());
    row("normal_child", &normal_child_circuit());
    row("ethereum_address", &ethereum_address_circuit());
}
