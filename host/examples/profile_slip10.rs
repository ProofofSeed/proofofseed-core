// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profiles the SLIP-10/ed25519 statements beside their BIP-32 counterparts: gate
//! counts, refcounts, per-response proof size, and the estimated prover working set.
//!
//! Run: `cargo run --release -p proofofseed-host --example profile_slip10`

use proofofseed_circuits::{
    hardened_child_circuit, master_key_circuit, slip10_child_circuit, slip10_master_circuit,
};
use zkboo_profiling::{ProfilingData, profile};

type D = [u8; 32];
type S = [u8; 32];

fn report(name: &str, prof: &ProfilingData) {
    println!("\n── {name} ────────────────────────────────");
    println!("  max individual refcount : {:?}", prof.max_refcount());
    println!("  response size (D=S=32B) : {} B", prof.response_size::<D, S>());
    println!("  proof size @438         : {:.1} MiB", prof.proof_size::<D, S>(438) as f64 / (1024.0 * 1024.0));
    println!("  prover mem (RC=u8)      : {} B", prof.prover_mem_usage::<u8>().total());
    println!("  executor mem (RC=u8)    : {} B", prof.executor_mem_usage::<u8>().total());
}

fn main() {
    report("BIP-32 master key (family 0)", &profile(&master_key_circuit()));
    report("SLIP-10 master key (family 1)", &profile(&slip10_master_circuit()));
    report("BIP-32 hardened child (family 0)", &profile(&hardened_child_circuit()));
    report("SLIP-10 hardened child (family 1)", &profile(&slip10_child_circuit()));
}
