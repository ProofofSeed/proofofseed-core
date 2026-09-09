// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profiles the proof-of-seed statements for on-device (Ledger) memory budgeting.
//!
//! Prints, per circuit, the max individual refcount (does `RC = u8` overflow 255?),
//! the executor/prover working-set heap at each refcount width, and state sizes.
//!
//! Run: `cargo run --release -p zkboo-bip32 --example profile_seed_statements`

use zkboo::backend::{Backend, Frontend};
use proofofseed_circuits::assert_nothing;
use zkboo::circuit::Circuit;
use zkboo::executor::{ExecOptions, exec, OwnedFlexibleWordPool};
use zkboo_bip32::{hardened_child_key, master_key};
use zkboo_profiling::{profile, ProfilingData};

struct MasterKeyCircuit {
    seed: Vec<u8>,
}

impl Circuit for MasterKeyCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let seed = self
            .seed
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let (il, ir) = master_key(frontend.allocator(), seed);
        il.into_iter().for_each(|w| frontend.output(w));
        ir.into_iter().for_each(|w| frontend.output(w));
        assert_nothing(frontend);
    }
}

struct HardenedChildCircuit {
    chain_code: Vec<u8>,
    parent_priv: Vec<u8>,
    index: u32,
}

impl Circuit for HardenedChildCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let cc = self
            .chain_code
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let pk = self
            .parent_priv
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let (child, cc_out) = hardened_child_key(frontend.allocator(), cc, pk, self.index);
        frontend.output(child);
        cc_out.into_iter().for_each(|w| frontend.output(w));
        assert_nothing(frontend);
    }
}

fn report(name: &str, prof: &ProfilingData) {
    println!("\n── {name} ────────────────────────────────");
    println!("  max individual refcount : {:?}", prof.max_refcount());
    println!("    -> u8 overflow (>255)?  {}", refcount_overflows_u8(prof));
    println!("  max cumulative refcount : {:?}", prof.max_cumulative_refcount());
    println!("  max live wordrefs       : {:?}", prof.max_live_wordrefs());
    println!("  state size (words)      : {:?}", prof.state_size());
    let ex8 = prof.executor_mem_usage::<u8>();
    let ex16 = prof.executor_mem_usage::<u16>();
    let ex32 = prof.executor_mem_usage::<u32>();
    println!(
        "  executor heap  u8={} u16={} u32={}  (stack u8={})",
        ex8.heap, ex16.heap, ex32.heap, ex8.stack
    );
    let pr8 = prof.prover_mem_usage::<u8>();
    let pr16 = prof.prover_mem_usage::<u16>();
    let pr32 = prof.prover_mem_usage::<u32>();
    println!(
        "  prover   heap  u8={} u16={} u32={}  (stack u8={})",
        pr8.heap, pr16.heap, pr32.heap, pr8.stack
    );
    println!(
        "  prover  total  u8={} u16={} u32={}",
        pr8.total(),
        pr16.total(),
        pr32.total()
    );
}

/// Whether any per-word-type max refcount exceeds what a u8 can hold (255).
fn refcount_overflows_u8(prof: &ProfilingData) -> bool {
    // Shape implements Debug; compare via its components by formatting is fragile,
    // so sum the max across word types — if the *max* per type > 255 we report it.
    // (Shape::sum gives the total; we want the per-type max, which Debug shows.)
    format!("{:?}", prof.max_refcount())
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|s| s.parse::<u64>().ok())
        .any(|v| v > 255)
}

fn main() {
    // Replicate the DEVICE code path exactly: exec with RC = u8 (the on-device
    // refcount type), not the usize the tests use. If this matches the BIP-32
    // vector, the on-device exec crash is environmental (machine stack / allocator),
    // not a logic bug in the u8 path.
    let master = MasterKeyCircuit {
        seed: (0u8..16).collect(),
    };
    let out_u8 = exec::<MasterKeyCircuit, OwnedFlexibleWordPool<u8>, _>(&master, ExecOptions::new()).u8;
    let il = out_u8[..32].iter().map(|b| format!("{b:02x}")).collect::<String>();
    let expect_il = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
    println!("exec<RC=u8> master IL = {il}");
    println!("  matches BIP-32 vector 1: {}", il == expect_il);

    report("master_key (HMAC-SHA512)", &profile(&master));

    // BIP-32 vector 1 m/0H inputs (32-byte chain code + 32-byte parent priv).
    let hardened = HardenedChildCircuit {
        chain_code: vec![0x11; 32],
        parent_priv: vec![0x22; 32],
        index: 0x8000_0000,
    };
    report("hardened_child_key", &profile(&hardened));
}
