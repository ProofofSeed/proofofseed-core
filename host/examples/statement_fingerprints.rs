// SPDX-License-Identifier: LGPL-3.0-or-later

//! Prints the circuit fingerprint of every implemented statement.
//!
//! Run: `cargo run --release -p proofofseed-host --example statement_fingerprints`

use proofofseed_circuits::comb::ComputedComb;
use proofofseed_circuits::request::Family::{self, Bip32Secp256k1 as B32, Slip10Ed25519 as S10};
use proofofseed_circuits::{
    BIP39_SEED, ETH_ADDRESS, HARDENED_CHILD, MASTER_KEY, NORMAL_CHILD, PUBLIC_KEY,
    statement_fingerprint,
};

fn show(family: Family, name: &str, statement: u8) {
    let fp = statement_fingerprint::<ComputedComb>(family, statement, 2048, None, None)
        .expect("implemented statement");
    println!("| {} | {name} | `{}` |", family as u8, hex(&fp));
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    println!("| family | statement | fingerprint |");
    println!("|---|---|---|");
    show(B32, "master key", MASTER_KEY);
    show(B32, "hardened child", HARDENED_CHILD);
    show(B32, "BIP-39 seed (r=2048)", BIP39_SEED);
    show(B32, "public key", PUBLIC_KEY);
    show(B32, "normal child", NORMAL_CHILD);
    show(B32, "Ethereum address", ETH_ADDRESS);
    show(S10, "master key", MASTER_KEY);
    show(S10, "hardened child", HARDENED_CHILD);
}
