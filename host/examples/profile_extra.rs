// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profiles the statements beyond the app's six — the per-chain address bindings
//! (Bitcoin P2PKH/P2WPKH, P2SH-P2WPKH, Taproot; Solana ed25519 public key) and the
//! BIP-39 seed derivation across round counts — for proof-size and device-budget
//! tracking. Everything here is computed off-device with `zkboo-profiling`
//! (`response_size` matches the streamed byte count exactly; cross-checked against
//! the `proof_size` example on the six app statements).
//!
//! Run: `cargo run --release -p proofofseed-host --example profile_extra`

use proofofseed_circuits::bip39_seed_circuit;
use zkboo::backend::{Backend, Frontend};
use zkboo::circuit::Circuit;
use zkboo_bip32::{
    be_bytes_to_word, ed25519_public_key, p2sh_p2wpkh_payload, pubkey_hash160, taproot_output_key,
};
use zkboo_profiling::{ProfilingData, profile};

type D = [u8; 32];
type S = [u8; 32];

/// A fixed nonzero witness; sizes are data-oblivious, so any value profiles alike.
const KEY: [u8; 32] = [0x5A; 32];

struct PubkeyHash160;
impl Circuit for PubkeyHash160 {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let bytes: [_; 32] = core::array::from_fn(|i| frontend.input(KEY[i]));
        let scalar = be_bytes_to_word(&bytes);
        pubkey_hash160(frontend, scalar)
            .into_iter()
            .for_each(|w| frontend.output(w));
    }
}

struct P2shP2wpkhPayload;
impl Circuit for P2shP2wpkhPayload {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let bytes: [_; 32] = core::array::from_fn(|i| frontend.input(KEY[i]));
        let scalar = be_bytes_to_word(&bytes);
        p2sh_p2wpkh_payload(frontend, scalar)
            .into_iter()
            .for_each(|w| frontend.output(w));
    }
}

struct TaprootOutputKey;
impl Circuit for TaprootOutputKey {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let bytes: [_; 32] = core::array::from_fn(|i| frontend.input(KEY[i]));
        let scalar = be_bytes_to_word(&bytes);
        taproot_output_key(frontend, scalar)
            .into_iter()
            .for_each(|w| frontend.output(w));
    }
}

struct Ed25519Pubkey;
impl Circuit for Ed25519Pubkey {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let key: [_; 32] = core::array::from_fn(|i| frontend.input(KEY[i]));
        ed25519_public_key(frontend, &key)
            .into_iter()
            .for_each(|w| frontend.output(w));
    }
}

fn report(name: &str, prof: &ProfilingData) {
    let resp = prof.response_size::<D, S>();
    println!(
        "{name:34} {resp:>11} B   @438 {:>8.1} MiB   prover mem (RC=u8) {:>6} B",
        prof.proof_size::<D, S>(438) as f64 / (1024.0 * 1024.0),
        prof.prover_mem_usage::<u8>().total(),
    );
}

fn main() {
    println!(
        "statement                            bytes/resp        proof @438     prover mem\n"
    );
    println!("Bitcoin / Solana address bindings (elephants):");
    report("pubkey_hash160 (P2PKH/P2WPKH)", &profile(&PubkeyHash160));
    report("p2sh_p2wpkh_payload", &profile(&P2shP2wpkhPayload));
    report("taproot_output_key (P2TR)", &profile(&TaprootOutputKey));
    report("ed25519 public key (Solana addr)", &profile(&Ed25519Pubkey));
    println!("\nBIP-39 seed derivation by round count:");
    for r in [1usize, 2, 8, 64, 2048] {
        report(
            &format!("bip39_seed (r={r})"),
            &profile(&bip39_seed_circuit(r)),
        );
    }
}
