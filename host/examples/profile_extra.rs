// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profiles the statements beyond the app's six — the per-chain address bindings
//! (Bitcoin P2PKH/P2WPKH, P2SH-P2WPKH, Taproot; Solana ed25519 public key) and the
//! BIP-39 seed derivation across round counts — for proof-size and device-budget
//! tracking. Everything here is computed off-device with `zkboo-profiling`
//! (`response_size` matches the streamed byte count exactly; cross-checked against
//! the `proof_size` example on the six app statements).
//!
//! Run: `cargo run --release -p proofofseed-host --example profile_extra`

use proofofseed_circuits::comb::ComputedComb;
use proofofseed_circuits::{
    PubKeyCircuit, bip39_seed_circuit, ethereum_address_circuit, public_key_circuit,
};
use zkboo::backend::{Backend, Frontend};
use zkboo::circuit::{Assertions, Circuit};
use zkboo_bip32::{
    be_bytes_to_word, ed25519_public_key, p2sh_p2wpkh_payload, pubkey_hash160, solana_pubkey,
    taproot_output_key,
};
use zkboo_profiling::{ProfilingData, profile};

type D = [u8; 32];
type S = [u8; 32];

/// A fixed nonzero witness; sizes are data-oblivious, so any value profiles alike.
const KEY: [u8; 32] = [0x5A; 32];

/// A 64-byte seed, the length a BIP-39 mnemonic produces.
const SEED: [u8; 64] = [0x5A; 64];

/// Every circuit here is handed `None` for whatever the host would otherwise mirror —
/// a comb's scalar, an advised affine point: the profiling backend discards input values,
/// so a mirror would compute what nothing reads. The gate counts these figures come from
/// are the same either way, which is the whole reason a verifier can pass `None` too.
struct PubkeyHash160;
impl Circuit for PubkeyHash160 {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        Assertions::scope(frontend, |assertions| {
            let bytes: [_; 32] = core::array::from_fn(|i| frontend.input(KEY[i]));
            let scalar = be_bytes_to_word(&bytes);
            pubkey_hash160(frontend, scalar, None, assertions)
                .into_iter()
                .for_each(|w| frontend.output(w));
        });
    }
}

struct P2shP2wpkhPayload;
impl Circuit for P2shP2wpkhPayload {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        Assertions::scope(frontend, |assertions| {
            let bytes: [_; 32] = core::array::from_fn(|i| frontend.input(KEY[i]));
            let scalar = be_bytes_to_word(&bytes);
            p2sh_p2wpkh_payload(frontend, scalar, None, assertions)
                .into_iter()
                .for_each(|w| frontend.output(w));
        });
    }
}

struct TaprootOutputKey;
impl Circuit for TaprootOutputKey {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        Assertions::scope(frontend, |assertions| {
            let bytes: [_; 32] = core::array::from_fn(|i| frontend.input(KEY[i]));
            let scalar = be_bytes_to_word(&bytes);
            taproot_output_key(frontend, scalar, None, None, assertions)
                .into_iter()
                .for_each(|w| frontend.output(w));
        });
    }
}

struct Ed25519Pubkey;
impl Circuit for Ed25519Pubkey {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        Assertions::scope(frontend, |assertions| {
            let key: [_; 32] = core::array::from_fn(|i| frontend.input(KEY[i]));
            ed25519_public_key(frontend, &key, None, assertions)
                .into_iter()
                .for_each(|w| frontend.output(w));
        });
    }
}

/// The whole Solana statement: a 64-byte seed through the SLIP-10 chain at
/// `m/44'/501'/account'/0'`, then the ed25519 public key.
///
/// This is the statement, and [Ed25519Pubkey] above is only its last step. The two differ
/// by the SLIP-10 layer, which is why they are profiled side by side: reading one row for
/// the other understates the statement, and did.
struct SolanaPubkey;
impl Circuit for SolanaPubkey {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        Assertions::scope(frontend, |assertions| {
            let seed = (0..64).map(|i| frontend.input(SEED[i])).collect::<Vec<_>>();
            solana_pubkey(frontend, seed, 0, None, assertions)
                .into_iter()
                .for_each(|w| frontend.output(w));
        });
    }
}

/// AND-messages: one per AND gate, plus one per CARRY gate, at that gate's word width.
///
/// This is the structural quantity. A response size moves by a whole input share whenever
/// the challenge lands the other way, so two profiles differing by one share agree; a
/// response size moving while this does not is bimodality, and this moving is the circuit.
fn and_messages(prof: &ProfilingData) -> usize {
    let gates = prof.gate_counts();
    return gates.bitand.sum() + gates.carry.sum();
}

fn report(name: &str, prof: &ProfilingData) {
    let resp = prof.response_size::<D, S>();
    println!(
        "{name:34} {:>10} {resp:>11} B   @438 {:>8.1} MiB   prover mem (RC=u8) {:>6} B",
        and_messages(prof),
        prof.proof_size::<D, S>(438) as f64 / (1024.0 * 1024.0),
        prof.prover_mem_usage::<u8>().total(),
    );
}

fn main() {
    println!(
        "statement                          AND-msgs   bytes/resp        proof @438     prover mem\n"
    );
    // The app's own curve statements, as controls: they share the secp256k1 fixed-base
    // comb with the Bitcoin rows, so a release that moves one of the rows below and not
    // these has moved something other than the comb.
    println!("Controls — the app's secp256k1 statements:");
    report(
        "public_key (affine x‖y)",
        &profile(&PubKeyCircuit::<ComputedComb>::new(
            public_key_circuit().private_key.clone(),
        )),
    );
    report("ethereum_address", &profile(&ethereum_address_circuit()));
    println!("\nBitcoin / Solana address bindings (elephants):");
    report("pubkey_hash160 (P2PKH/P2WPKH)", &profile(&PubkeyHash160));
    report("p2sh_p2wpkh_payload", &profile(&P2shP2wpkhPayload));
    report("taproot_output_key (P2TR)", &profile(&TaprootOutputKey));
    report("solana_pubkey (the statement)", &profile(&SolanaPubkey));
    report("  of which ed25519_public_key", &profile(&Ed25519Pubkey));
    println!("\nBIP-39 seed derivation by round count:");
    for r in [1usize, 2, 8, 64, 2048] {
        report(
            &format!("bip39_seed (r={r})"),
            &profile(&bip39_seed_circuit(r)),
        );
    }
}
