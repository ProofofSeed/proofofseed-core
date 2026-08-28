// SPDX-License-Identifier: LGPL-3.0-or-later

//! Every statement's public output, against its canonical vector.
//!
//! These checks existed only inside `validate_statements`, a hand-run example — so they
//! were not run by anything, and five of the six had been failing since ZKBoo 2.0.0
//! appended the assertion word without anyone seeing it. The values are what a verifier
//! pins a proof against, so they belong in the suite.

use proofofseed_circuits::{
    EXPECTED_BIP39_SEED, EXPECTED_ETH_ADDRESS, EXPECTED_HARDENED_CC, EXPECTED_HARDENED_PRIV,
    EXPECTED_MASTER, EXPECTED_NORMAL_CC, EXPECTED_NORMAL_PRIV, EXPECTED_PUBKEY,
    bip39_seed_circuit, checked_payload, ethereum_address_circuit, hardened_child_circuit,
    master_key_circuit, normal_child_circuit, public_key_circuit,
};
use zkboo::circuit::Circuit;
use zkboo::executor::{OwnedFlexibleWordPool, exec};
use zkboo::word::Words;

type WP = OwnedFlexibleWordPool<usize>;

fn payload<C: Circuit>(circuit: &C) -> Words {
    checked_payload(exec::<C, WP>(circuit)).expect("assertions hold")
}

fn u8_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A 256-bit value emitted as four little-endian-ordered u64 limbs, as big-endian hex.
fn u64x4_be_hex(limbs: &[u64]) -> String {
    limbs.iter().rev().flat_map(|l| l.to_be_bytes()).map(|b| format!("{b:02x}")).collect()
}

#[test]
fn every_statement_produces_its_canonical_output() {
    let master = payload(&master_key_circuit());
    assert_eq!(u8_hex(&master.u8), EXPECTED_MASTER, "master_key");

    let child = payload(&hardened_child_circuit());
    assert_eq!(u64x4_be_hex(&child.u64[0..4]), EXPECTED_HARDENED_PRIV, "hardened_child key");
    assert_eq!(u8_hex(&child.u8), EXPECTED_HARDENED_CC, "hardened_child chain code");

    let seed = payload(&bip39_seed_circuit(2048));
    assert_eq!(u8_hex(&seed.u8), EXPECTED_BIP39_SEED, "bip39_seed");

    // The public key of private key 1 is the generator itself, so this pins the affine
    // coordinates the comb emits against a value that is not this code's own opinion.
    let pk = payload(&public_key_circuit());
    let pk_hex = format!("{}{}", u64x4_be_hex(&pk.u64[0..4]), u64x4_be_hex(&pk.u64[4..8]));
    assert_eq!(pk_hex, EXPECTED_PUBKEY, "public_key");

    let normal = payload(&normal_child_circuit());
    assert_eq!(u64x4_be_hex(&normal.u64[0..4]), EXPECTED_NORMAL_PRIV, "normal_child key");
    assert_eq!(u8_hex(&normal.u8), EXPECTED_NORMAL_CC, "normal_child chain code");

    let address = payload(&ethereum_address_circuit());
    assert_eq!(u8_hex(&address.u8), EXPECTED_ETH_ADDRESS, "ethereum_address");
}
