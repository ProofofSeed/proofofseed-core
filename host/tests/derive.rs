// SPDX-License-Identifier: LGPL-3.0-or-later

//! The executor-based derivation module against the published vectors, and the
//! byte-equality of the write-streaming prover with the in-memory one.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use proofofseed_circuits::hardened_child_circuit;
use proofofseed_host::derive;
use proofofseed_host::harness::{gen_stream, gen_stream_range, gen_stream_range_to, gen_stream_to};

const H: u32 = 0x8000_0000;

const MNEMONIC: &[u8] = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// BIP-86's published `m/86'/0'/0'` account key for that mnemonic.
const BIP86_ACCOUNT_XPRV: &str = "xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn xprv_key_cc(s: &str) -> ([u8; 32], [u8; 32]) {
    let body = bitcoin::base58::decode_check(s).expect("valid base58check");
    (body[46..78].try_into().unwrap(), body[13..45].try_into().unwrap())
}

#[test]
fn bip32_walk_matches_the_published_account_key() {
    let seed = derive::bip39_seed(MNEMONIC, b"");
    let node = derive::bip32_node(&seed, &[H | 86, H, H]);
    let (key, cc) = xprv_key_cc(BIP86_ACCOUNT_XPRV);
    assert_eq!(*node.private_key, key, "m/86'/0'/0' private key");
    assert_eq!(node.chain_code, cc, "m/86'/0'/0' chain code");
}

#[test]
fn bip32_walk_with_a_normal_component_matches_rust_bitcoin() {
    let seed = derive::bip39_seed(MNEMONIC, b"");
    let node = derive::bip32_node(&seed, &[H | 44, 0]);
    let root = Xpriv::new_master(bitcoin::NetworkKind::Main, &seed).expect("master");
    let path = DerivationPath::from_str("m/44'/0").expect("valid path");
    let reference = root.derive_priv(&Secp256k1::new(), &path).expect("derivation");
    assert_eq!(
        *node.private_key,
        reference.private_key.secret_bytes(),
        "m/44'/0 private key vs rust-bitcoin"
    );
    assert_eq!(node.chain_code, reference.chain_code.to_bytes(), "m/44'/0 chain code");
}

#[test]
fn slip10_walk_matches_the_published_vector() {
    // SLIP-0010 ed25519 test vector 1: seed 000102…0f, master and m/0'.
    let seed = hex("000102030405060708090a0b0c0d0e0f");
    let master = derive::slip10_node(&seed, &[]).expect("empty path is valid");
    assert_eq!(
        master.private_key.to_vec(),
        hex("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"),
        "master key"
    );
    assert_eq!(
        master.chain_code.to_vec(),
        hex("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"),
        "master chain code"
    );
    let child = derive::slip10_node(&seed, &[H]).expect("hardened path is valid");
    assert_eq!(
        child.private_key.to_vec(),
        hex("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"),
        "m/0' key"
    );
    assert_eq!(
        child.chain_code.to_vec(),
        hex("8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"),
        "m/0' chain code"
    );
    assert!(derive::slip10_node(&seed, &[0]).is_none(), "a non-hardened component refuses");
}

#[test]
fn write_streaming_prover_is_byte_identical_to_the_in_memory_one() {
    let circuit = hardened_child_circuit();
    let entropy = b"write-sink-entropy";
    let binding = b"write-sink-binding";
    let full = gen_stream(&circuit, 3, entropy, binding);
    let mut out = Vec::new();
    let written = gen_stream_to(&circuit, 3, entropy, binding, &mut out).expect("io");
    assert_eq!(out, full, "full stream via Write");
    assert_eq!(written as usize, full.len(), "byte count");
    let segment = gen_stream_range(&circuit, 3, (1, 2), entropy, binding);
    let mut seg_out = Vec::new();
    gen_stream_range_to(&circuit, 3, (1, 2), entropy, binding, &mut seg_out).expect("io");
    assert_eq!(seg_out, segment, "range stream via Write");
}
