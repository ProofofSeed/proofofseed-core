// SPDX-License-Identifier: LGPL-3.0-or-later

//! Bitcoin recovery-statement validation, entirely off-device.
//!
//! The hardened-child statement is chain-agnostic (BIP-32 is the same derivation for
//! Bitcoin and Ethereum); these tests make that demonstrable by anchoring the exact
//! shared circuits the device proves with (`proofofseed_circuits`) at Bitcoin account paths,
//! against two independent references:
//!
//! - the published BIP-84/BIP-86 test vectors (base58check-decoded in-test, so a
//!   corrupted vector string fails loudly rather than silently anchoring nothing), and
//! - `rust-bitcoin`'s BIP-32 implementation, for the purposes (44', 49') whose BIP
//!   documents publish no mainnet account-level keys.
//!
//! The full pipeline is covered end to end with public data only: BIP-39 mnemonic →
//! seed (2048 PBKDF2 rounds, in-circuit) → master node (in-circuit) → three hardened
//! steps per purpose (in-circuit) → the published account keys. Round trips then prove
//! and verify the account-level hardened-child statement in the device configuration
//! (Keccak-256 suite, request-anchored chain code + index, nonempty binding), with the
//! wrong-chain-code / wrong-index / wrong-binding refusals asserted against the same
//! proof that just verified — each refusal test's positive twin shows it can go green.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use proofofseed_circuits::{HARDENED_CHILD, HardenedChildCircuit, MasterKeyCircuit, SeedCircuit};
use proofofseed_host::harness::{exec_words, gen_stream, output_of};
use proofofseed_host::verify;
use zkboo::word::Words;

const H: u32 = 0x8000_0000;

/// The standard BIP-39 test mnemonic shared by the BIP-49/84/86 test vectors.
const MNEMONIC: &[u8] = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// The published root key of that mnemonic (empty passphrase): BIP-86's `rootpriv`.
/// BIP-84 publishes the same key material in `zprv` encoding (checked below).
const ROOT_XPRV: &str = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
const ROOT_ZPRV: &str = "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5";

/// The published account-level keys: BIP-84's `m/84'/0'/0'` zprv and BIP-86's
/// `m/86'/0'/0'` xprv. (BIP-44 publishes no key vectors and BIP-49's are
/// testnet-only, so 44' and 49' anchor against rust-bitcoin instead.)
const BIP84_ACCOUNT_ZPRV: &str = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE";
const BIP86_ACCOUNT_XPRV: &str = "xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk";

const PURPOSES: [u32; 4] = [44, 49, 84, 86];

/// Decodes any BIP-32 extended private key (xprv/yprv/zprv — the version bytes are
/// ignored) into `(private key, chain code)`, verifying the base58 checksum.
fn xprv_key_cc(s: &str) -> ([u8; 32], [u8; 32]) {
    let body = bitcoin::base58::decode_check(s).expect("valid base58check");
    assert_eq!(body.len(), 78, "extended-key payload length");
    assert_eq!(body[45], 0, "private-key prefix byte");
    (body[46..78].try_into().unwrap(), body[13..45].try_into().unwrap())
}

fn root() -> Xpriv {
    Xpriv::from_str(ROOT_XPRV).expect("valid root xprv")
}

/// rust-bitcoin reference node at `path` (e.g. `"84'/0'"`): `(private key, chain code)`.
fn reference_node(path: &str) -> ([u8; 32], [u8; 32]) {
    let node = root()
        .derive_priv(&Secp256k1::new(), &DerivationPath::from_str(path).expect("valid path"))
        .expect("derivable path");
    (node.private_key.secret_bytes(), node.chain_code.to_bytes())
}

/// The account-level hardened-child statement circuit for `m/purpose'/0'/0'`:
/// witness = the parent node `m/purpose'/0'` (as the device would derive via BOLOS),
/// public parameters = the asserted parent chain code and child index `0'`.
fn account_circuit(purpose: u32) -> HardenedChildCircuit {
    let (parent_priv, parent_cc) = reference_node(&format!("{purpose}'/0'"));
    HardenedChildCircuit {
        chain_code: parent_cc.to_vec(),
        parent_priv: parent_priv.to_vec(),
        index: H,
    }
}

/// Splits the hardened-child circuit output into `(child private key BE, chain code)`.
fn child_priv_cc(words: &Words) -> ([u8; 32], [u8; 32]) {
    assert_eq!(words.u64.len(), 4, "child key limbs");
    assert_eq!(words.u8.len(), 32, "chain code bytes");
    let mut priv_be = [0u8; 32];
    for (i, limb) in words.u64.iter().rev().enumerate() {
        priv_be[8 * i..8 * i + 8].copy_from_slice(&limb.to_be_bytes());
    }
    (priv_be, words.u8[..].try_into().unwrap())
}

#[test]
fn published_root_encodings_agree() {
    // BIP-84's zprv and BIP-86's xprv decode to the same key material, and
    // rust-bitcoin parses the root to the same values — the anchors are consistent.
    let (key, cc) = xprv_key_cc(ROOT_XPRV);
    assert_eq!(xprv_key_cc(ROOT_ZPRV), (key, cc), "zprv/xprv encodings of the root");
    assert_eq!(root().private_key.secret_bytes(), key, "rust-bitcoin root key");
    assert_eq!(root().chain_code.to_bytes(), cc, "rust-bitcoin root chain code");
}

#[test]
fn mnemonic_to_published_root_through_the_circuits() {
    // BIP-39 mnemonic → seed (full 2048 PBKDF2 rounds) → BIP-32 master node, both
    // steps through the exact circuits the device proves with, landing on the
    // published root key. Empty passphrase ⇒ salt "mnemonic".
    let seed = exec_words(&SeedCircuit {
        mnemonic: MNEMONIC.to_vec(),
        salt: b"mnemonic".to_vec(),
        rounds: 2048,
    });
    assert_eq!(seed.u8.len(), 64, "BIP-39 seed length");
    let master = exec_words(&MasterKeyCircuit { seed: seed.u8.clone() });
    let (root_key, root_cc) = xprv_key_cc(ROOT_XPRV);
    assert_eq!(master.u8[..32], root_key, "master private key vs published root");
    assert_eq!(master.u8[32..], root_cc, "master chain code vs published root");
    // rust-bitcoin agrees on the master step from the circuit-derived seed.
    let reference = Xpriv::new_master(bitcoin::NetworkKind::Main, &seed.u8).expect("master");
    assert_eq!(reference.private_key.secret_bytes(), root_key, "reference master key");
}

#[test]
fn hardened_chain_from_root_to_account_matches_reference() {
    // Three hardened-child circuit steps m → purpose' → purpose'/0' → purpose'/0'/0',
    // each feeding the next, cross-checked against rust-bitcoin at every node.
    let (root_key, root_cc) = xprv_key_cc(ROOT_XPRV);
    for purpose in PURPOSES {
        let (mut key, mut cc) = (root_key, root_cc);
        let steps = [(purpose, format!("{purpose}'")), (0, format!("{purpose}'/0'")), (0, format!("{purpose}'/0'/0'"))];
        for (index, path) in steps {
            let words = exec_words(&HardenedChildCircuit {
                chain_code: cc.to_vec(),
                parent_priv: key.to_vec(),
                index: H | index,
            });
            (key, cc) = child_priv_cc(&words);
            assert_eq!((key, cc), reference_node(&path), "node m/{path}");
        }
    }
}

#[test]
fn account_outputs_match_published_bip84_bip86_vectors() {
    // The account-level circuit outputs equal the published account keys directly.
    for (purpose, published) in [(84, BIP84_ACCOUNT_ZPRV), (86, BIP86_ACCOUNT_XPRV)] {
        let words = exec_words(&account_circuit(purpose));
        assert_eq!(
            child_priv_cc(&words),
            xprv_key_cc(published),
            "m/{purpose}'/0'/0' vs the published vector"
        );
    }
}

#[test]
fn account_proof_round_trips_with_asserted_params_and_binding() {
    // The recovery statement at each Bitcoin account path, request-anchored and
    // binding-bound, proven and verified in the device configuration. Each negative
    // corrupts exactly one input of the verification that just passed, naming the
    // check that refuses it.
    const N: usize = 4;
    let binding = b"bitcoin-recovery-tx";
    for purpose in PURPOSES {
        let circuit = account_circuit(purpose);
        let cc = circuit.chain_code.clone();
        let output = output_of(&circuit);
        let stream = gen_stream(&circuit, N, b"test-entropy", binding);
        assert!(
            verify(HARDENED_CHILD, &output, &stream, N, binding, 0, Some(&cc), Some(H), 0),
            "m/{purpose}'/0'/0' proof must verify under the asserted params"
        );
        let mut wrong_cc = cc.clone();
        wrong_cc[0] ^= 0xff;
        assert!(
            !verify(HARDENED_CHILD, &output, &stream, N, binding, 0, Some(&wrong_cc), Some(H), 0),
            "m/{purpose}'/0'/0': a wrong asserted chain code must refuse"
        );
        assert!(
            !verify(HARDENED_CHILD, &output, &stream, N, binding, 0, Some(&cc), Some(H | 1), 0),
            "m/{purpose}'/0'/0': a wrong asserted index must refuse"
        );
        assert!(
            !verify(HARDENED_CHILD, &output, &stream, N, b"some-other-tx", 0, Some(&cc), Some(H), 0),
            "m/{purpose}'/0'/0': a wrong binding must refuse"
        );
    }
}
