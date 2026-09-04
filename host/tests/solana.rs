// SPDX-License-Identifier: LGPL-3.0-or-later

//! SLIP-10/ed25519 (family 1) recovery-statement validation, entirely off-device.
//!
//! Anchors the shared family-1 circuits (`proofofseed_circuits`) against the official
//! SLIP-0010 ed25519 test vectors — private key AND chain code at every node of both
//! published chains — and against Solana wallet practice via the trust-wallet-core
//! vector (mnemonic → BIP-39 seed → SLIP-10 chain at m/44'/501'/0' → RFC 8032 public
//! key → the published address). Round trips then prove and verify the family-1
//! statements in the device configuration, with the wrong-chain-code / wrong-index /
//! wrong-binding / non-hardened-index refusals, and the cross-family negatives: a
//! proof made in one family never verifies in the other, in either direction.

use proofofseed_circuits::{
    EXPECTED_SLIP10_CHILD, EXPECTED_SLIP10_MASTER, HARDENED_CHILD, MASTER_KEY, PUBLIC_KEY,
    SeedCircuit, Slip10ChildCircuit, Slip10MasterCircuit, hardened_child_circuit,
    slip10_child_circuit, slip10_master_circuit,
};
use proofofseed_host::harness::{exec_words, gen_stream, output_of};
use proofofseed_host::{expected_output, verify};
use zkboo::backend::{Backend, Frontend};
use zkboo::circuit::{Assertions, Circuit};

const H: u32 = 0x8000_0000;
const BIP32_FAMILY: u8 = 0;
const SLIP10_FAMILY: u8 = 1;

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A circuit's outputs with the trailing assertion word checked and removed. None of
/// the SLIP-10 circuits can assert falsely — they touch no curve — so an execution that
/// reports otherwise here is a defect rather than a degenerate key.
fn payload(words: zkboo::word::Words) -> zkboo::word::Words {
    proofofseed_circuits::checked_payload(words).expect("SLIP-10 assertions hold")
}

/// Walks a SLIP-10 chain through the shared circuits: master from `seed`, then one
/// child step per (raw, unhardened) index. Returns `(key, chain code)` per node.
fn slip10_chain(seed: &[u8], path: &[u32]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let master = payload(exec_words(&Slip10MasterCircuit { seed: seed.to_vec() }));
    let mut nodes = vec![(master.u8[..32].to_vec(), master.u8[32..].to_vec())];
    for &index in path {
        let (key, cc) = nodes.last().expect("nonempty").clone();
        let child = payload(exec_words(&Slip10ChildCircuit {
            chain_code: cc,
            parent_priv: key,
            index: H | index,
        }));
        nodes.push((child.u8[..32].to_vec(), child.u8[32..].to_vec()));
    }
    nodes
}

#[test]
fn slip10_chains_match_the_published_vectors() {
    // The official SLIP-0010 ed25519 test vectors: key and chain code at every node.
    // (The published documents list both; the keys here are also cross-validated in
    // the zkboo-bip32 test suite together with each node's public key.)
    let vector_1: [(&str, &str); 6] = [
        ("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
         "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"),
        ("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
         "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"),
        ("b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
         "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"),
        ("92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
         "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c"),
        ("30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
         "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc"),
        ("8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
         "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230"),
    ];
    let vector_2: [(&str, &str); 6] = [
        ("171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
         "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b"),
        ("1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
         "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d"),
        ("ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
         "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f"),
        ("3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
         "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90"),
        ("5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
         "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a"),
        ("551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
         "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4"),
    ];
    let cases: [(&str, Vec<u32>, &[(&str, &str)]); 2] = [
        ("000102030405060708090a0b0c0d0e0f", vec![0, 1, 2, 2, 1000000000], &vector_1),
        (
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            vec![0, 2147483647, 1, 2147483646, 2],
            &vector_2,
        ),
    ];
    for (seed_hex, path, expected) in cases {
        let nodes = slip10_chain(&from_hex(seed_hex), &path);
        for (i, ((key, cc), (want_key, want_cc))) in nodes.iter().zip(expected).enumerate() {
            assert_eq!(to_hex(key), *want_key, "node {i} key");
            assert_eq!(to_hex(cc), *want_cc, "node {i} chain code");
        }
    }
}

#[test]
fn canonical_circuits_match_their_expected_constants() {
    let master = payload(exec_words(&slip10_master_circuit()));
    assert_eq!(to_hex(&master.u8), EXPECTED_SLIP10_MASTER);
    let child = payload(exec_words(&slip10_child_circuit()));
    assert_eq!(to_hex(&child.u8), EXPECTED_SLIP10_CHILD);
}

/// RFC 8032 public key of a derived key, for the wallet-core anchor below.
struct PubkeyOf {
    key: Vec<u8>,
}
impl Circuit for PubkeyOf {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let key: [_; 32] = core::array::from_fn(|i| frontend.input(self.key[i]));
        zkboo_bip32::ed25519_public_key(frontend, &key)
            .into_iter()
            .for_each(|w| frontend.output(w));
        // The suite's circuits all end with the assertion word, and [payload] strips it;
        // a circuit that omitted it would have its last payload byte eaten instead.
        Assertions::new().output(frontend);
    }
}

#[test]
fn solana_wallet_core_anchor() {
    // The trust-wallet-core vector (TWSolanaAddress.HDWallet): this mnemonic at
    // Solana's default path m/44'/501'/0' gives the address below, whose Base58
    // decoding is the ed25519 public key. The whole pipeline runs through the shared
    // statement circuits (BIP-39 seed at the full 2048 rounds, SLIP-10 master, three
    // hardened child steps), with the final RFC 8032 public-key step executed here.
    const MNEMONIC: &[u8] =
        b"shoot island position soft burden budget tooth cruel issue economy destroy above";
    const ADDRESS: &str = "2bUBiBNZyD29gP1oV6de7nxowMLoDBtopMMTGgMvjG5m";
    let seed = payload(exec_words(&SeedCircuit {
        mnemonic: MNEMONIC.to_vec(),
        salt: b"mnemonic".to_vec(),
        rounds: 2048,
    }));
    let nodes = slip10_chain(&seed.u8, &[44, 501, 0]);
    let (account_key, _) = nodes.last().expect("account node");
    let pubkey = payload(exec_words(&PubkeyOf { key: account_key.clone() }));
    let expected = bitcoin::base58::decode(ADDRESS).expect("valid base58 address");
    assert_eq!(pubkey.u8, expected, "public key vs the published Solana address");
}

#[test]
fn solana_account_proof_round_trips_with_asserted_params_and_binding() {
    // The family-1 recovery statement at Solana's account path m/44'/501'/0':
    // witness = the parent node m/44'/501', anchored on the asserted chain code and
    // hardened index, bound to a transaction stand-in. Each negative corrupts exactly
    // one input of the verification that just passed.
    const N: usize = 4;
    let binding = b"solana-recovery-tx";
    let seed: Vec<u8> = (0..64).collect();
    let nodes = slip10_chain(&seed, &[44, 501]);
    let (parent_key, parent_cc) = nodes.last().expect("parent node").clone();
    let circuit = Slip10ChildCircuit {
        chain_code: parent_cc.clone(),
        parent_priv: parent_key,
        index: H | 0,
    };
    let output = output_of(&circuit);
    let stream = gen_stream(&circuit, N, b"test-entropy", binding);
    let check = |output: &[u8], binding: &[u8], cc: &[u8], index: u32, family: u8| {
        verify(HARDENED_CHILD, output, &stream, N, binding, 0, Some(cc), Some(index), family)
    };
    assert!(
        check(&output, binding, &parent_cc, H | 0, SLIP10_FAMILY),
        "m/44'/501'/0' proof must verify under the asserted params"
    );
    let mut wrong_cc = parent_cc.clone();
    wrong_cc[0] ^= 0xff;
    assert!(
        !check(&output, binding, &wrong_cc, H | 0, SLIP10_FAMILY),
        "a wrong asserted chain code must refuse"
    );
    assert!(
        !check(&output, binding, &parent_cc, H | 1, SLIP10_FAMILY),
        "a wrong asserted index must refuse"
    );
    assert!(
        !check(&output, b"some-other-tx", &parent_cc, H | 0, SLIP10_FAMILY),
        "a wrong binding must refuse"
    );
    assert!(
        !check(&output, binding, &parent_cc, 0, SLIP10_FAMILY),
        "a non-hardened asserted index must refuse (SLIP-10 ed25519 is hardened-only)"
    );
    assert!(
        !check(&output, binding, &parent_cc, H | 0, BIP32_FAMILY),
        "the same proof must not verify in the BIP-32/secp256k1 family"
    );
    assert!(
        !check(&output, binding, &parent_cc, H | 0, 2),
        "an unknown family byte must refuse"
    );
}

#[test]
fn slip10_master_round_trips_and_families_do_not_cross_verify() {
    const N: usize = 4;
    // Family-1 master statement (canonical SLIP-0010 vector 1 circuit).
    let slip10 = slip10_master_circuit();
    let output = output_of(&slip10);
    let stream = gen_stream(&slip10, N, b"e", b"bind");
    assert!(
        verify(MASTER_KEY, &output, &stream, N, b"bind", 0, None, None, SLIP10_FAMILY),
        "the family-1 master statement must verify"
    );
    assert!(
        !verify(MASTER_KEY, &output, &stream, N, b"bind", 0, None, None, BIP32_FAMILY),
        "a family-1 master proof must not verify as family 0"
    );
    // And the reverse direction, from the BIP-32 side.
    let bip32 = hardened_child_circuit();
    let output = output_of(&bip32);
    let stream = gen_stream(&bip32, N, b"e", b"bind");
    assert!(
        verify(HARDENED_CHILD, &output, &stream, N, b"bind", 0, None, None, BIP32_FAMILY),
        "the family-0 hardened-child statement must verify"
    );
    assert!(
        !verify(HARDENED_CHILD, &output, &stream, N, b"bind", 0, None, None, SLIP10_FAMILY),
        "a family-0 proof must not verify as family 1"
    );
}

#[test]
fn family_1_carries_only_the_recovery_statements() {
    assert!(expected_output(MASTER_KEY, 0, SLIP10_FAMILY).is_some());
    assert!(expected_output(HARDENED_CHILD, 0, SLIP10_FAMILY).is_some());
    assert!(
        expected_output(PUBLIC_KEY, 0, SLIP10_FAMILY).is_none(),
        "family 1 must not carry the secp256k1 statements"
    );
    assert!(expected_output(MASTER_KEY, 0, 2).is_none(), "unknown family");
}
