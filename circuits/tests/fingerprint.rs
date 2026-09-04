// SPDX-License-Identifier: LGPL-3.0-or-later

//! The statement fingerprint, and the two properties anything asking a device for one
//! depends on.
//!
//! A device can be asked for this digest and its answer compared with the host's, which
//! is only meaningful if the digest is a function of the *public* parameters and not of
//! the seed. Both halves are checked here: changing a public parameter must move it (or
//! the comparison proves nothing), and changing the witness must not (or asking a device
//! for it would leak).

use proofofseed_circuits::comb::{ComputedComb, FlashComb};
use proofofseed_circuits::request::Family::{Bip32Secp256k1 as B32, Slip10Ed25519 as S10};
use proofofseed_circuits::{
    BIP39_SEED, ETH_ADDRESS, HARDENED_CHILD, HardenedChildCircuit, MASTER_KEY, NORMAL_CHILD,
    PUBLIC_KEY, statement_fingerprint,
};
use proofofseed_circuits::hasher::Keccak256Hasher;
use zkboo_circuit_hash::hash_circuit;

const H: u32 = 0x8000_0000;

fn fp(family: proofofseed_circuits::request::Family, statement: u8) -> Option<[u8; 32]> {
    statement_fingerprint::<ComputedComb>(family, statement, 2048, None, None)
}

#[test]
fn every_implemented_statement_has_one_and_nothing_else_does() {
    for s in [MASTER_KEY, HARDENED_CHILD, BIP39_SEED, PUBLIC_KEY, NORMAL_CHILD, ETH_ADDRESS] {
        assert!(fp(B32, s).is_some(), "family 0 statement {s}");
    }
    for s in [MASTER_KEY, HARDENED_CHILD] {
        assert!(fp(S10, s).is_some(), "family 1 statement {s}");
    }
    // SLIP-10 ed25519 has no non-hardened children and no curve statements.
    for s in [BIP39_SEED, PUBLIC_KEY, NORMAL_CHILD, ETH_ADDRESS] {
        assert!(fp(S10, s).is_none(), "family 1 must not claim statement {s}");
    }
    assert!(fp(B32, 6).is_none(), "unknown statement");
}

#[test]
fn the_public_parameters_move_the_fingerprint() {
    // If they did not, comparing a device's digest with the host's would be checking
    // nothing about the parameters the proof is anchored on.
    let a = statement_fingerprint::<ComputedComb>(B32, HARDENED_CHILD, 2048, Some(&[1u8; 32]), None);
    let b = statement_fingerprint::<ComputedComb>(B32, HARDENED_CHILD, 2048, Some(&[2u8; 32]), None);
    assert_ne!(a, b, "chain code");
    let c = statement_fingerprint::<ComputedComb>(
        B32,
        HARDENED_CHILD,
        2048,
        Some(&[1u8; 32]),
        Some(H | 7),
    );
    assert_ne!(a, c, "derivation index");
    let r2 = statement_fingerprint::<ComputedComb>(B32, BIP39_SEED, 2, None, None);
    let r4 = statement_fingerprint::<ComputedComb>(B32, BIP39_SEED, 4, None, None);
    assert_ne!(r2, r4, "PBKDF2 round count");
}

#[test]
fn the_witness_does_not_move_the_fingerprint() {
    // The property that makes the digest safe to ask a device for. The fingerprinting
    // backend ingests an input's type, never its value.
    let one = HardenedChildCircuit {
        chain_code: alloc_cc(9),
        parent_priv: vec![0xAA; 32],
        index: H,
    };
    let two = HardenedChildCircuit {
        chain_code: alloc_cc(9),
        parent_priv: vec![0x55; 32],
        index: H,
    };
    assert_eq!(
        hash_circuit::<_, Keccak256Hasher>(&one),
        hash_circuit::<_, Keccak256Hasher>(&two),
        "two different parent keys, same circuit structure",
    );
    // And the same digest the parameter-only entry point produces.
    assert_eq!(
        Some(hash_circuit::<_, Keccak256Hasher>(&one)),
        statement_fingerprint::<ComputedComb>(B32, HARDENED_CHILD, 2048, Some(&alloc_cc(9)), Some(H)),
        "the parameter-only fingerprint is the circuit's own",
    );
}

fn alloc_cc(b: u8) -> Vec<u8> {
    vec![b; 32]
}

#[test]
fn the_table_source_does_not_move_the_non_curve_statements() {
    // A device reading its comb tables from flash must agree with a host recomputing
    // them, for every statement — trivially so where no curve arithmetic occurs, and by
    // table parity where it does (tests/flash_tables.rs).
    for s in [MASTER_KEY, HARDENED_CHILD, BIP39_SEED] {
        assert_eq!(
            statement_fingerprint::<ComputedComb>(B32, s, 2048, None, None),
            statement_fingerprint::<FlashComb>(B32, s, 2048, None, None),
            "statement {s}",
        );
    }
}
