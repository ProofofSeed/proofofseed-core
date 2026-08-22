// SPDX-License-Identifier: LGPL-3.0-or-later

//! The two seed statements, against witnesses of realistic shape.
//!
//! Both allocate one circuit input per witness byte, so the witness *length* is a
//! public parameter: a proof over a 64-byte BIP-39 seed and one over the 16-byte BIP-32
//! test vector are structurally different circuits. A verifier told neither rebuilds the
//! test-vector circuit and rejects the proof.
//!
//! That is not hypothetical. Until these tests existed, the verifier had no way to be
//! told, so it always rebuilt the test-vector circuit: the standalone prover would
//! happily produce a master-key or BIP-39 proof of a real seed that **could never
//! verify**, and nothing said so. The negatives below are what keep that from returning
//! — each is paired with the positive that shows the difference is the shape and not
//! some unrelated breakage.
//!
//! ⚠️ The BIP-39 salt (`"mnemonic" ‖ passphrase`) is likewise public, so proving that
//! statement under a passphrase discloses the passphrase to the verifier. The
//! wrong-salt negative below is what makes that concrete.

use proofofseed_circuits::{
    BIP39_SEED, MASTER_KEY, MasterKeyCircuit, SeedCircuit, Slip10MasterCircuit, bip39_salt_for,
};
use proofofseed_host::harness::{gen_stream, output_of};
use proofofseed_host::{verify, verify_with_shape};

const BINDING: &[u8] = b"seed-statement-binding";
const N: usize = 2;

/// A realistic BIP-39 seed: 64 bytes, as PBKDF2-HMAC-SHA512 produces.
fn real_seed() -> Vec<u8> {
    (0..64u8).map(|i| i.wrapping_mul(7).wrapping_add(11)).collect()
}

const MNEMONIC: &[u8] =
    b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn a_master_key_proof_of_a_real_seed_verifies_when_the_shape_is_given() {
    let circuit = MasterKeyCircuit { seed: real_seed() };
    let output = output_of(&circuit);
    let stream = gen_stream(&circuit, N, b"entropy-mk", BINDING);

    assert!(
        verify_with_shape(
            MASTER_KEY, &output, &stream, N, BINDING, 2048, None, None, 0,
            Some(real_seed().len()),
            None,
        ),
        "a 64-byte seed proof must verify when the verifier is told the length",
    );
    // The bug this test exists for: without the length the verifier rebuilds the
    // 16-byte test-vector circuit, and no real proof can ever verify.
    assert!(
        !verify(MASTER_KEY, &output, &stream, N, BINDING, 2048, None, None, 0),
        "without the length the verifier must not accept it (it rebuilds another circuit)",
    );
    // And a wrong length is not merely unhelpful, it is refused.
    assert!(
        !verify_with_shape(
            MASTER_KEY, &output, &stream, N, BINDING, 2048, None, None, 0, Some(32), None,
        ),
        "a wrong witness length must not verify",
    );
}

#[test]
fn a_slip10_master_proof_of_a_real_seed_verifies_when_the_shape_is_given() {
    let circuit = Slip10MasterCircuit { seed: real_seed() };
    let output = output_of(&circuit);
    let stream = gen_stream(&circuit, N, b"entropy-s10", BINDING);
    assert!(
        verify_with_shape(
            MASTER_KEY, &output, &stream, N, BINDING, 2048, None, None, 1,
            Some(real_seed().len()),
            None,
        ),
        "family 1, 64-byte seed",
    );
    assert!(
        !verify(MASTER_KEY, &output, &stream, N, BINDING, 2048, None, None, 1),
        "without the length, family 1 must not accept it either",
    );
}

#[test]
fn a_bip39_proof_of_a_real_mnemonic_verifies_when_the_shape_and_salt_are_given() {
    let salt = bip39_salt_for(b"");
    let circuit = SeedCircuit { mnemonic: MNEMONIC.to_vec(), salt: salt.clone(), rounds: 2 };
    let output = output_of(&circuit);
    let stream = gen_stream(&circuit, N, b"entropy-b39", BINDING);

    assert!(
        verify_with_shape(
            BIP39_SEED, &output, &stream, N, BINDING, 2, None, None, 0,
            Some(MNEMONIC.len()),
            Some(&salt),
        ),
        "a real mnemonic must verify under its own length and salt",
    );
    assert!(
        !verify(BIP39_SEED, &output, &stream, N, BINDING, 2, None, None, 0),
        "without the shape the verifier rebuilds the test-vector circuit",
    );
    assert!(
        !verify_with_shape(
            BIP39_SEED, &output, &stream, N, BINDING, 2, None, None, 0,
            Some(MNEMONIC.len()),
            Some(&bip39_salt_for(b"TREZOR")),
        ),
        "a different passphrase is a different circuit — which is why the salt is public",
    );
    assert!(
        !verify_with_shape(
            BIP39_SEED, &output, &stream, N, BINDING, 2, None, None, 0,
            Some(MNEMONIC.len() - 1),
            Some(&salt),
        ),
        "a wrong mnemonic length must not verify",
    );
}

#[test]
fn half_a_bip39_shape_is_refused_rather_than_guessed() {
    // Both parts are public parameters and neither has a default that is safe to
    // assume, so being given one without the other must fail rather than silently
    // reach for the test vector's.
    let salt = bip39_salt_for(b"");
    let circuit = SeedCircuit { mnemonic: MNEMONIC.to_vec(), salt: salt.clone(), rounds: 2 };
    let output = output_of(&circuit);
    let stream = gen_stream(&circuit, N, b"entropy-b39b", BINDING);
    for (len, s) in [(Some(MNEMONIC.len()), None), (None, Some(&salt[..]))] {
        assert!(
            !verify_with_shape(BIP39_SEED, &output, &stream, N, BINDING, 2, None, None, 0, len, s),
            "half a shape must be refused",
        );
    }
}
