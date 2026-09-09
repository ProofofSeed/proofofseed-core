// SPDX-License-Identifier: LGPL-3.0-or-later

//! The two seed statements against witnesses of realistic shape, with a negative per
//! shape parameter and its positive twin.

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
            Some(salt.len()),
        ),
        "a real mnemonic must verify under its own lengths",
    );
    assert!(
        !verify(BIP39_SEED, &output, &stream, N, BINDING, 2, None, None, 0),
        "without the shape the verifier rebuilds the test-vector circuit",
    );
    assert!(
        !verify_with_shape(
            BIP39_SEED, &output, &stream, N, BINDING, 2, None, None, 0,
            Some(MNEMONIC.len()),
            Some(bip39_salt_for(b"TREZOR").len()),
        ),
        "a passphrase of a different length is a different circuit",
    );
    assert!(
        !verify_with_shape(
            BIP39_SEED, &output, &stream, N, BINDING, 2, None, None, 0,
            Some(MNEMONIC.len() - 1),
            Some(salt.len()),
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
    for (len, s) in [(Some(MNEMONIC.len()), None), (None, Some(salt.len()))] {
        assert!(
            !verify_with_shape(BIP39_SEED, &output, &stream, N, BINDING, 2, None, None, 0, len, s),
            "half a shape must be refused",
        );
    }
}


#[test]
fn the_passphrase_never_reaches_the_verifier() {
    // The property the salt was made witness for. Two provers whose passphrases differ
    // but are the same length build the *same* circuit, so a verifier — who is handed
    // only the lengths — cannot tell them apart, and is never given the passphrase to
    // begin with. When the salt was a public constant it was in the circuit, so it had
    // to be handed over for the circuit to be rebuilt at all.
    use proofofseed_circuits::hasher::Keccak256Hasher;
    use zkboo_circuit_hash::hash_circuit;

    let one = SeedCircuit {
        mnemonic: MNEMONIC.to_vec(),
        salt: bip39_salt_for(b"hunter2!"),
        rounds: 2,
    };
    let two = SeedCircuit {
        mnemonic: MNEMONIC.to_vec(),
        salt: bip39_salt_for(b"correct!"),
        rounds: 2,
    };
    assert_eq!(bip39_salt_for(b"hunter2!").len(), bip39_salt_for(b"correct!").len());
    assert_eq!(
        hash_circuit::<_, Keccak256Hasher>(&one),
        hash_circuit::<_, Keccak256Hasher>(&two),
        "same-length passphrases must be indistinguishable in the circuit",
    );

    // And the length is not hidden: that is the residual disclosure, stated rather than
    // wished away.
    let longer = SeedCircuit {
        mnemonic: MNEMONIC.to_vec(),
        salt: bip39_salt_for(b"a-much-longer-passphrase"),
        rounds: 2,
    };
    assert_ne!(
        hash_circuit::<_, Keccak256Hasher>(&one),
        hash_circuit::<_, Keccak256Hasher>(&longer),
        "a different passphrase length is a different circuit",
    );

    // Each still proves its own statement and not the other's.
    let out_one = output_of(&one);
    let stream_one = gen_stream(&one, N, b"entropy-p1", BINDING);
    let len = (MNEMONIC.len(), bip39_salt_for(b"hunter2!").len());
    assert!(verify_with_shape(
        BIP39_SEED, &out_one, &stream_one, N, BINDING, 2, None, None, 0, Some(len.0), Some(len.1),
    ));
    assert!(
        !verify_with_shape(
            BIP39_SEED, &output_of(&two), &stream_one, N, BINDING, 2, None, None, 0, Some(len.0),
            Some(len.1),
        ),
        "the proof is still bound to its own seed",
    );
}
