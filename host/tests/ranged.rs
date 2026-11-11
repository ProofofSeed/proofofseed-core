// SPDX-License-Identifier: LGPL-3.0-or-later

//! Ranged proving, off-device: byte-equality with the canonical builder, reassembly of
//! any partition, refusal of a lone range, and the entropy derivation's sensitivities.

use proofofseed_circuits::ranged::{
    WitnessMaterial, deterministic_seed_entropy, ranged_request_digest, request_transcript_digest,
};
use proofofseed_circuits::request::{Family, ProofRequest};
use proofofseed_circuits::{HARDENED_CHILD, hardened_child_circuit, master_key_circuit, public_key_circuit};
use proofofseed_host::harness::{gen_stream, gen_stream_range, output_of};
use proofofseed_host::verify;
use zeroize::Zeroizing;

/// Sixteen responses. Every refusal in this file that is not a length check is ZKBoo's
/// own soundness, accepted with probability about `3^-N`, so a small count makes a
/// negative a coin flip rather than a check.
const N: usize = 16;
/// A range long enough that a Fiat-Shamir agreement by chance, at `3^-LONG`, is not a
/// thing a test run will see.
const LONG: usize = 20;
const BINDING: &[u8] = b"ranged-recovery-tx";

/// A representative proof request for the hardened-child test-vector statement,
/// as the app would parse it (the range is set per test).
fn request(range: Option<(u16, u16)>) -> ProofRequest {
    ProofRequest {
        num_iters: N,
        rounds: 2048,
        family: Family::Bip32Secp256k1,
        path: None,
        index: None,
        chain_code: None,
        binding: BINDING.to_vec(),
        range,
    }
}

/// The deterministic prover entropy the device would derive for [request], via the
/// same shared functions.
fn entropy(secrets: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let digest = request_transcript_digest(HARDENED_CHILD, &request(Some((0, N as u16))), secrets);
    deterministic_seed_entropy(&hardened_child_circuit(), &digest)
}

#[test]
fn full_range_equals_the_canonical_builder() {
    let circuit = hardened_child_circuit();
    let entropy = entropy(&[b"witness-material"]);
    let full = gen_stream(&circuit, N, &*entropy, BINDING);
    let ranged = gen_stream_range(&circuit, N, (0, N), &*entropy, BINDING);
    assert_eq!(full, ranged, "the ranged builder over [0, n) must be byte-identical");
}

#[test]
fn a_partition_of_ranges_reassembles_the_proof_and_verifies() {
    let circuit = hardened_child_circuit();
    let output = output_of(&circuit);
    let entropy = entropy(&[b"witness-material"]);
    let full = gen_stream(&circuit, N, &*entropy, BINDING);
    // A coarse partition and the all-singletons partition, each segment produced by
    // an independent prover run (fresh challenge phase included), as separate
    // devices would.
    for partition in [vec![(0, 2), (2, 3), (3, N)], (0..N).map(|i| (i, i + 1)).collect()] {
        let assembled: Vec<u8> = partition
            .iter()
            .flat_map(|&range| gen_stream_range(&circuit, N, range, &*entropy, BINDING))
            .collect();
        assert_eq!(assembled, full, "partition {partition:?} must reassemble the proof");
    }
    assert!(
        verify(HARDENED_CHILD, &output, &full, N, BINDING, 0, None, None, 0),
        "the reassembled proof must verify in the device configuration"
    );
}

/// A lone range `[0, length)`, drawn from a `total`-response proof under `binding` and
/// offered as though it were a complete proof of its own length.
fn lone_range_passes(total: usize, length: usize, binding: &[u8]) -> bool {
    let circuit = hardened_child_circuit();
    let request = ProofRequest {
        num_iters: total,
        binding: binding.to_vec(),
        ..request(Some((0, total as u16)))
    };
    let digest = request_transcript_digest(HARDENED_CHILD, &request, &[b"witness-material"]);
    let entropy = deterministic_seed_entropy(&circuit, &digest);
    let segment = gen_stream_range(&circuit, total, (0, length), &*entropy, binding);
    verify(
        HARDENED_CHILD,
        &output_of(&circuit),
        &segment,
        length,
        binding,
        0,
        None,
        None,
        0,
    )
}

#[test]
fn a_lone_range_is_not_a_complete_proof() {
    let circuit = hardened_child_circuit();
    let output = output_of(&circuit);
    let entropy = entropy(&[b"witness-material"]);
    // Its twin — a genuine LONG-response proof — verifies at that count; the segment
    // carries the same number of responses but its challenges were derived over all
    // 2·LONG commitments, so passing it off as a complete proof must refuse.
    //
    // The range is long because the refusal is probabilistic; see the test below.
    let twin = gen_stream(&circuit, LONG, &*entropy, BINDING);
    assert!(
        verify(HARDENED_CHILD, &output, &twin, LONG, BINDING, 0, None, None, 0),
        "the {LONG}-response twin must verify"
    );
    assert!(
        !lone_range_passes(2 * LONG, LONG, BINDING),
        "a lone range must not pass as a complete proof of its own length"
    );
}

#[test]
fn a_lone_range_is_refused_at_the_protocols_own_rate_and_no_better() {
    // A lone range is not structurally distinguishable from a complete proof of its
    // own length. Nothing in the stream says which of `num_iters` commitments its
    // challenges were derived over, so the refusal is the ordinary Fiat-Shamir one: the
    // verifier re-derives `length` challenges from the commitments it was given, and an
    // unrelated digest still agrees with each of them one time in three.
    //
    // A short range is therefore accepted about `3^-length` of the time, which the test
    // above buys off by being long rather than by any property of ranged proving. This
    // is what the 2-response refusal the device once demonstrated actually showed: one
    // draw of a 1-in-9 event.
    let trials = 60u32;
    for (length, expected) in [(1usize, trials / 3), (2, trials / 9), (3, trials / 27)] {
        let passes = (0..trials)
            .filter(|t| lone_range_passes(N, length, format!("lone-range-{t}").as_bytes()))
            .count() as u32;
        // Three standard deviations of the binomial either side, floored at one trial,
        // so the band is wide enough not to flake and narrow enough to exclude both a
        // refusal that has become structural and one that has stopped happening.
        let share = 3u32.pow(length as u32);
        let sigma =
            (f64::from(trials) * f64::from(share - 1) / f64::from(share).powi(2)).sqrt();
        let slack = (3.0 * sigma).ceil() as u32 + 1;
        assert!(
            passes.abs_diff(expected) <= slack,
            "a lone range of {length} passed {passes} of {trials} times, against the \
             {expected} that 3^-{length} predicts (slack {slack})"
        );
    }
}

#[test]
fn a_range_from_a_different_binding_breaks_the_assembled_proof() {
    let circuit = hardened_child_circuit();
    let output = output_of(&circuit);
    // Each run derives its entropy from its own request, as the device would — the
    // foreign segment differs in binding only.
    let digest_a = request_transcript_digest(HARDENED_CHILD, &request(Some((0, N as u16))), &[]);
    let entropy_a = deterministic_seed_entropy(&circuit, &digest_a);
    let mut foreign_request = request(Some((2, 3)));
    foreign_request.binding = b"some-other-tx".to_vec();
    let digest_b = request_transcript_digest(HARDENED_CHILD, &foreign_request, &[]);
    let entropy_b = deterministic_seed_entropy(&circuit, &digest_b);
    let assembled: Vec<u8> = [
        gen_stream_range(&circuit, N, (0, 2), &*entropy_a, BINDING),
        gen_stream_range(&circuit, N, (2, 3), &*entropy_b, b"some-other-tx"),
        gen_stream_range(&circuit, N, (3, N), &*entropy_a, BINDING),
    ]
    .concat();
    let genuine: Vec<u8> = [
        gen_stream_range(&circuit, N, (0, 2), &*entropy_a, BINDING),
        gen_stream_range(&circuit, N, (2, 3), &*entropy_a, BINDING),
        gen_stream_range(&circuit, N, (3, N), &*entropy_a, BINDING),
    ]
    .concat();
    assert!(
        verify(HARDENED_CHILD, &output, &genuine, N, BINDING, 0, None, None, 0),
        "the all-same-binding assembly must verify"
    );
    assert!(
        !verify(HARDENED_CHILD, &output, &assembled, N, BINDING, 0, None, None, 0),
        "an assembly containing a foreign-binding range must refuse"
    );
}

#[test]
fn deterministic_entropy_is_stable_and_input_sensitive() {
    let secrets: &[&[u8]] = &[b"parent-priv", b"chain-code"];
    let base = request_transcript_digest(HARDENED_CHILD, &request(Some((0, N as u16))), secrets);
    let again = request_transcript_digest(HARDENED_CHILD, &request(Some((0, N as u16))), secrets);
    assert_eq!(*base, *again, "the digest must be reproducible across runs");
    // Blind to the range: ranges of one proof must share their entropy.
    let other_range = request_transcript_digest(HARDENED_CHILD, &request(Some((2, 3))), secrets);
    assert_eq!(*base, *other_range, "the digest must not absorb the range");
    // Sensitive to every challenge-relevant input.
    let variants: [(&str, ProofRequest); 6] = [
        ("num_iters", ProofRequest { num_iters: N + 1, ..request(None) }),
        ("rounds", ProofRequest { rounds: 4, ..request(None) }),
        ("family", ProofRequest { family: Family::Slip10Ed25519, ..request(None) }),
        ("path", ProofRequest { path: Some(vec![44]), ..request(None) }),
        (
            "index+chain code",
            ProofRequest { index: Some(7), chain_code: Some([9u8; 32]), ..request(None) },
        ),
        ("binding", ProofRequest { binding: b"other".to_vec(), ..request(None) }),
    ];
    for (what, req) in variants {
        let varied = request_transcript_digest(HARDENED_CHILD, &req, secrets);
        assert_ne!(*base, *varied, "a change of {what} must change the digest");
    }
    let other_statement = request_transcript_digest(0, &request(Some((0, N as u16))), secrets);
    assert_ne!(*base, *other_statement, "a change of statement must change the digest");
    let other_secrets =
        request_transcript_digest(HARDENED_CHILD, &request(Some((0, N as u16))), &[b"parent-priv"]);
    assert_ne!(*base, *other_secrets, "a change of witness material must change the digest");
    // And the final entropy binds the circuit: the same digest over two different
    // circuits must never share prover seeds (an app update that changes a circuit
    // changes the commitments, hence the challenge).
    let child = deterministic_seed_entropy(&hardened_child_circuit(), &base);
    let master = deterministic_seed_entropy(&master_key_circuit(), &base);
    assert_ne!(*child, *master, "the entropy must bind the circuit fingerprint");
}

#[test]
fn a_longer_stream_does_not_verify_under_a_smaller_count() {
    // The soundness-downgrade guard: a proof of N responses must not verify when
    // checked as fewer — else a relayer downgrades a 438-proof by claiming a
    // smaller count and leaving the tail unread. Verified via the trailing-byte
    // rejection in verify_stream.
    let circuit = hardened_child_circuit();
    let output = output_of(&circuit);
    let entropy = entropy(&[b"witness-material"]);
    let full = gen_stream(&circuit, N, &*entropy, BINDING);
    assert!(
        verify(HARDENED_CHILD, &output, &full, N, BINDING, 0, None, None, 0),
        "the full N-response proof verifies at N"
    );
    for smaller in 1..N {
        assert!(
            !verify(HARDENED_CHILD, &output, &full, smaller, BINDING, 0, None, None, 0),
            "the N-response proof must not verify as {smaller} responses"
        );
    }
    // Appended trailing bytes are rejected too.
    let mut trailed = full.clone();
    trailed.push(0);
    assert!(
        !verify(HARDENED_CHILD, &output, &trailed, N, BINDING, 0, None, None, 0),
        "a proof with trailing bytes must not verify"
    );
}

#[test]
fn witness_material_shapes_never_collide_across_prover_configurations() {
    // The (statement, absorbed-part-count) disambiguation invariant, checked
    // exhaustively over every (statement, material variant) a real prover uses:
    // the device's test-vector shapes and the CLI's real-witness shapes. All
    // digests must be pairwise distinct, so no two configurations can share
    // prover entropy while producing different challenges.
    use proofofseed_circuits::{BIP39_SEED, ETH_ADDRESS, MASTER_KEY, NORMAL_CHILD, PUBLIC_KEY};
    const HARD: u32 = 0x8000_0000;
    let req = request(Some((0, N as u16)));
    let path: &[u32] = &[HARD | 44, HARD];
    let sk = &[7u8; 32];
    let cc = &[8u8; 32];
    let digests = [
        ("master/testvector", ranged_request_digest(MASTER_KEY, &req, &[], WitnessMaterial::TestVector)),
        ("master/seed", ranged_request_digest(MASTER_KEY, &req, &[], WitnessMaterial::Seed { seed: &[9u8; 64] })),
        ("bip39/testvector", ranged_request_digest(BIP39_SEED, &req, &[], WitnessMaterial::TestVector)),
        ("bip39/mnemonic", ranged_request_digest(BIP39_SEED, &req, &[], WitnessMaterial::Mnemonic { mnemonic: b"m", salt: b"mnemonic" })),
        ("hardened/child", ranged_request_digest(HARDENED_CHILD, &req, path, WitnessMaterial::Child { parent_priv: sk, chain_code: cc, index: HARD })),
        ("normal/child", ranged_request_digest(NORMAL_CHILD, &req, path, WitnessMaterial::Child { parent_priv: sk, chain_code: cc, index: 0 })),
        ("pubkey/priv", ranged_request_digest(PUBLIC_KEY, &req, path, WitnessMaterial::Priv { private_key: sk })),
        ("address/priv", ranged_request_digest(ETH_ADDRESS, &req, path, WitnessMaterial::Priv { private_key: sk })),
    ];
    for (i, (name_i, di)) in digests.iter().enumerate() {
        for (name_j, dj) in &digests[i + 1..] {
            assert_ne!(**di, **dj, "digest collision between {name_i} and {name_j}");
        }
    }
}

#[test]
fn witness_material_assembly_is_sensitive_to_every_component() {
    // The device assembles its witness material through the same shared function
    // (`ranged_request_digest`) exercised here — the seam where the secret enters
    // the derivation. Every component of every witness shape must move the digest:
    // an omission would let two different device seeds share prover entropy, which
    // is the witness-leak condition.
    let req = request(Some((0, N as u16)));
    let path: &[u32] = &[0x8000_002c, 0x8000_003c, 0x8000_0000];
    let child = |parent_priv: &[u8], chain_code: &[u8], index: u32| {
        ranged_request_digest(
            HARDENED_CHILD,
            &req,
            path,
            WitnessMaterial::Child { parent_priv, chain_code, index },
        )
    };
    let base = child(&[1u8; 32], &[2u8; 32], 0x8000_0000);
    assert_eq!(*base, *child(&[1u8; 32], &[2u8; 32], 0x8000_0000), "reproducible");
    assert_ne!(*base, *child(&[9u8; 32], &[2u8; 32], 0x8000_0000), "parent key must move it");
    assert_ne!(*base, *child(&[1u8; 32], &[9u8; 32], 0x8000_0000), "chain code must move it");
    assert_ne!(*base, *child(&[1u8; 32], &[2u8; 32], 0x8000_0001), "child index must move it");
    let other_path = ranged_request_digest(
        HARDENED_CHILD,
        &req,
        &[0x8000_002c],
        WitnessMaterial::Child {
            parent_priv: &[1u8; 32],
            chain_code: &[2u8; 32],
            index: 0x8000_0000,
        },
    );
    assert_ne!(*base, *other_path, "the resolved path must move it");
    let privkey = ranged_request_digest(
        HARDENED_CHILD,
        &req,
        path,
        WitnessMaterial::Priv { private_key: &[1u8; 32] },
    );
    let other_privkey = ranged_request_digest(
        HARDENED_CHILD,
        &req,
        path,
        WitnessMaterial::Priv { private_key: &[9u8; 32] },
    );
    assert_ne!(*privkey, *other_privkey, "the private key must move it");
    let vector = ranged_request_digest(HARDENED_CHILD, &req, path, WitnessMaterial::TestVector);
    assert_ne!(*base, *vector, "witness shapes must not collide");
    assert_ne!(*privkey, *vector, "witness shapes must not collide");
}

#[test]
fn full_range_equals_the_canonical_builder_on_an_elephant() {
    // The byte-equality lock on the ranged builder, pinned on the secp256k1
    // public-key statement too (a very different circuit shape from the hash
    // statements — wide words, curve arithmetic, comb tables), including one
    // skipped response.
    let circuit = public_key_circuit();
    let entropy = entropy(&[b"witness-material"]);
    let full = gen_stream(&circuit, 2, &*entropy, BINDING);
    let assembled: Vec<u8> = [
        gen_stream_range(&circuit, 2, (0, 1), &*entropy, BINDING),
        gen_stream_range(&circuit, 2, (1, 2), &*entropy, BINDING),
    ]
    .concat();
    assert_eq!(assembled, full, "the elephant partition must reassemble the proof");
}
