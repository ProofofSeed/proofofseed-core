// SPDX-License-Identifier: LGPL-3.0-or-later

//! Proof-byte neutrality: the extracted crates must reproduce, byte for byte, the
//! streams the pre-extraction ledger-app code produced (extraction acceptance,
//! `knowledge/plan.md` milestone 1). The fixture (`golden_streams.txt`) was
//! recorded from the untouched ledger-app tree at commit 86a4656; this test
//! recomputes each stream with the same parameters and compares length and
//! Keccak-256. Any mismatch means the move — or a later change — altered proof
//! bytes: the deterministic-entropy transcript, the circuit fingerprints, and
//! `DETERMINISTIC_ENTROPY_VERSION` are format commitments, not internals.

use proofofseed_circuits::ranged::{
    WitnessMaterial, deterministic_seed_entropy, ranged_request_digest,
};
use proofofseed_circuits::request::{Family, ProofRequest};
use proofofseed_circuits::{
    HARDENED_CHILD, bip39_seed_circuit, hardened_child_circuit, master_key_circuit,
    public_key_circuit, slip10_child_circuit,
};
use proofofseed_host::harness::{gen_stream, gen_stream_range};
use zkboo::circuit::Circuit;
use zkboo::crypto::Hasher;

const H: u32 = 0x8000_0000;
const BINDING: &[u8] = b"golden-fixture-binding";

fn keccak_hex(data: &[u8]) -> String {
    let mut h = zkboo::crypto::Keccak256Hasher::new();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_into(&mut out);
    out.iter().map(|b| format!("{b:02x}")).collect()
}

fn request(num_iters: usize, family: Family, range: Option<(u16, u16)>) -> ProofRequest {
    ProofRequest {
        num_iters,
        rounds: 2048,
        family,
        path: None,
        index: None,
        chain_code: None,
        binding: BINDING.to_vec(),
        range,
    }
}

fn derived_entropy<C: Circuit>(
    circuit: &C,
    statement: u8,
    family: Family,
    num_iters: usize,
) -> zeroize::Zeroizing<[u8; 32]> {
    let req = request(num_iters, family, Some((0, num_iters as u16)));
    let digest = ranged_request_digest(
        statement,
        &req,
        &[H | 44, H | 60, H | 0],
        WitnessMaterial::Child {
            parent_priv: &[1u8; 32],
            chain_code: &[2u8; 32],
            index: H,
        },
    );
    deterministic_seed_entropy(circuit, &digest)
}

#[test]
fn extracted_crates_reproduce_the_pre_extraction_streams() {
    let hc = hardened_child_circuit();
    let hc_e = derived_entropy(&hc, HARDENED_CHILD, Family::Bip32Secp256k1, 4);
    let sc = slip10_child_circuit();
    let sc_e = derived_entropy(&sc, HARDENED_CHILD, Family::Slip10Ed25519, 4);
    let pk = public_key_circuit();
    let raw = b"golden-fixture-entropy";
    let streams: [(&str, Vec<u8>); 9] = [
        ("raw/master_key/n2", gen_stream(&master_key_circuit(), 2, raw, BINDING)),
        ("raw/bip39-r2/n2", gen_stream(&bip39_seed_circuit(2), 2, raw, BINDING)),
        ("derived/hardened_child/n4/full", gen_stream(&hc, 4, &*hc_e, BINDING)),
        ("derived/hardened_child/n4/seg0-2", gen_stream_range(&hc, 4, (0, 2), &*hc_e, BINDING)),
        ("derived/hardened_child/n4/seg2-3", gen_stream_range(&hc, 4, (2, 3), &*hc_e, BINDING)),
        ("derived/hardened_child/n4/seg3-4", gen_stream_range(&hc, 4, (3, 4), &*hc_e, BINDING)),
        ("derived/slip10_child/n4/full", gen_stream(&sc, 4, &*sc_e, BINDING)),
        ("raw/public_key/n2/full", gen_stream(&pk, 2, raw, BINDING)),
        ("raw/public_key/n2/seg1-2", gen_stream_range(&pk, 2, (1, 2), raw, BINDING)),
    ];
    let fixture: std::collections::HashMap<&str, (usize, &str)> =
        include_str!("golden_streams.txt")
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| {
                let mut parts = l.split(' ');
                let name = parts.next().expect("name");
                let len: usize = parts.next().expect("length").parse().expect("valid length");
                let digest = parts.next().expect("digest");
                (name, (len, digest))
            })
            .collect();
    assert_eq!(fixture.len(), streams.len(), "fixture row count");
    // Every row is checked before anything is reported. A fixture that stops at the first
    // mismatch cannot answer the question one actually asks when it goes red — *which*
    // rows moved — and a change meant to touch one group is only shown to have done that
    // if the other group is seen not to move.
    let mut moved = Vec::new();
    for (name, stream) in streams {
        let (len, digest) = fixture[name];
        let got = keccak_hex(&stream);
        if stream.len() != len || got != digest {
            moved.push(format!("  {name}: {len} B {digest}  ->  {} B {got}", stream.len()));
        }
    }
    assert!(moved.is_empty(), "proof bytes moved in {} row(s):\n{}", moved.len(), moved.join("\n"));
}
