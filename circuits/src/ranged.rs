// SPDX-License-Identifier: LGPL-3.0-or-later

//! Ranged proving: emitting any half-open sub-range of a proof's response sequence,
//! and the deterministic prover entropy the ranges of one proof must share.
//!
//! 🚨 The derivation absorbs everything the challenge depends on, and rests on an
//! invariant it cannot enforce by itself: no secret may reach a circuit through
//! `Frontend::input` without also appearing in the [WitnessMaterial] handed to
//! [request_transcript_digest]. See `knowledge/ranged-entropy.md`.

use crate::request::ProofRequest;
use alloc::vec::Vec;
use zeroize::{Zeroize, Zeroizing};
use zkboo::backend::{Backend, BackendHook, Hooked, NoHook};
use zkboo::circuit::Circuit;
use crate::hasher::Keccak256Hasher;
use zkboo::crypto::{Hasher, PseudoRandomGenerator, Seed, TAG_CHALLENGE, TAG_PRG, TAG_VIEW_COMMITMENT};
use zkboo::prover::proof::collectors::ResponseDataCollector;
use zkboo::prover::proof::{ProofBuilder, ProofOptions};
use zkboo::prover::views::WordTriplePool;
use zkboo_circuit_hash::CircuitHashingBackend;

/// The version of this module's entropy transcript, bumped by hand on any change to
/// what [request_transcript_digest] absorbs or to how.
pub const DETERMINISTIC_ENTROPY_VERSION: u32 = 4;

/// Absorbs a length-prefixed byte string.
fn absorb_bytes(h: &mut Keccak256Hasher, data: &[u8]) {
    h.update(&(data.len() as u16).to_be_bytes());
    h.update(data);
}

/// The witness material of a resolved request, as every prover assembles it for the
/// entropy derivation.
///
/// 🚨 Variants are disambiguated by absorbed part count together with the statement
/// byte, so a new one must not collide with an existing pair; see
/// `knowledge/ranged-entropy.md`.
pub enum WitnessMaterial<'a> {
    /// Statements proved on their public canonical test vector.
    TestVector,
    /// A child statement's witness: parent key, parent chain code and resolved index.
    Child { parent_priv: &'a [u8], chain_code: &'a [u8], index: u32 },
    /// A plain private-key witness.
    Priv { private_key: &'a [u8] },
    /// A real master-seed witness.
    Seed { seed: &'a [u8] },
    /// A real mnemonic witness, with its full salt.
    Mnemonic { mnemonic: &'a [u8], salt: &'a [u8] },
}

/// [request_transcript_digest] over the resolved path and the components of a
/// [WitnessMaterial], in variant order.
pub fn ranged_request_digest(
    statement: u8,
    req: &ProofRequest,
    resolved_path: &[u32],
    material: WitnessMaterial,
) -> Zeroizing<[u8; 32]> {
    let path_bytes: Vec<u8> = resolved_path.iter().flat_map(|c| c.to_be_bytes()).collect();
    let index_bytes;
    let parts: Vec<&[u8]> = match material {
        WitnessMaterial::TestVector => alloc::vec![&path_bytes],
        WitnessMaterial::Child { parent_priv, chain_code, index } => {
            index_bytes = index.to_be_bytes();
            alloc::vec![&path_bytes, parent_priv, chain_code, &index_bytes]
        }
        WitnessMaterial::Priv { private_key } => alloc::vec![&path_bytes, private_key],
        WitnessMaterial::Seed { seed } => alloc::vec![&path_bytes, seed],
        WitnessMaterial::Mnemonic { mnemonic, salt } => {
            alloc::vec![&path_bytes, mnemonic, salt]
        }
    };
    request_transcript_digest(statement, req, &parts)
}

/// Digest of everything the request contributes to the challenge, plus the witness
/// secrets, length-prefixed throughout and excluding the response range.
pub fn request_transcript_digest(
    statement: u8,
    req: &ProofRequest,
    secrets: &[&[u8]],
) -> Zeroizing<[u8; 32]> {
    // 🚨 Absorbed narrowed, so a value that does not survive the narrowing must not
    // reach the hasher: see knowledge/ranged-entropy.md.
    assert!(req.num_iters <= u16::MAX as usize, "num_iters must fit the transcript");
    assert!(req.rounds <= u16::MAX as usize, "rounds must fit the transcript");
    let mut h = Keccak256Hasher::new();
    absorb_bytes(&mut h, b"ProofofSeed/ranged-prover-entropy/request/v1");
    h.update(&DETERMINISTIC_ENTROPY_VERSION.to_be_bytes());
    h.update(&zkboo::PROOF_FORMAT_ID);
    // Length-prefixed and in a fixed order, so no two tags can be read as one.
    absorb_bytes(&mut h, TAG_CHALLENGE);
    absorb_bytes(&mut h, TAG_VIEW_COMMITMENT);
    absorb_bytes(&mut h, TAG_PRG);
    h.update(&[statement, req.family as u8]);
    h.update(&(req.num_iters as u16).to_be_bytes());
    h.update(&(req.rounds as u16).to_be_bytes());
    match &req.path {
        None => h.update(&[0]),
        Some(path) => {
            assert!(path.len() <= u8::MAX as usize, "path depth must fit the transcript");
            h.update(&[1, path.len() as u8]);
            for component in path {
                h.update(&component.to_be_bytes());
            }
        }
    }
    match req.index {
        None => h.update(&[0]),
        Some(index) => {
            h.update(&[1]);
            h.update(&index.to_be_bytes());
        }
    }
    match &req.chain_code {
        None => h.update(&[0]),
        Some(cc) => {
            h.update(&[1]);
            h.update(cc);
        }
    }
    absorb_bytes(&mut h, &req.binding);
    h.update(&[secrets.len() as u8]);
    for secret in secrets {
        absorb_bytes(&mut h, secret);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    h.finalize_into(&mut *out);
    h.zeroize();
    out
}

/// The deterministic prover entropy for a ranged proof, binding the request transcript
/// digest to the structural fingerprint of the circuit actually proved.
pub fn deterministic_seed_entropy<C: Circuit>(
    circuit: &C,
    request_digest: &Zeroizing<[u8; 32]>,
) -> Zeroizing<[u8; 32]> {
    return deterministic_seed_entropy_hooked::<C, NoHook>(circuit, request_digest, ());
}

/// [deterministic_seed_entropy] with a [BackendHook] wrapping the fingerprinting pass.
///
/// ⚠️ The pass services no io, so a caller on a device with a watchdog must use this
/// form; see `knowledge/circuit-fingerprints.md`.
pub fn deterministic_seed_entropy_hooked<C: Circuit, BH: BackendHook>(
    circuit: &C,
    request_digest: &Zeroizing<[u8; 32]>,
    hook_init_arg: BH::InitArg,
) -> Zeroizing<[u8; 32]> {
    let fingerprint: [u8; 32] = circuit_fingerprint_hooked::<C, BH>(circuit, hook_init_arg);
    let mut h = Keccak256Hasher::new();
    absorb_bytes(&mut h, b"ProofofSeed/ranged-prover-entropy/seed/v1");
    h.update(&fingerprint);
    h.update(&**request_digest);
    let mut out = Zeroizing::new([0u8; 32]);
    h.finalize_into(&mut *out);
    h.zeroize();
    out
}

/// The structural fingerprint of a circuit, computed with a [BackendHook] wrapping the
/// hashing backend.
pub fn circuit_fingerprint_hooked<C: Circuit, BH: BackendHook>(
    circuit: &C,
    hook_init_arg: BH::InitArg,
) -> [u8; 32] {
    let backend = Hooked::new(BH::new(hook_init_arg), CircuitHashingBackend::<Keccak256Hasher>::new());
    let mut frontend = backend.into_frontend();
    circuit.exec(&mut frontend);
    return frontend.finalize();
}

/// Builds the responses of a half-open range of a proof, streaming each through the
/// [ResponseDataCollector].
pub fn build_ranged_proof_hooked<C, H, PS, PV, S, RDC, WTP, BH>(
    circuit: &C,
    seed_entropy: &[u8],
    challenge_entropy: Zeroizing<Vec<u8>>,
    num_iters: usize,
    (start, end): (usize, usize),
    collector_init_arg: RDC::InitArg,
    hook_init_arg: BH::InitArg,
) -> Vec<RDC::FinalizeRes>
where
    C: Circuit,
    H: Hasher,
    PS: PseudoRandomGenerator,
    PV: PseudoRandomGenerator,
    S: Seed,
    RDC: ResponseDataCollector<H::Digest, S, InitArg: Copy>,
    WTP: WordTriplePool,
    BH: BackendHook<InitArg: Copy>,
{
    assert!(
        start <= end && end <= num_iters,
        "response range [{start}, {end}) out of bounds for {num_iters} responses"
    );
    let options = ProofOptions::new()
        .with_collector_arg::<RDC>(collector_init_arg)
        .with_hook_arg::<BH>(hook_init_arg);
    let mut builder = ProofBuilder::<H, PS, PV, S, RDC, WTP, BH>::new(
        seed_entropy,
        challenge_entropy,
        num_iters,
        options,
    );
    builder.skip_iters(start);
    let mut res_vec = Vec::with_capacity(end - start);
    for _ in start..end {
        let iter = builder.next_iter().expect("an iteration within the range remains");
        circuit.exec(iter.view_builder());
        res_vec.push(iter.finalize());
    }
    builder.skip_remaining_iters();
    builder.finalize();
    res_vec
}
