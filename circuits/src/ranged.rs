// SPDX-License-Identifier: LGPL-3.0-or-later

//! Ranged proving: emitting any half-open sub-range `[start, end)` of a proof's
//! response sequence, so a long proof is resumable, retriable, and can be split
//! across several devices holding the same seed.
//!
//! Two facts shape this module:
//!
//! - **The Fiat-Shamir challenge is global.** The challenge entropy hashes the
//!   commitments of *all* `num_iters` iterations (plus the binding), so a prover
//!   emitting any sub-range must still run the full challenge phase; only the
//!   response phase is restricted to the range. Skipping the responses before
//!   `start` costs one PRG step and one challenge draw each — no circuit execution.
//!
//! - **Ranges only compose under identical prover entropy.** Responses produced in
//!   different runs (or on different devices) verify as one proof only if every run
//!   derives the same per-iteration view seeds and the same challenge sequence. The
//!   prover entropy therefore cannot be drawn from a TRNG per run; it is derived
//!   deterministically — the construction Picnic uses for its per-signature seeds —
//!   as a hash of the witness secrets and the full request transcript
//!   ([request_transcript_digest]), bound to the circuit fingerprint and a
//!   transcript version ([deterministic_seed_entropy]).
//!
//! Why the derivation is safe, and what it must include: re-running the prover with
//! the same entropy and the same request re-opens exactly the same view pair of the
//! same commitment in every iteration, which reveals nothing beyond the first run.
//! The danger is the same entropy under a *different* challenge: opening two
//! different view pairs of the same seeded iteration reconstructs all three input
//! shares — the witness. The derivation therefore absorbs every input the challenge
//! depends on, so that *any* change that could move the challenge also moves the
//! entropy: the statement and family, `num_iters` (the challenge hashes that many
//! commitments), the BIP-39 rounds, the derivation path, the asserted index and
//! chain code, the binding, the witness itself — and, through
//! [deterministic_seed_entropy], the circuit's structural fingerprint (an app
//! update that changes a circuit, e.g. a gate-level optimisation, changes the
//! commitments too) and [DETERMINISTIC_ENTROPY_VERSION], to be bumped on any change
//! to the proof byte format or commitment scheme that the fingerprint cannot see.
//! The response range itself is deliberately *not* absorbed: ranges of the same
//! proof must share the entropy.
//!
//! Residual caveats, stated rather than hidden: a proof-system change that alters
//! neither the circuit structure nor this module's constants would silently
//! decorrelate the challenge from the entropy across app versions — the version
//! constant is the manual guard, and mixing app versions across runs of one ranged
//! proof is unsupported. And unlike the TRNG mode, a deterministic prover re-runs
//! identically, so a fault injected into a later run's challenge phase could in
//! principle steer reopenings; the TRNG mode therefore remains the default for
//! full-sequence proofs, and ranged mode is opt-in per request.

use crate::request::ProofRequest;
use alloc::vec::Vec;
use zeroize::{Zeroize, Zeroizing};
use zkboo::backend::{Backend, BackendHook, Hooked};
use zkboo::circuit::Circuit;
use zkboo::crypto::{
    GeneratesRandom, HashPRG, Hasher, Keccak256Hasher, PseudoRandomGenerator, Seed,
};
use zkboo::prover::challenge::{ChallengeGenerator, Party};
use zkboo::prover::proof::collectors::ResponseDataCollector;
use zkboo::prover::views::{ViewBuilderBackend, WordTriplePool, collectors::ResponseDataSelector};
use zkboo_circuit_hash::hash_circuit;

/// Version of the deterministic-entropy transcript. Bump on ANY change to the proof
/// byte format or commitment scheme that [hash_circuit] cannot observe (it
/// fingerprints circuit structure only), so proofs from different proof-system
/// versions never share prover entropy. The adoption of the ZKB++ view commitment
/// is an example of exactly such a change.
pub const DETERMINISTIC_ENTROPY_VERSION: u32 = 1;

/// Absorbs a length-prefixed byte string.
fn absorb_bytes(h: &mut Keccak256Hasher, data: &[u8]) {
    h.update(&(data.len() as u16).to_be_bytes());
    h.update(data);
}

/// The witness material of a resolved request, exactly as every prover (the
/// device app, the standalone CLI) assembles it for the entropy derivation —
/// shared so the host tests exercise the same assembly the provers run (this
/// seam is where the secret enters the derivation: an omission here would let
/// two different seeds share prover entropy, the witness-leak condition, which
/// is why it must not live in untestable app code), and so co-proving provers
/// derive identical entropy.
///
/// Shape invariant: the absorbed parts carry no variant tag, so variants are
/// disambiguated by the absorbed part count *together with the statement byte*
/// (each statement admits at most one variant per part count: master key is
/// [WitnessMaterial::TestVector] (1 part, device) or [WitnessMaterial::Seed]
/// (2, real seed); BIP-39 is TestVector (1) or [WitnessMaterial::Mnemonic] (3);
/// the child statements are [WitnessMaterial::Child] (4); the key statements are
/// [WitnessMaterial::Priv] (2)). A new variant must not create a
/// (statement, part-count) collision with an existing one.
pub enum WitnessMaterial<'a> {
    /// Statements proved on their public canonical test vector (no device secret).
    TestVector,
    /// A child statement's witness: the secret parent key, the parent chain code,
    /// and the resolved child index (post-default, wire encoding).
    Child { parent_priv: &'a [u8], chain_code: &'a [u8], index: u32 },
    /// A plain private-key witness (public-key / address statements).
    Priv { private_key: &'a [u8] },
    /// A real master-seed witness (software-wallet provers; the master-key
    /// statement against the actual 64-byte BIP-39 seed).
    Seed { seed: &'a [u8] },
    /// A real mnemonic witness (software-wallet provers; the BIP-39 statement),
    /// with its full salt (`"mnemonic" ‖ passphrase`) — the salt is part of the
    /// witness environment and must move the entropy.
    Mnemonic { mnemonic: &'a [u8], salt: &'a [u8] },
}

/// [request_transcript_digest] with the device's exact material assembly: the
/// resolved derivation path (post-default — compiled-in defaults may change
/// between app versions without the request bytes changing) followed by the
/// witness's secret and public components in [WitnessMaterial] order.
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

/// Digest of everything the request contributes to the challenge — statement,
/// family, response count, rounds, path, asserted index and chain code, binding —
/// plus the witness secrets, length-prefixed throughout. The response range is
/// deliberately excluded (see the module doc). `secrets` are the raw witness byte
/// strings exactly as the circuit will consume them; for test-vector statements
/// they are public constants and the "entropy" is merely reproducible, which is all
/// those statements need.
pub fn request_transcript_digest(
    statement: u8,
    req: &ProofRequest,
    secrets: &[&[u8]],
) -> Zeroizing<[u8; 32]> {
    let mut h = Keccak256Hasher::new();
    absorb_bytes(&mut h, b"ProofofSeed/ranged-prover-entropy/request/v1");
    h.update(&DETERMINISTIC_ENTROPY_VERSION.to_be_bytes());
    h.update(&[statement, req.family as u8]);
    h.update(&(req.num_iters as u16).to_be_bytes());
    h.update(&(req.rounds as u16).to_be_bytes());
    match &req.path {
        None => h.update(&[0]),
        Some(path) => {
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

/// The deterministic prover entropy for a ranged proof: a hash binding the request
/// transcript digest to the structural fingerprint of the circuit actually proved,
/// so a circuit change (which changes the commitments, hence the challenge) can
/// never reuse the per-iteration seeds of an earlier circuit's proof.
pub fn deterministic_seed_entropy<C: Circuit>(
    circuit: &C,
    request_digest: &Zeroizing<[u8; 32]>,
) -> Zeroizing<[u8; 32]> {
    let fingerprint: [u8; 32] = hash_circuit::<C, Keccak256Hasher>(circuit);
    let mut h = Keccak256Hasher::new();
    absorb_bytes(&mut h, b"ProofofSeed/ranged-prover-entropy/seed/v1");
    h.update(&fingerprint);
    h.update(&**request_digest);
    let mut out = Zeroizing::new([0u8; 32]);
    h.finalize_into(&mut *out);
    h.zeroize();
    out
}

/// Builds the responses `[start, end)` of the `num_iters`-response proof determined
/// by `seed_entropy` and `challenge_entropy`, streaming each response through the
/// [ResponseDataCollector]. With `start = 0, end = num_iters` the emitted bytes are
/// identical to zkboo's `build_proof_custom_hooked` (locked by a psverify test);
/// the responses before `start` are skipped by advancing the seed PRG and the
/// challenge generator without executing the circuit, exactly one draw each — the
/// iteration recipe replicated here from zkboo's `ProofBuilder`, which does not
/// (yet) expose a ranged entry point of its own.
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
    let mut seed_prg = PS::new(seed_entropy);
    let mut challenge_generator = ChallengeGenerator::new(HashPRG::<H>::new(&challenge_entropy));
    for _ in 0..start {
        let _seeds: Zeroizing<[S; 3]> = Zeroizing::new(seed_prg.next());
        let _: Party = challenge_generator.next();
    }
    let mut res_vec = Vec::with_capacity(end - start);
    for _ in start..end {
        let seeds: Zeroizing<[S; 3]> = Zeroizing::new(seed_prg.next());
        let challenge: Party = challenge_generator.next();
        let backend: ViewBuilderBackend<H, PV, S, ResponseDataSelector<H::Digest, S, RDC>, WTP> =
            ViewBuilderBackend::new_with_arg(seeds, (challenge, collector_init_arg));
        let frontend = Hooked::new(BH::new(hook_init_arg), backend).into_frontend();
        circuit.exec(&frontend);
        res_vec.push(frontend.finalize());
    }
    res_vec
}
