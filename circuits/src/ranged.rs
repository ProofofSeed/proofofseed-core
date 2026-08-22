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
//!   The skipping itself is zkboo's (`ProofBuilder::skip_iters`); this module only
//!   supplies the request-keyed entropy the ranges must share.
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
//! shares — the witness. The derivation therefore absorbs the inputs the challenge
//! depends on, so that a change that could move the challenge also moves the
//! entropy: the statement and family, `num_iters` (the challenge hashes that many
//! commitments), the BIP-39 rounds, the derivation path, the asserted index and
//! chain code, the binding, the witness itself — and, through
//! [deterministic_seed_entropy], the circuit's structural fingerprint (an app
//! update that changes a circuit, e.g. a gate-level optimisation, changes the
//! commitments too), [zkboo::PROOF_FORMAT_VERSION] (a change to the emitted response
//! bytes or the commitment preimages is invisible to a circuit fingerprint but moves
//! every commitment, hence the challenge) and [DETERMINISTIC_ENTROPY_VERSION] (this
//! transcript's own layout). The response range itself is deliberately *not*
//! absorbed: ranges of the same proof must share the entropy.
//!
//! **The invariant this rests on**, which the absorbed material cannot enforce by
//! itself: *no secret may reach the circuit through `Frontend::input` without also
//! appearing in the [WitnessMaterial] handed to [request_transcript_digest].* The
//! circuit fingerprint cannot substitute for it — `zkboo-circuit-hash` ingests the
//! *type* of each input, never its value — so two circuits differing only in a
//! compiled-in witness value fingerprint identically and, if that value is not
//! absorbed here, derive identical entropy under different commitments. That is the
//! leak condition. It is why [WitnessMaterial::TestVector] absorbs no secret and is
//! sound only because its witnesses are public constants compiled into the binary:
//! change one to another value of the same length and the guarantee is gone with no
//! visible signal. A new statement, or a new witness source for an existing one,
//! must extend [WitnessMaterial] rather than rely on the fingerprint.
//!
//! Residual caveats, stated rather than hidden: mixing app versions across the runs
//! of one ranged proof is unsupported, and a change to this transcript's own layout
//! still relies on [DETERMINISTIC_ENTROPY_VERSION] being bumped by hand — only the
//! proof format is now tracked mechanically. And unlike the TRNG mode, a
//! deterministic prover re-runs
//! identically, so a fault injected into a later run's challenge phase could in
//! principle steer reopenings; the TRNG mode therefore remains the default for
//! full-sequence proofs, and ranged mode is opt-in per request.

use crate::request::ProofRequest;
use alloc::vec::Vec;
use zeroize::{Zeroize, Zeroizing};
use zkboo::backend::{Backend, BackendHook, Hooked, NoHook};
use zkboo::circuit::Circuit;
use zkboo::crypto::{
    Hasher, Keccak256Hasher, PseudoRandomGenerator, Seed,
};
use zkboo::prover::proof::ProofBuilder;
use zkboo::prover::proof::collectors::ResponseDataCollector;
use zkboo::prover::views::WordTriplePool;
use zkboo_circuit_hash::CircuitHashingBackend;

/// Version of *this module's* entropy transcript — the field layout that
/// [request_transcript_digest] absorbs. Bump on any change to what the transcript
/// absorbs, or to how, so that two app versions deriving entropy differently can
/// never collide.
///
/// This no longer has to track the proof *format*: the transcript absorbs
/// [zkboo::PROOF_FORMAT_VERSION] directly, so a change to the emitted response bytes
/// or the commitment preimages moves the entropy mechanically, whether or not anyone
/// remembers to touch this constant. That coupling is what the format constant exists
/// for, and hand-tracking it here was the previous arrangement (version `1`).
pub const DETERMINISTIC_ENTROPY_VERSION: u32 = 2;

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
    // These fields are absorbed narrowed, so a value that does not survive the
    // narrowing must not reach the hasher: `num_iters` in particular does not change
    // the circuit fingerprint, so two counts sharing a low 16 bits would derive the
    // same entropy while phase 1 hashed a different number of commitments — a
    // different challenge over the same seeds, which is the witness-leak condition.
    // Every caller in this workspace bounds these already; this function is public,
    // and a third-party prover reusing it must not be able to walk into that.
    assert!(req.num_iters <= u16::MAX as usize, "num_iters must fit the transcript");
    assert!(req.rounds <= u16::MAX as usize, "rounds must fit the transcript");
    let mut h = Keccak256Hasher::new();
    absorb_bytes(&mut h, b"ProofofSeed/ranged-prover-entropy/request/v1");
    h.update(&DETERMINISTIC_ENTROPY_VERSION.to_be_bytes());
    h.update(&zkboo::PROOF_FORMAT_VERSION.to_be_bytes());
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

/// The deterministic prover entropy for a ranged proof: a hash binding the request
/// transcript digest to the structural fingerprint of the circuit actually proved,
/// so a circuit change (which changes the commitments, hence the challenge) can
/// never reuse the per-iteration seeds of an earlier circuit's proof.
pub fn deterministic_seed_entropy<C: Circuit>(
    circuit: &C,
    request_digest: &Zeroizing<[u8; 32]>,
) -> Zeroizing<[u8; 32]> {
    return deterministic_seed_entropy_hooked::<C, NoHook>(circuit, request_digest, ());
}

/// [deterministic_seed_entropy] with a [BackendHook] wrapping the fingerprinting pass.
///
/// The pass is a full execution of the circuit through a hashing backend, and it is
/// *silent*: it emits no proof bytes and, unhooked, hands control back to nobody until
/// it finishes. On a secure element that is not merely slow, it is fatal — the OS
/// watchdog reboots the device out from under a command that stops answering, and this
/// pass runs before the prover has emitted its first byte. Its cost is linear in the
/// gate count, so the round count of a PBKDF2 circuit scales it without bound while
/// leaving its memory flat: a BIP-39 circuit at 2048 rounds fingerprints in 553x the
/// time of one at 2 rounds and 221x that of a single-HMAC circuit, on the same heap.
///
/// A caller that can yield must therefore hook this pass rather than the prover alone.
/// The hook is transcript-neutral — it observes backend operations and never touches
/// the hasher — so the digest, and hence the derived entropy, is identical to the
/// unhooked path; `tests/hooked_fingerprint.rs` pins that and that the hook fires.
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

/// The structural fingerprint of `circuit`, computed with a [BackendHook] wrapping the
/// hashing backend so a constrained caller can service its watchdog through the pass.
///
/// Identical in output to `zkboo_circuit_hash::hash_circuit` — the hook only observes.
pub fn circuit_fingerprint_hooked<C: Circuit, BH: BackendHook>(
    circuit: &C,
    hook_init_arg: BH::InitArg,
) -> [u8; 32] {
    let backend = Hooked::new(BH::new(hook_init_arg), CircuitHashingBackend::<Keccak256Hasher>::new());
    let mut frontend = backend.into_frontend();
    circuit.exec(&mut frontend);
    return frontend.finalize();
}

/// Builds the responses `[start, end)` of the `num_iters`-response proof determined
/// by `seed_entropy` and `challenge_entropy`, streaming each response through the
/// [ResponseDataCollector].
///
/// A thin wrapper over zkboo's own [ProofBuilder]: the responses outside the range
/// are skipped with [ProofBuilder::skip_iters], which advances the seed and challenge
/// streams past an iteration without executing the circuit. With
/// `start = 0, end = num_iters` the emitted bytes are identical to
/// `build_proof_custom_hooked` (locked by a psverify test).
///
/// Skipping the tail and finalizing is not ceremony: [ProofBuilder::finalize] checks
/// that every iteration was either yielded or skipped, so a range that does not add
/// up fails here rather than producing a proof that silently will not verify.
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
    let mut builder = ProofBuilder::<H, PS, PV, S, RDC, WTP, BH>::new_with_arg_hooked(
        seed_entropy,
        challenge_entropy,
        num_iters,
        collector_init_arg,
        hook_init_arg,
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
