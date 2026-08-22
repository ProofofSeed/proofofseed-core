// SPDX-License-Identifier: LGPL-3.0-or-later

//! Host-side streaming verifier for ProofofSeed Ledger proofs.
//!
//! The device streams a ZKBoo proof as a flat byte sequence (see the app's
//! `stream.rs`): per response `challenge(1) || seed_challenge(32) || seed_next(32)`,
//! then the AND-message and party-2 input-share words (little-endian) in circuit
//! order, then the unopened commitment digest (32). This crate replays the circuit
//! against that stream via a [ReplaySource] reading a byte cursor — mirroring
//! `zkboo-harness`'s streaming pipe, but with the channel replaced by the bytes the
//! host pulled over APDU — and checks the Fiat-Shamir challenges.
//!
//! The verifier never sees the witness: the replayer ignores the value passed to
//! `frontend.input`, so a circuit built with a dummy witness of the correct length
//! suffices. The public statement output (e.g. the BIP-32 master key/chain code) is
//! supplied by the caller.

pub mod statement;

use proofofseed_circuits::request::Family;
use proofofseed_circuits::{
    BIP39_SEED, ETH_ADDRESS, HARDENED_CHILD, MASTER_KEY, NORMAL_CHILD, PUBLIC_KEY,
    bip39_seed_circuit, ethereum_address_circuit, ethereum_address_verify_circuit,
    hardened_child_circuit, hardened_child_verify_circuit, master_key_circuit, normal_child_circuit,
    normal_child_verify_circuit, public_key_circuit, public_key_verify_circuit,
    bip39_seed_verify_circuit, master_key_verify_circuit, slip10_child_circuit,
    slip10_child_verify_circuit, slip10_master_circuit, slip10_master_verify_circuit,
};
use zkboo::circuit::Circuit;
use zkboo::crypto::{GeneratesRandom, HashPRG, Hasher, Keccak256Hasher, PseudoRandomGenerator};
use zkboo::prover::challenge::{ChallengeGenerator, Party, PartyVec};
use zkboo::verifier::replay::{
    OwnedFlexibleWordPairPool, ReplaySource, ViewReplayError, ViewReplayerBackend,
};
use zkboo::word::{CompositeWord, Word, Words};

// Fixed crypto choices — must match the device prover.
type H = Keccak256Hasher;
type PV = HashPRG<H>;
type S = [u8; 32];
type RC = usize; // host verifier: no memory pressure, no overflow worry
type WPP = OwnedFlexibleWordPairPool<RC>;

// ---------------------------------------------------------------------------
// Byte-cursor replay source.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Cursor<'d> {
    data: &'d [u8],
    pos: usize,
}

impl<'d> Cursor<'d> {
    fn take(&mut self, n: usize) -> &'d [u8] {
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        s
    }
}

#[derive(Debug)]
struct CursorReplaySource<'a, 'd> {
    cur: &'a mut Cursor<'d>,
}

fn read_word<W: Word, const N: usize>(cur: &mut Cursor) -> CompositeWord<W, N> {
    let sz = core::mem::size_of::<W>();
    let bytes = cur.take(N * sz);
    let words: [W::Bytes; N] = core::array::from_fn(|i| {
        let mut b = W::Bytes::default();
        b.as_mut().copy_from_slice(&bytes[i * sz..(i + 1) * sz]);
        b
    });
    CompositeWord::<W, N>::from_le_bytes(words)
}

impl<'a, 'd> ReplaySource<[u8; 32]> for CursorReplaySource<'a, 'd> {
    fn next_and_msg<W: Word, const N: usize>(&mut self) -> CompositeWord<W, N> {
        read_word(self.cur)
    }
    fn next_input_share2<W: Word, const N: usize>(&mut self) -> CompositeWord<W, N> {
        read_word(self.cur)
    }
    fn commitment_digest_unopened(&mut self) -> [u8; 32] {
        let mut d = [0u8; 32];
        d.copy_from_slice(self.cur.take(32));
        d
    }
    fn check_consumed(&self) -> Result<(), ViewReplayError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Verification.
// ---------------------------------------------------------------------------

/// Verifies a streamed proof for `circuit` against the public `expected_output`.
/// Returns `true` iff the proof is valid and bound to `binding`. A malformed or
/// truncated stream is treated as invalid (returns `false`), never a panic.
///
/// `num_iters` is part of the statement: soundness error is `(2/3)^num_iters`, so the
/// caller must pass the response count it *demands* (see [n_eps]), never one derived
/// from the proof's own length. A zero count would make every check vacuous — an
/// empty proof would "verify" — so it is refused outright.
pub fn verify_stream<C: Circuit>(
    circuit: &C,
    expected_output: &Words,
    stream: &[u8],
    num_iters: usize,
    binding: &[u8],
) -> bool {
    if num_iters == 0 {
        return false;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_stream_inner(circuit, expected_output, stream, num_iters, binding)
    }))
    .unwrap_or(false)
}

fn verify_stream_inner<C: Circuit>(
    circuit: &C,
    expected_output: &Words,
    stream: &[u8],
    num_iters: usize,
    binding: &[u8],
) -> bool {
    let mut cur = Cursor {
        data: stream,
        pos: 0,
    };

    let mut challenge_hasher = H::new();
    // Length-prefixed, domain-separated binding — must match the prover exactly.
    challenge_hasher.update(b"ZKBOO-BINDING-v1");
    challenge_hasher.update(&(binding.len() as u64).to_le_bytes());
    challenge_hasher.update(binding);

    let mut challenges = PartyVec::new();

    for _ in 0..num_iters {
        // Per-response header.
        if cur.pos + 65 > stream.len() {
            return false;
        }
        let challenge = cur.take(1)[0];
        let mut seed_challenge = [0u8; 32];
        seed_challenge.copy_from_slice(cur.take(32));
        let mut seed_next = [0u8; 32];
        seed_next.copy_from_slice(cur.take(32));

        let party = Party::from(challenge as usize);
        challenges.push(party);

        let source = CursorReplaySource { cur: &mut cur };
        let replayer = ViewReplayerBackend::<H, PV, S, WPP, _>::with_source(
            party,
            [&seed_challenge, &seed_next],
            source,
        )
        .into_view_replayer();
        circuit.exec(&replayer);
        let commitments = match replayer.finalize_with_arg(expected_output) {
            Ok(c) => c,
            Err(_) => return false,
        };

        for commitment in &commitments {
            challenge_hasher.update(commitment.digest().as_ref());
            commitment
                .output_share()
                .update_hasher(&mut challenge_hasher);
        }
    }

    // The stream must be exactly `num_iters` responses — no trailing bytes. Without
    // this a longer proof verifies under a shorter `num_iters`, i.e. a relayer could
    // downgrade a 438-response proof to a 3-response one by claiming a smaller count
    // and leaving the rest unread. (The header bound above already rejects a stream
    // shorter than the count.)
    if cur.pos != stream.len() {
        return false;
    }

    // Re-derive the Fiat-Shamir challenges and check they match the proof.
    let challenge_entropy = challenge_hasher.finalize();
    let mut generator = ChallengeGenerator::new(HashPRG::<H>::new(challenge_entropy.as_ref()));
    for challenge in &challenges {
        if generator.next() != challenge {
            return false;
        }
    }
    true
}

/// Reconstructs the `Words` the device serialized with `proofofseed_circuits::serialize_words`.
fn deserialize_words(b: &[u8]) -> Option<Words> {
    fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Option<&'a [u8]> {
        if *p + n > b.len() {
            return None;
        }
        let s = &b[*p..*p + n];
        *p += n;
        Some(s)
    }
    let mut p = 0;
    let n8 = u16::from_be_bytes(take(b, &mut p, 2)?.try_into().ok()?) as usize;
    let u8v = take(b, &mut p, n8)?.to_vec();
    let n32 = u16::from_be_bytes(take(b, &mut p, 2)?.try_into().ok()?) as usize;
    let mut u32v = Vec::with_capacity(n32);
    for _ in 0..n32 {
        u32v.push(u32::from_le_bytes(take(b, &mut p, 4)?.try_into().ok()?));
    }
    let n64 = u16::from_be_bytes(take(b, &mut p, 2)?.try_into().ok()?) as usize;
    let mut u64v = Vec::with_capacity(n64);
    for _ in 0..n64 {
        u64v.push(u64::from_le_bytes(take(b, &mut p, 8)?.try_into().ok()?));
    }
    Some(Words {
        u8: u8v,
        u32: u32v,
        u64: u64v,
    })
}

/// The serialized public output for `statement` in `family` (a `Family` wire byte),
/// computed off-device with the shared `proofofseed_circuits` circuits (same encoding the
/// device's `EXEC` returns). Lets the host obtain the expected output for statements
/// whose on-device `EXEC` is impractical — the secp256k1 "elephants", whose monolithic
/// exec trips the OS watchdog. Returns `None` for an unknown statement, family, or a
/// statement the family does not carry.
pub fn expected_output(statement: u8, rounds: usize, family: u8) -> Option<Vec<u8>> {
    use zkboo::executor::{OwnedFlexibleWordPool, exec};
    type WP = OwnedFlexibleWordPool<RC>;
    let words = match Family::from_wire(family)? {
        Family::Bip32Secp256k1 => match statement {
            MASTER_KEY => exec::<_, WP>(&master_key_circuit()),
            HARDENED_CHILD => exec::<_, WP>(&hardened_child_circuit()),
            BIP39_SEED => exec::<_, WP>(&bip39_seed_circuit(rounds)),
            PUBLIC_KEY => exec::<_, WP>(&public_key_circuit()),
            NORMAL_CHILD => exec::<_, WP>(&normal_child_circuit()),
            ETH_ADDRESS => exec::<_, WP>(&ethereum_address_circuit()),
            _ => return None,
        },
        Family::Slip10Ed25519 => match statement {
            MASTER_KEY => exec::<_, WP>(&slip10_master_circuit()),
            HARDENED_CHILD => exec::<_, WP>(&slip10_child_circuit()),
            _ => return None,
        },
    };
    Some(proofofseed_circuits::serialize_words(&words))
}

/// Verifies a streamed proof for the given statement, request-anchored: the
/// verifier reconstructs the circuit from the *public* parameters it asserts and
/// checks the proof against the output it expects, never trusting the device's
/// witness or — for the child statements — the parent chain code.
///
/// `output` is the expected serialized public output (the address/public key the
/// verifier is challenging, or in the dev flow the device's streamed output).
/// `rounds` is the BIP-39 PBKDF2 round count (ignored by the other statements).
/// `chain_code` and `index` are the verifier-asserted public parameters of the
/// hardened/normal child statements; when `None` they fall back to the canonical
/// test-vector parameters (so existing callers are unchanged). `family` is the
/// derivation-family wire byte the proof was requested under (0 = BIP-32/secp256k1,
/// 1 = SLIP-10/ed25519) — the families build different circuits, so a proof made in
/// one never verifies in the other. The private-key statements (public key, Ethereum
/// address, all child kinds) reconstruct with a placeholder witness — the ZKBoo
/// verifier never reads witness values. Returns `false` for an unknown statement or
/// family, or malformed input.
pub fn verify(
    statement: u8,
    output: &[u8],
    stream: &[u8],
    num_iters: usize,
    binding: &[u8],
    rounds: usize,
    chain_code: Option<&[u8]>,
    index: Option<u32>,
    family: u8,
) -> bool {
    verify_with_shape(
        statement, output, stream, num_iters, binding, rounds, chain_code, index, family, None,
        None,
    )
}

/// [verify], told the witness *shape* of the seed statements.
///
/// The master-key and BIP-39 statements allocate one circuit input per witness byte, so
/// their witness length is a public parameter: a proof over a 64-byte BIP-39 seed and one
/// over the 16-byte BIP-32 test vector are different circuits. A verifier given neither
/// falls back to the canonical test vector, which is what a stock device proves, and
/// which is why [verify] was able to look correct while rejecting every real seed proof.
///
/// `salt_len` is the length of the BIP-39 PBKDF2 salt, `"mnemonic" ‖ passphrase`. The salt
/// itself is witness, so a verifier needs only its length — it never learns the
/// passphrase, only how long it is.
#[allow(clippy::too_many_arguments)]
pub fn verify_with_shape(
    statement: u8,
    output: &[u8],
    stream: &[u8],
    num_iters: usize,
    binding: &[u8],
    rounds: usize,
    chain_code: Option<&[u8]>,
    index: Option<u32>,
    family: u8,
    witness_len: Option<usize>,
    salt_len: Option<usize>,
) -> bool {
    let expected = match deserialize_words(output) {
        Some(w) => w,
        None => return false,
    };
    let family = match Family::from_wire(family) {
        Some(f) => f,
        None => return false,
    };
    match (family, statement) {
        // The seed statements. Their witness *shape* is public — one input word per
        // byte — so the verifier must be told it, or it rebuilds a structurally
        // different circuit and rejects every real proof. `witness_len` absent means
        // the canonical test vector, which is what a stock device proves (its real
        // seed is unreachable through BOLOS).
        (Family::Bip32Secp256k1, MASTER_KEY) => {
            let circuit = match witness_len {
                Some(n) => master_key_verify_circuit(n),
                None => master_key_circuit(),
            };
            verify_stream(&circuit, &expected, stream, num_iters, binding)
        }
        (Family::Bip32Secp256k1, BIP39_SEED) => {
            let circuit = match (witness_len, salt_len) {
                (Some(m), Some(sl)) => bip39_seed_verify_circuit(m, sl, rounds),
                (None, None) => bip39_seed_circuit(rounds),
                // One length without the other cannot name a circuit: both are public
                // shape parameters and neither has a default that is safe to assume.
                _ => return false,
            };
            verify_stream(&circuit, &expected, stream, num_iters, binding)
        }
        // Child statements: verifier-asserted chain code + index, placeholder witness.
        (Family::Bip32Secp256k1, HARDENED_CHILD) => {
            let circuit = match (chain_code, index) {
                (Some(cc), Some(i)) => hardened_child_verify_circuit(cc.to_vec(), i),
                _ => hardened_child_circuit(),
            };
            verify_stream(&circuit, &expected, stream, num_iters, binding)
        }
        (Family::Bip32Secp256k1, NORMAL_CHILD) => {
            let circuit = match (chain_code, index) {
                (Some(cc), Some(i)) => normal_child_verify_circuit(cc.to_vec(), i),
                _ => normal_child_circuit(),
            };
            verify_stream(&circuit, &expected, stream, num_iters, binding)
        }
        // Public-key / address statements: no public params, placeholder witness.
        (Family::Bip32Secp256k1, PUBLIC_KEY) => verify_stream(
            &public_key_verify_circuit(),
            &expected,
            stream,
            num_iters,
            binding,
        ),
        (Family::Bip32Secp256k1, ETH_ADDRESS) => verify_stream(
            &ethereum_address_verify_circuit(),
            &expected,
            stream,
            num_iters,
            binding,
        ),
        // The SLIP-10/ed25519 family carries only the recovery statements. A
        // non-hardened asserted index panics in the circuit and is caught by
        // [verify_stream] as a failed verification.
        (Family::Slip10Ed25519, MASTER_KEY) => {
            let circuit = match witness_len {
                Some(n) => slip10_master_verify_circuit(n),
                None => slip10_master_circuit(),
            };
            verify_stream(&circuit, &expected, stream, num_iters, binding)
        }
        (Family::Slip10Ed25519, HARDENED_CHILD) => {
            let circuit = match (chain_code, index) {
                (Some(cc), Some(i)) => slip10_child_verify_circuit(cc.to_vec(), i),
                _ => slip10_child_circuit(),
            };
            verify_stream(&circuit, &expected, stream, num_iters, binding)
        }
        _ => false,
    }
}

/// The public output of a seed statement proved against `witness`.
///
/// The master-key and BIP-39 statements normally run on a compiled-in test vector,
/// because a stock secure element cannot reach its own master seed or mnemonic. A prover
/// handed a witness directly — a software wallet, or a device exercising the statement
/// with a mock one — produces a different output, and a verifier needs it. `salt` is the
/// BIP-39 PBKDF2 salt and must be empty for the master-key statement.
pub fn seed_statement_output(
    statement: u8,
    family: u8,
    witness: &[u8],
    salt: &[u8],
    rounds: usize,
) -> Option<Vec<u8>> {
    use proofofseed_circuits::{MasterKeyCircuit, SeedCircuit, Slip10MasterCircuit};
    match (family, statement) {
        (0, MASTER_KEY) if salt.is_empty() => {
            Some(harness::output_of(&MasterKeyCircuit { seed: witness.to_vec() }))
        }
        (1, MASTER_KEY) if salt.is_empty() => {
            Some(harness::output_of(&Slip10MasterCircuit { seed: witness.to_vec() }))
        }
        (0, BIP39_SEED) if !salt.is_empty() => Some(harness::output_of(&SeedCircuit {
            mnemonic: witness.to_vec(),
            salt: salt.to_vec(),
            rounds,
        })),
        _ => None,
    }
}

/// The structural fingerprint of the circuit a prover runs for `(family, statement)`,
/// computed with natively recomputed comb tables.
///
/// Exposed so a host can compare its own answer with one read back from a device, which
/// is what establishes that the device compiled the circuit the host thinks it did. See
/// [proofofseed_circuits::statement_fingerprint] for why the digest is a function of the
/// public parameters and not of the witness.
pub fn statement_fingerprint(
    statement: u8,
    rounds: usize,
    family: u8,
    chain_code: Option<&[u8]>,
    index: Option<u32>,
) -> Option<[u8; 32]> {
    let family = match family {
        0 => proofofseed_circuits::request::Family::Bip32Secp256k1,
        1 => proofofseed_circuits::request::Family::Slip10Ed25519,
        _ => return None,
    };
    proofofseed_circuits::statement_fingerprint::<proofofseed_circuits::comb::ComputedComb>(
        family, statement, rounds, chain_code, index,
    )
}

/// The number of ZKBoo responses (repetitions) needed for `bits` bits of soundness.
///
/// A cheating prover survives one repetition with probability 2/3: of the three view
/// pairs, the verifier opens one, and for a false statement at most two of the three
/// pairs can be made consistent. `n` independent repetitions therefore leave soundness
/// error `(2/3)^n`, and `(2/3)^n <= 2^-bits` requires `n >= bits / log2(3/2)`.
///
/// The deployment parameter targets 128-bit *post-quantum* soundness: Grover search
/// over the Fiat-Shamir challenge space gives a quadratic speedup, so the classical
/// soundness error must be `2^-256` — `n_eps(256) = 438` responses, the whitepaper's
/// N_epsilon and the only setting these crates use. Lower arguments are meaningful to
/// the formula but are not deployment parameters here.
pub fn n_eps(bits: u32) -> usize {
    (f64::from(bits) / 1.5f64.log2()).ceil() as usize
}

// ---------------------------------------------------------------------------
// Prover-side host harness.
// ---------------------------------------------------------------------------

/// Host-side prover harness for round-trip validation (tests, examples, future
/// drivers): generates the canonical proof byte stream the device would emit over
/// APDU, using the device's crypto suite, so a proof can be produced and verified
/// entirely off-device.
pub mod harness {
    use super::*;
    use core::cell::RefCell;
    use zkboo::executor::{OwnedFlexibleWordPool, exec};
    use zkboo::prover::challenge::ChallengeBuilder;
    use zkboo::prover::proof::build_proof_custom;
    use zkboo::prover::proof::collectors::ResponseDataCollector;
    use zkboo::prover::views::OwnedFlexibleWordTriplePool;

    type PS = HashPRG<H>;
    type WP = OwnedFlexibleWordPool<RC>;
    pub(crate) type WTP = OwnedFlexibleWordTriplePool<RC>;

    /// Prover-side sink that writes the canonical byte stream to a Vec (the same
    /// encoding the device emits over APDU).
    #[derive(Debug)]
    pub(crate) struct VecSink<'a> {
        out: &'a RefCell<Vec<u8>>,
        include_input_share2: bool,
    }

    impl<'a> VecSink<'a> {
        fn write_word<W: Word, const N: usize>(&self, word: CompositeWord<W, N>) {
            let mut out = self.out.borrow_mut();
            for wb in word.to_le_bytes() {
                out.extend_from_slice(wb.as_ref());
            }
        }
    }

    impl<'a> ResponseDataCollector<[u8; 32], [u8; 32]> for VecSink<'a> {
        type InitArg = &'a RefCell<Vec<u8>>;
        type FinalizeRes = ();
        fn new(challenge: Party, sc: [u8; 32], sn: [u8; 32], arg: Self::InitArg) -> Self {
            {
                let mut out = arg.borrow_mut();
                out.push(challenge.index() as u8);
                out.extend_from_slice(&sc);
                out.extend_from_slice(&sn);
            }
            Self {
                out: arg,
                include_input_share2: challenge.index() != 0,
            }
        }
        fn push_input_share2<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) {
            if self.include_input_share2 {
                self.write_word(word);
            }
        }
        fn push_and_msg<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) {
            self.write_word(word);
        }
        fn finalize(self, digest: [u8; 32]) {
            self.out.borrow_mut().extend_from_slice(&digest);
        }
    }

    /// Proves `circuit` with `n` responses and returns the canonical proof byte
    /// stream (the same encoding the device emits), bound to `binding`.
    pub fn gen_stream<C: Circuit>(
        circuit: &C,
        n: usize,
        seed_entropy: &[u8],
        binding: &[u8],
    ) -> Vec<u8> {
        let out = RefCell::new(Vec::new());
        let mut builder = ChallengeBuilder::<H, PS, PV, S, WTP>::new(seed_entropy, binding);
        for _ in 0..n {
            let it = builder.next_iter();
            circuit.exec(it.view_builder());
            it.finalize();
        }
        let challenge_entropy = builder.finalize();
        let _: Vec<()> = build_proof_custom::<C, H, PS, PV, S, VecSink, WTP>(
            circuit,
            seed_entropy,
            challenge_entropy,
            n,
            &out,
        );
        out.into_inner()
    }

    /// Proves only the responses `[start, end)` of the `n`-response proof of
    /// `circuit` and returns their byte stream — the ranged path the device runs
    /// for a range-carrying request, driven by the shared
    /// `proofofseed_circuits::ranged::build_ranged_proof_hooked`. The challenge phase still
    /// covers all `n` responses (the Fiat-Shamir challenge is global); with the
    /// same `seed_entropy`, concatenating the ranges of a partition of `0..n` in
    /// order reproduces [gen_stream]'s output byte for byte.
    pub fn gen_stream_range<C: Circuit>(
        circuit: &C,
        n: usize,
        (start, end): (usize, usize),
        seed_entropy: &[u8],
        binding: &[u8],
    ) -> Vec<u8> {
        let out = RefCell::new(Vec::new());
        let mut builder = ChallengeBuilder::<H, PS, PV, S, WTP>::new(seed_entropy, binding);
        for _ in 0..n {
            let it = builder.next_iter();
            circuit.exec(it.view_builder());
            it.finalize();
        }
        let challenge_entropy = builder.finalize();
        let _: Vec<()> = proofofseed_circuits::ranged::build_ranged_proof_hooked::<
            C,
            H,
            PS,
            PV,
            S,
            VecSink,
            WTP,
            zkboo::backend::NoHook,
        >(circuit, seed_entropy, challenge_entropy, n, (start, end), &out, ());
        out.into_inner()
    }

    /// The device's serialized public output for `circuit` (plain execution, then
    /// `proofofseed_circuits::serialize_words`).
    pub fn output_of<C: Circuit>(circuit: &C) -> Vec<u8> {
        proofofseed_circuits::serialize_words(&exec::<C, WP>(circuit))
    }

    /// The plain-execution public output of `circuit`, as structured [Words].
    pub fn exec_words<C: Circuit>(circuit: &C) -> Words {
        exec::<C, WP>(circuit)
    }

    /// Shared state behind [WriteSink]: the writer, the number of proof bytes
    /// written, and the first io error (subsequent writes are skipped once an
    /// error is recorded — the collector API has no error channel, so the caller
    /// checks after the build).
    pub struct SinkState<W: std::io::Write> {
        writer: W,
        bytes: u64,
        error: Option<std::io::Error>,
    }

    impl<W: std::io::Write> core::fmt::Debug for SinkState<W> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SinkState")
                .field("bytes", &self.bytes)
                .field("error", &self.error)
                .finish()
        }
    }

    impl<W: std::io::Write> SinkState<W> {
        pub fn new(writer: W) -> RefCell<Self> {
            RefCell::new(Self { writer, bytes: 0, error: None })
        }
        fn write(&mut self, data: &[u8]) {
            if self.error.is_some() {
                return;
            }
            match self.writer.write_all(data) {
                Ok(()) => self.bytes += data.len() as u64,
                Err(e) => self.error = Some(e),
            }
        }
        /// Consumes the state, returning the bytes written or the first io error.
        pub fn finish(self) -> std::io::Result<u64> {
            match self.error {
                Some(e) => Err(e),
                None => Ok(self.bytes),
            }
        }
    }

    /// Prover-side sink streaming the canonical byte encoding (identical to
    /// [VecSink]'s, i.e. to the device's) into any [std::io::Write] — so proofs
    /// larger than memory go straight to disk.
    pub struct WriteSink<'a, W: std::io::Write> {
        out: &'a RefCell<SinkState<W>>,
        include_input_share2: bool,
    }

    impl<'a, W: std::io::Write> core::fmt::Debug for WriteSink<'a, W> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("WriteSink")
                .field("include_input_share2", &self.include_input_share2)
                .finish()
        }
    }

    impl<'a, W: std::io::Write> WriteSink<'a, W> {
        fn write_word<Wd: Word, const N: usize>(&self, word: CompositeWord<Wd, N>) {
            let mut out = self.out.borrow_mut();
            for wb in word.to_le_bytes() {
                out.write(wb.as_ref());
            }
        }
    }

    impl<'a, W: std::io::Write> ResponseDataCollector<[u8; 32], [u8; 32]> for WriteSink<'a, W> {
        type InitArg = &'a RefCell<SinkState<W>>;
        type FinalizeRes = ();
        fn new(challenge: Party, sc: [u8; 32], sn: [u8; 32], arg: Self::InitArg) -> Self {
            {
                let mut out = arg.borrow_mut();
                out.write(&[challenge.index() as u8]);
                out.write(&sc);
                out.write(&sn);
            }
            Self {
                out: arg,
                include_input_share2: challenge.index() != 0,
            }
        }
        fn push_input_share2<Wd: Word, const N: usize>(&mut self, word: CompositeWord<Wd, N>) {
            if self.include_input_share2 {
                self.write_word(word);
            }
        }
        fn push_and_msg<Wd: Word, const N: usize>(&mut self, word: CompositeWord<Wd, N>) {
            self.write_word(word);
        }
        fn finalize(self, digest: [u8; 32]) {
            self.out.borrow_mut().write(&digest);
        }
    }

    /// [gen_stream], streamed into a writer instead of a `Vec` — byte-identical
    /// output, constant memory. Returns the number of proof bytes written.
    pub fn gen_stream_to<C: Circuit, W: std::io::Write>(
        circuit: &C,
        n: usize,
        seed_entropy: &[u8],
        binding: &[u8],
        writer: W,
    ) -> std::io::Result<u64> {
        gen_stream_range_to(circuit, n, (0, n), seed_entropy, binding, writer)
    }

    /// [gen_stream_range], streamed into a writer instead of a `Vec` —
    /// byte-identical output, constant memory. Returns the bytes written.
    pub fn gen_stream_range_to<C: Circuit, W: std::io::Write>(
        circuit: &C,
        n: usize,
        (start, end): (usize, usize),
        seed_entropy: &[u8],
        binding: &[u8],
        writer: W,
    ) -> std::io::Result<u64> {
        let out = SinkState::new(writer);
        let mut builder = ChallengeBuilder::<H, PS, PV, S, WTP>::new(seed_entropy, binding);
        for _ in 0..n {
            let it = builder.next_iter();
            circuit.exec(it.view_builder());
            it.finalize();
        }
        let challenge_entropy = builder.finalize();
        let _: Vec<()> = proofofseed_circuits::ranged::build_ranged_proof_hooked::<
            C,
            H,
            PS,
            PV,
            S,
            WriteSink<W>,
            WTP,
            zkboo::backend::NoHook,
        >(circuit, seed_entropy, challenge_entropy, n, (start, end), &out, ());
        out.into_inner().finish()
    }
}

/// Native derivation of witnesses and public parameters from a BIP-39 mnemonic,
/// implemented by *executing the statement circuits* through zkboo's plain
/// executor — the same circuits the proofs are about, so derivation cannot drift
/// from what is proved, and no third-party wallet code enters the trust path.
/// All returned key material is [Zeroizing]-wrapped.
pub mod derive {
    use super::harness::exec_words;
    use proofofseed_circuits::{
        comb::ComputedComb, HardenedChildCircuit, MasterKeyCircuit, NormalChildCircuit,
        SeedCircuit,
        Slip10ChildCircuit, Slip10MasterCircuit,
    };
    use zeroize::{Zeroize, Zeroizing};
    use zkboo::word::Words;

    const HARDENED: u32 = 0x8000_0000;

    /// A derived tree node: private key (32 bytes, big-endian) and chain code.
    pub struct Node {
        pub private_key: Zeroizing<[u8; 32]>,
        pub chain_code: [u8; 32],
    }

    /// The BIP-39 seed of `mnemonic` under `passphrase` (empty for none), via the
    /// full 2048-round PBKDF2 circuit.
    pub fn bip39_seed(mnemonic: &[u8], passphrase: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut salt = b"mnemonic".to_vec();
        salt.extend_from_slice(passphrase);
        let mut words = exec_words(&SeedCircuit {
            mnemonic: mnemonic.to_vec(),
            salt,
            rounds: 2048,
        });
        let seed = Zeroizing::new(words.u8.clone());
        words.u8.zeroize();
        seed
    }

    /// Splits a BIP-32 master/child circuit output into a [Node]. The child
    /// circuits emit the key as four little-endian-ordered u64 limbs; the master
    /// emits plain bytes.
    fn bip32_node_of(mut words: Words) -> Node {
        let mut private_key = Zeroizing::new([0u8; 32]);
        let chain_code: [u8; 32];
        if words.u64.len() == 4 {
            for (i, limb) in words.u64.iter().rev().enumerate() {
                private_key[8 * i..8 * i + 8].copy_from_slice(&limb.to_be_bytes());
            }
            chain_code = words.u8[..32].try_into().expect("chain code bytes");
        } else {
            private_key.copy_from_slice(&words.u8[..32]);
            chain_code = words.u8[32..64].try_into().expect("chain code bytes");
        }
        words.u8.zeroize();
        words.u64.zeroize();
        Node { private_key, chain_code }
    }

    /// Walks the BIP-32/secp256k1 tree from `seed` down `path` (hardened bit set
    /// per component), executing the master, hardened-child and normal-child
    /// circuits.
    pub fn bip32_node(seed: &[u8], path: &[u32]) -> Node {
        let mut node = bip32_node_of(exec_words(&MasterKeyCircuit { seed: seed.to_vec() }));
        for &index in path {
            let words = if index & HARDENED != 0 {
                exec_words(&HardenedChildCircuit {
                    chain_code: node.chain_code.to_vec(),
                    parent_priv: node.private_key.to_vec(),
                    index,
                })
            } else {
                exec_words(&NormalChildCircuit::<ComputedComb>::new(
                    node.chain_code.to_vec(),
                    node.private_key.to_vec(),
                    index,
                ))
            };
            node = bip32_node_of(words);
        }
        node
    }

    /// Walks the SLIP-10/ed25519 tree from `seed` down `path`. Every component
    /// must be hardened (SLIP-10 ed25519 defines nothing else); returns `None`
    /// for a non-hardened component.
    pub fn slip10_node(seed: &[u8], path: &[u32]) -> Option<Node> {
        let words = exec_words(&Slip10MasterCircuit { seed: seed.to_vec() });
        let mut node = slip10_node_of(words);
        for &index in path {
            if index & HARDENED == 0 {
                return None;
            }
            let words = exec_words(&Slip10ChildCircuit {
                chain_code: node.chain_code.to_vec(),
                parent_priv: node.private_key.to_vec(),
                index,
            });
            node = slip10_node_of(words);
        }
        Some(node)
    }

    fn slip10_node_of(mut words: Words) -> Node {
        let mut private_key = Zeroizing::new([0u8; 32]);
        private_key.copy_from_slice(&words.u8[..32]);
        let chain_code: [u8; 32] = words.u8[32..64].try_into().expect("chain code bytes");
        words.u8.zeroize();
        Node { private_key, chain_code }
    }
}

// ---------------------------------------------------------------------------
// Tests: host round-trip (generate a stream, verify it, tamper it).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::harness::{VecSink, WTP, gen_stream, output_of};
    use super::*;
    use core::cell::RefCell;
    use zkboo::prover::challenge::ChallengeBuilder;
    use zkboo::prover::proof::build_proof_custom;
    use zkboo::prover::views::collectors::{ViewCommitmentsRelayer, ViewsDataCollector};
    use zkboo::prover::views::ViewCommitment;

    type PS = HashPRG<H>;

    /// A challenge-phase collector mirroring the app's `ChallengeKeepalive`: it relays
    /// the genuine commitments via [ViewCommitmentsRelayer] and counts the per-AND-gate
    /// `push_and_msgs` calls (where the device would fire a watchdog keepalive), but
    /// feeds no hasher — so it must be transcript-neutral.
    #[derive(Debug)]
    struct CountingRelayer {
        inner: ViewCommitmentsRelayer<[u8; 32], [u8; 32]>,
        count: usize,
    }

    impl ViewsDataCollector<[u8; 32], [u8; 32]> for CountingRelayer {
        type InitArg = ();
        type FinalizeRes = [ViewCommitment<[u8; 32]>; 3];
        fn new(seeds: &[[u8; 32]; 3], _arg: ()) -> Self {
            Self {
                inner: ViewCommitmentsRelayer::new(seeds, ()),
                count: 0,
            }
        }
        fn push_input_share2<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) {
            self.inner.push_input_share2(word);
        }
        fn push_and_msgs<W: Word, const N: usize>(&mut self, and_msgs: [CompositeWord<W, N>; 3]) {
            self.count += 1;
            self.inner.push_and_msgs(and_msgs);
        }
        fn finalize(self, commitments: [ViewCommitment<[u8; 32]>; 3]) -> Self::FinalizeRes {
            assert!(self.count > 0, "challenge pass should relay AND messages");
            self.inner.finalize(commitments)
        }
    }

    /// Like [gen_stream], but drives the challenge phase through [CountingRelayer] via
    /// `next_iter_custom` instead of the default `next_iter`.
    fn gen_stream_custom_challenge<C: Circuit>(
        circuit: &C,
        n: usize,
        seed_entropy: &[u8],
        binding: &[u8],
    ) -> Vec<u8> {
        let out = RefCell::new(Vec::new());
        let mut builder = ChallengeBuilder::<H, PS, PV, S, WTP>::new(seed_entropy, binding);
        for _ in 0..n {
            let it = builder.next_iter_custom::<CountingRelayer>(());
            circuit.exec(it.view_builder());
            it.finalize();
        }
        let challenge_entropy = builder.finalize();
        let _: Vec<()> = build_proof_custom::<C, H, PS, PV, S, VecSink, WTP>(
            circuit,
            seed_entropy,
            challenge_entropy,
            n,
            &out,
        );
        out.into_inner()
    }

    /// A custom challenge-phase collector that only observes the relayed AND-message
    /// stream must not perturb the Fiat-Shamir challenge, so the emitted proof bytes are
    /// identical to the default-relayer path and still verify.
    fn assert_challenge_collector_neutral<C: Circuit>(stmt: u8, c: C) {
        let default = gen_stream(&c, 5, b"e", b"bind");
        let custom = gen_stream_custom_challenge(&c, 5, b"e", b"bind");
        assert_eq!(
            default, custom,
            "custom challenge collector changed the proof bytes (statement {stmt})"
        );
        assert!(verify(stmt, &output_of(&c), &custom, 5, b"bind", 0, None, None, 0));
    }

    #[test]
    fn custom_challenge_collector_is_transcript_neutral() {
        // The invariant the device's watchdog keepalive depends on.
        assert_challenge_collector_neutral(MASTER_KEY, master_key_circuit());
        assert_challenge_collector_neutral(HARDENED_CHILD, hardened_child_circuit());
    }

    #[test]
    fn round_trip_non_elephant_statements() {
        // master_key, hardened_child, and bip39 (few rounds) verify end to end.
        let cases: [(u8, &str, Vec<u8>, Vec<u8>); 3] = [
            (
                MASTER_KEY,
                "master",
                output_of(&master_key_circuit()),
                gen_stream(&master_key_circuit(), 6, b"e", b""),
            ),
            (
                HARDENED_CHILD,
                "hardened",
                output_of(&hardened_child_circuit()),
                gen_stream(&hardened_child_circuit(), 6, b"e", b""),
            ),
            (
                BIP39_SEED,
                "bip39",
                output_of(&bip39_seed_circuit(4)),
                gen_stream(&bip39_seed_circuit(4), 6, b"e", b""),
            ),
        ];
        for (stmt, name, output, stream) in cases {
            assert!(
                verify(stmt, &output, &stream, 6, b"", 4, None, None, 0),
                "{name} should verify"
            );
        }
    }

    #[test]
    fn rejects_tampered_wrong_output_and_binding() {
        let c = hardened_child_circuit();
        let output = output_of(&c);
        let stream = gen_stream(&c, 6, b"e", b"tx_a");
        assert!(verify(HARDENED_CHILD, &output, &stream, 6, b"tx_a", 0, None, None, 0));

        // Tampered stream.
        let mut bad = stream.clone();
        bad[200] ^= 0xff;
        assert!(!verify(HARDENED_CHILD, &output, &bad, 6, b"tx_a", 0, None, None, 0));

        // Wrong public output.
        let mut wrong = output.clone();
        wrong[3] ^= 0xff;
        assert!(!verify(HARDENED_CHILD, &wrong, &stream, 6, b"tx_a", 0, None, None, 0));

        // Mismatched binding.
        assert!(!verify(HARDENED_CHILD, &output, &stream, 6, b"tx_b", 0, None, None, 0));
    }

    #[test]
    fn verifier_needs_only_public_params_not_witness_values() {
        // Request-anchored verification (docs/real-witness.md): the verifier rebuilds
        // the circuit from the public params it asserts, with a zeroed placeholder
        // witness, and a proof made with a *different* (here, the test-vector) witness
        // still verifies. The witness values are irrelevant to verification — only the
        // witness length and the public circuit constants matter. This is what lets the
        // device prove its real seed while the host only knows the asserted public data.
        let real = hardened_child_circuit();
        let stream = gen_stream(&real, 6, b"e", b"tx");
        let expected = deserialize_words(&output_of(&real)).unwrap();

        let verifier = hardened_child_verify_circuit(real.chain_code.clone(), real.index);
        assert_ne!(
            verifier.parent_priv, real.parent_priv,
            "placeholder witness must differ from the real one"
        );
        assert!(
            verify_stream(&verifier, &expected, &stream, 6, b"tx"),
            "proof must verify against a placeholder-witness circuit with the asserted params"
        );

        // A verifier that asserts the wrong chain code rebuilds a different circuit
        // constant and must reject — the public params are genuinely bound.
        let mut wrong_cc = real.chain_code.clone();
        wrong_cc[0] ^= 0xff;
        let bad = hardened_child_verify_circuit(wrong_cc, real.index);
        assert!(
            !verify_stream(&bad, &expected, &stream, 6, b"tx"),
            "a wrong asserted chain code must reject"
        );
    }

    #[test]
    fn verify_accepts_asserted_child_params_and_rejects_wrong_ones() {
        // The request-anchored path through the public verify() API: the verifier
        // passes the chain code and index it asserts; the proof verifies only when
        // they match the circuit the prover used.
        let real = hardened_child_circuit();
        let output = output_of(&real);
        let stream = gen_stream(&real, 6, b"e", b"tx");
        let cc = real.chain_code.clone();

        assert!(
            verify(HARDENED_CHILD, &output, &stream, 6, b"tx", 0, Some(&cc), Some(real.index), 0),
            "correct asserted params must verify"
        );

        let mut bad_cc = cc.clone();
        bad_cc[0] ^= 0xff;
        assert!(
            !verify(HARDENED_CHILD, &output, &stream, 6, b"tx", 0, Some(&bad_cc), Some(real.index), 0),
            "wrong asserted chain code must reject"
        );
        assert!(
            !verify(HARDENED_CHILD, &output, &stream, 6, b"tx", 0, Some(&cc), Some(real.index ^ 1), 0),
            "wrong asserted index must reject"
        );
    }

    #[test]
    fn soundness_parameter_derivation() {
        // The deployment parameter: 128-bit post-quantum = 2^-256 classical soundness.
        assert_eq!(n_eps(256), 438);
        // The formula away from the deployment point, and a sanity floor. (Deliberately
        // not evaluated at 128: that value is a soundness setting this project does not
        // use, and it is not to appear in these crates.)
        assert_eq!(n_eps(64), 110);
        assert_eq!(n_eps(1), 2);
    }

    #[test]
    fn malformed_output_or_statement_rejected() {
        let c = master_key_circuit();
        let stream = gen_stream(&c, 4, b"e", b"");
        assert!(!verify(MASTER_KEY, b"\x00", &stream, 4, b"", 0, None, None, 0)); // truncated output
        assert!(!verify(99, &output_of(&c), &stream, 4, b"", 0, None, None, 0)); // unknown statement
    }

    #[test]
    fn zero_responses_never_verify() {
        // The response count is part of the statement: with num_iters = 0 every check
        // is vacuous, so an empty proof (or any proof) must refuse rather than
        // trivially pass. The twin at num_iters = 4 shows the same inputs verify.
        let c = master_key_circuit();
        let output = output_of(&c);
        let stream = gen_stream(&c, 4, b"e", b"");
        assert!(verify(MASTER_KEY, &output, &stream, 4, b"", 0, None, None, 0));
        assert!(!verify(MASTER_KEY, &output, &stream, 0, b"", 0, None, None, 0));
        assert!(!verify(MASTER_KEY, &output, b"", 0, b"", 0, None, None, 0), "empty proof");
    }

    #[test]
    fn canonical_expected_constants_match_their_circuits() {
        // The BIP-32 vector constants are anchored directly to the circuits, so a
        // corrupted constant fails here rather than silently anchoring nothing (the
        // SLIP-10 constants get the same treatment in tests/solana.rs).
        use proofofseed_circuits::{EXPECTED_HARDENED_CC, EXPECTED_HARDENED_PRIV, EXPECTED_MASTER};
        let to_hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let master = super::harness::exec_words(&master_key_circuit());
        assert_eq!(to_hex(&master.u8), EXPECTED_MASTER);
        let child = super::harness::exec_words(&hardened_child_circuit());
        assert_eq!(to_hex(&child.u8), EXPECTED_HARDENED_CC);
        let priv_be: Vec<u8> =
            child.u64.iter().rev().flat_map(|l| l.to_be_bytes()).collect();
        assert_eq!(to_hex(&priv_be), EXPECTED_HARDENED_PRIV);
    }
}
