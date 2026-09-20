// SPDX-License-Identifier: LGPL-3.0-or-later

//! The host-side streaming verifier and prover harness for ProofofSeed proofs.
//!
//! The wire encoding, what the verifier refuses, and the soundness parameter are in
//! `knowledge/proof-stream.md`.

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
use proofofseed_circuits::hasher::Keccak256Hasher;
use zkboo::circuit::Circuit;
use zkboo::crypto::{
    GeneratesRandom, HashPRG, Hasher, PseudoRandomGenerator, TAG_CHALLENGE, absorb_framed,
};
use zkboo::prover::challenge::{ChallengeGenerator, Party, PartyVec};
use zkboo::verifier::replay::{
    OwnedFlexibleWordPairPool, ReplaySource, ViewReplayError, ViewReplayerBackend,
};
use zkboo::word::{CompositeWord, Word, Words};

// Fixed crypto choices, which must match the device prover.
type H = Keccak256Hasher;
type PV = HashPRG<H>;
type S = [u8; 32];
type RC = usize; // host verifier: no memory pressure, no overflow worry
type WPP = OwnedFlexibleWordPairPool<RC>;
type WP = zkboo::executor::OwnedFlexibleWordPool<RC>;

/// Plain execution of a circuit, with the host's word pool and no backend hook.
fn exec_circuit<C: Circuit>(circuit: &C) -> Words {
    zkboo::executor::exec::<C, WP, _>(circuit, zkboo::executor::ExecOptions::new())
}

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

/// Verifies a streamed proof for a circuit against its public output and binding.
///
/// 🚨 `num_iters` is part of the statement: pass the response count the verifier
/// demands, never one derived from the proof's own length.
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
    // Tagged and length-prefixed with the library's own tag and framing, never a
    // second copy of them, so that it matches the prover exactly.
    absorb_framed(&mut challenge_hasher, TAG_CHALLENGE, binding);

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

    // 🚨 Exactly `num_iters` responses, with no trailing bytes: without this a longer
    // proof verifies under a shorter count. See knowledge/proof-stream.md.
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

/// Reconstructs the `Words` a device serialised with `serialize_words`.
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

/// The serialised public output of a statement's canonical test vector, computed
/// off-device.
pub fn expected_output(statement: u8, rounds: usize, family: u8) -> Option<Vec<u8>> {
    let words = match Family::from_wire(family)? {
        Family::Bip32Secp256k1 => match statement {
            MASTER_KEY => exec_circuit(&master_key_circuit()),
            HARDENED_CHILD => exec_circuit(&hardened_child_circuit()),
            BIP39_SEED => exec_circuit(&bip39_seed_circuit(rounds)),
            PUBLIC_KEY => exec_circuit(&public_key_circuit()),
            NORMAL_CHILD => exec_circuit(&normal_child_circuit()),
            ETH_ADDRESS => exec_circuit(&ethereum_address_circuit()),
            _ => return None,
        },
        Family::Slip10Ed25519 => match statement {
            MASTER_KEY => exec_circuit(&slip10_master_circuit()),
            HARDENED_CHILD => exec_circuit(&slip10_child_circuit()),
            _ => return None,
        },
    };
    Some(proofofseed_circuits::serialize_words(&words))
}

/// The public output a curve statement produces for a given private key.
pub fn curve_statement_output(
    statement: u8,
    private_key: &[u8],
    chain_code: Option<&[u8]>,
    index: Option<u32>,
) -> Option<Vec<u8>> {
    use proofofseed_circuits::{AddressCircuit, NormalChildCircuit, PubKeyCircuit};
    let key = private_key.to_vec();
    // The default table source, as the canonical constructors use: the source moves
    // neither the output nor the fingerprint, but the parameter must be pinned.
    let words = match statement {
        PUBLIC_KEY => {
            let circuit: PubKeyCircuit = PubKeyCircuit::new(key);
            exec_circuit(&circuit)
        }
        ETH_ADDRESS => {
            let circuit: AddressCircuit = AddressCircuit::new(key);
            exec_circuit(&circuit)
        }
        NORMAL_CHILD => {
            let circuit: NormalChildCircuit =
                NormalChildCircuit::new(chain_code?.to_vec(), key, index?);
            exec_circuit(&circuit)
        }
        _ => return None,
    };
    Some(proofofseed_circuits::serialize_words(&words))
}

/// The public output of a hardened-child statement proved against a given parent key.
pub fn hardened_child_statement_output(
    family: u8,
    parent_priv: &[u8],
    chain_code: &[u8],
    index: u32,
) -> Option<Vec<u8>> {
    use proofofseed_circuits::{HardenedChildCircuit, Slip10ChildCircuit};
    let words = match family {
        0 => exec_circuit(&HardenedChildCircuit {
            chain_code: chain_code.to_vec(),
            parent_priv: parent_priv.to_vec(),
            index,
        }),
        1 => exec_circuit(&Slip10ChildCircuit {
            chain_code: chain_code.to_vec(),
            parent_priv: parent_priv.to_vec(),
            index,
        }),
        _ => return None,
    };
    Some(proofofseed_circuits::serialize_words(&words))
}

/// Verifies a streamed proof for a statement, rebuilding the circuit from the public
/// parameters the verifier asserts.
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

/// [verify], told the witness shape of the seed statements.
///
/// ⚠️ Without the shape a seed proof cannot be verified at all; see
/// `knowledge/verifier-circuits.md`.
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
        // The seed statements. An absent `witness_len` means the canonical test
        // vector, which is what a stock device proves.
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
                // One length without the other cannot name a circuit, and neither has
                // a default that is safe to assume.
                _ => return false,
            };
            verify_stream(&circuit, &expected, stream, num_iters, binding)
        }
        // Child statements: asserted chain code and index, placeholder witness.
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
        // Public-key and address statements: no public parameters, placeholder witness.
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
        // non-hardened asserted index panics in the circuit, which `verify_stream`
        // catches as a failed verification.
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

/// The public output of a seed statement proved against a given witness.
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

/// The structural fingerprint of the circuit a prover runs for a family and statement,
/// computed with natively recomputed comb tables.
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

/// The number of ZKBoo responses needed for a given number of bits of soundness.
///
/// The deployment parameter is `n_eps(256) = 438`; see `knowledge/proof-stream.md`.
pub fn n_eps(bits: u32) -> usize {
    (f64::from(bits) / 1.5f64.log2()).ceil() as usize
}

// ---------------------------------------------------------------------------
// Prover-side host harness.
// ---------------------------------------------------------------------------

/// A host-side prover generating the canonical proof byte stream a device emits.
pub mod harness {
    use super::*;
    use core::cell::RefCell;
    use zkboo::prover::challenge::ChallengeBuilder;
    use zkboo::prover::proof::collectors::ResponseDataCollector;
    use zkboo::prover::proof::{ProofOptions, build_proof};
    use zkboo::prover::views::OwnedFlexibleWordTriplePool;

    type PS = HashPRG<H>;
    pub(crate) type WTP = OwnedFlexibleWordTriplePool<RC>;

    /// A sink writing the canonical byte stream to a `Vec`.
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

    /// Proves a circuit with `n` responses, returning the canonical proof byte stream.
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
        let _: Vec<()> = build_proof::<C, H, PS, PV, S, VecSink, WTP, _>(
            circuit,
            seed_entropy,
            challenge_entropy,
            n,
            ProofOptions::new().with_collector_arg::<VecSink>(&out),
        );
        out.into_inner()
    }

    /// Proves only a half-open range of an `n`-response proof, returning its byte
    /// stream.
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

    /// The serialised public output of a circuit.
    pub fn output_of<C: Circuit>(circuit: &C) -> Vec<u8> {
        proofofseed_circuits::serialize_words(&exec_circuit(circuit))
    }

    /// The public output of a circuit, as structured [Words].
    pub fn exec_words<C: Circuit>(circuit: &C) -> Words {
        super::exec_circuit(circuit)
    }

    /// Shared state behind [WriteSink]: the writer, the bytes written, and the first
    /// io error, which the caller checks after the build.
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

    /// A sink streaming the canonical byte encoding into any [std::io::Write].
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

    /// [gen_stream], streamed into a writer at constant memory.
    pub fn gen_stream_to<C: Circuit, W: std::io::Write>(
        circuit: &C,
        n: usize,
        seed_entropy: &[u8],
        binding: &[u8],
        writer: W,
    ) -> std::io::Result<u64> {
        gen_stream_range_to(circuit, n, (0, n), seed_entropy, binding, writer)
    }

    /// [gen_stream_range], streamed into a writer at constant memory.
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

/// Native derivation of witnesses and public parameters from a BIP-39 mnemonic, by
/// executing the statement circuits through zkboo's plain executor.
pub mod derive {
    use super::harness::exec_words;
    use proofofseed_circuits::{
        comb::ComputedComb, checked_payload, HardenedChildCircuit, MasterKeyCircuit,
        NormalChildCircuit, SeedCircuit,
        Slip10ChildCircuit, Slip10MasterCircuit,
    };
    use zeroize::{Zeroize, Zeroizing};
    use zkboo::word::Words;

    const HARDENED: u32 = 0x8000_0000;

    /// A derived tree node: a big-endian private key and a chain code.
    pub struct Node {
        pub private_key: Zeroizing<[u8; 32]>,
        pub chain_code: [u8; 32],
    }

    /// The BIP-39 seed of a mnemonic under a passphrase.
    pub fn bip39_seed(mnemonic: &[u8], passphrase: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut salt = b"mnemonic".to_vec();
        salt.extend_from_slice(passphrase);
        let mut words = checked_payload(exec_words(&SeedCircuit {
            mnemonic: mnemonic.to_vec(),
            salt,
            rounds: 2048,
        }))
        .expect("the BIP-39 seed circuit makes no assertion that can fail");
        let seed = Zeroizing::new(words.u8.clone());
        words.u8.zeroize();
        seed
    }

    /// Splits a BIP-32 master or child circuit output into a [Node].
    fn bip32_node_of(words: Words) -> Node {
        // 🚨 The assertion word is checked and removed before anything is sliced.
        let mut words = checked_payload(words)
            .expect("a BIP-32 derivation step asserted a non-finite public key");
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

    /// Walks the BIP-32/secp256k1 tree from a seed down a path.
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

    /// Walks the SLIP-10/ed25519 tree from a seed down a path, every component of
    /// which must be hardened.
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

    fn slip10_node_of(words: Words) -> Node {
        let mut words = checked_payload(words)
            .expect("the SLIP-10 derivation circuits make no assertion that can fail");
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
    use proofofseed_circuits::{
        comb::ComputedComb, HardenedChildCircuit, MasterKeyCircuit, NormalChildCircuit,
        PubKeyCircuit, Slip10ChildCircuit,
    };
    use std::collections::BTreeSet;
    use zkboo::Repetitions;
    use core::cell::RefCell;
    use zkboo::prover::challenge::ChallengeBuilder;
    use zkboo::prover::proof::{ProofOptions, build_proof};
    use zkboo::prover::views::collectors::{ViewCommitmentsRelayer, ViewsDataCollector};
    use zkboo::prover::views::ViewCommitment;

    type PS = HashPRG<H>;

    /// A challenge-phase collector mirroring the app's `ChallengeKeepalive`, which
    /// relays the genuine commitments and counts AND-gate calls without feeding a hasher.
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

    /// [gen_stream], driving the challenge phase through [CountingRelayer].
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
        let _: Vec<()> = build_proof::<C, H, PS, PV, S, VecSink, WTP, _>(
            circuit,
            seed_entropy,
            challenge_entropy,
            n,
            ProofOptions::new().with_collector_arg::<VecSink>(&out),
        );
        out.into_inner()
    }

    /// An observing challenge-phase collector leaves the emitted proof bytes identical
    /// to the default-relayer path.
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
    fn a_proofs_size_is_bimodal_in_the_challenge_by_the_input_share() {
        // A response carries party 2's input share only for challenges 1 and 2, so a
        // one-response proof has exactly two possible sizes and they differ by the input
        // share. This is not noise and it is not drift: an off-device size estimate drawn
        // from one fixed seed will disagree with a device that drew the other branch, by
        // that exact amount. Recording it as "run-to-run variation" understates it —
        // the magnitude is a property of the circuit's witness, and is predictable.
        let seed = vec![0xA5u8; 16];
        let circuit = MasterKeyCircuit { seed: seed.clone() };
        let sizes: BTreeSet<usize> = (0u8..24)
            .map(|i| gen_stream(&circuit, 1, &[i], b"binding").len())
            .collect();
        assert_eq!(sizes.len(), 2, "expected exactly two sizes, got {sizes:?}");
        let (small, large) = (*sizes.iter().next().unwrap(), *sizes.iter().last().unwrap());
        assert_eq!(
            large - small,
            seed.len(),
            "the two sizes must differ by the input share, i.e. the witness length"
        );
    }

    #[test]
    fn supplied_key_statement_outputs_are_what_a_verifier_must_hold() {
        // Both output helpers exist because a device proves against a key the host cannot
        // compile in. What has to be true of them is not that they return bytes but that
        // they return *the* bytes a verifier holds: a proof made with the supplied key
        // verifies against them, and one made with a neighbouring key does not. Without
        // the second half this passes for a helper that returns any fixed circuit's
        // output, which is exactly the failure the benchmark's `verified: None` rows hid.
        // 16 responses: the refusal of a neighbouring parent's output is ZKBoo's own
        // soundness, accepted with probability about 3^-n, so a small count makes the
        // negative a coin flip rather than a check.
        let cc = [7u8; 32];
        let key = [3u8; 32];
        let other = [4u8; 32];
        let hardened = 0x8000_0005u32;

        let real = HardenedChildCircuit {
            chain_code: cc.to_vec(),
            parent_priv: key.to_vec(),
            index: hardened,
        };
        let stream = gen_stream(&real, 16, b"e", b"tx");
        let expected = hardened_child_statement_output(0, &key, &cc, hardened).unwrap();
        assert_eq!(expected, output_of(&real), "helper must execute the real circuit");
        assert!(
            verify(HARDENED_CHILD, &expected, &stream, 16, b"tx", 0, Some(&cc), Some(hardened), 0),
            "hardened child should verify against the supplied parent's output"
        );
        let wrong = hardened_child_statement_output(0, &other, &cc, hardened).unwrap();
        assert_ne!(wrong, expected, "a different parent must give a different output");
        assert!(
            !verify(HARDENED_CHILD, &wrong, &stream, 16, b"tx", 0, Some(&cc), Some(hardened), 0),
            "a neighbouring parent's output must be rejected"
        );

        let sl = Slip10ChildCircuit {
            chain_code: cc.to_vec(),
            parent_priv: key.to_vec(),
            index: hardened,
        };
        let sl_stream = gen_stream(&sl, 16, b"e", b"tx");
        let sl_expected = hardened_child_statement_output(1, &key, &cc, hardened).unwrap();
        assert_ne!(sl_expected, expected, "the two families are different circuits");
        assert!(
            verify(
                HARDENED_CHILD, &sl_expected, &sl_stream, 16, b"tx", 0, Some(&cc),
                Some(hardened), 1
            ),
            "slip-10 child should verify against the supplied parent's output"
        );

        assert!(
            hardened_child_statement_output(2, &key, &cc, hardened).is_none(),
            "an unknown family has no output"
        );
    }

    #[test]
    fn curve_statement_outputs_for_a_supplied_key_verify_a_real_proof() {
        // The same check for the curve statements, which the benchmark also recorded as
        // unverified until their outputs could be derived. Eight responses, not the one
        // this used to use: the positive needs no more than one, but the negative is
        // ZKBoo's own soundness, and a wrong output is accepted about 3^-n of the time —
        // at one response that is better than one run in four.
        let key = [3u8; 32];
        let other = [4u8; 32];
        let cc = [7u8; 32];

        let pk = PubKeyCircuit::<ComputedComb>::new(key.to_vec());
        let pk_stream = gen_stream(&pk, 8, b"e", b"tx");
        let pk_expected = curve_statement_output(PUBLIC_KEY, &key, None, None).unwrap();
        assert!(
            verify(PUBLIC_KEY, &pk_expected, &pk_stream, 8, b"tx", 0, None, None, 0),
            "public key should verify against the supplied key's output"
        );
        let pk_wrong = curve_statement_output(PUBLIC_KEY, &other, None, None).unwrap();
        assert_ne!(pk_wrong, pk_expected);
        assert!(
            !verify(PUBLIC_KEY, &pk_wrong, &pk_stream, 8, b"tx", 0, None, None, 0),
            "a neighbouring key's public key must be rejected"
        );

        let nc = NormalChildCircuit::<ComputedComb>::new(cc.to_vec(), key.to_vec(), 0);
        let nc_stream = gen_stream(&nc, 8, b"e", b"tx");
        let nc_expected =
            curve_statement_output(NORMAL_CHILD, &key, Some(&cc), Some(0)).unwrap();
        assert!(
            verify(NORMAL_CHILD, &nc_expected, &nc_stream, 8, b"tx", 0, Some(&cc), Some(0), 0),
            "normal child should verify against the supplied parent's output"
        );

        assert!(
            curve_statement_output(MASTER_KEY, &key, None, None).is_none(),
            "a non-curve statement has no curve output"
        );
        assert!(
            curve_statement_output(NORMAL_CHILD, &key, None, None).is_none(),
            "the normal child needs its public parameters"
        );
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
        // zkboo 1.3.0 states the same count from the post-quantum security level, by a
        // rational approximation where this crate divides floating-point logarithms.
        // Its argument is post-quantum bits, so 128 there is the 256 above.
        assert_eq!(n_eps(256), Repetitions::for_pq_security_bits(128).count());
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
        use proofofseed_circuits::{
            EXPECTED_HARDENED_CC, EXPECTED_HARDENED_PRIV, EXPECTED_MASTER, checked_payload,
        };
        let to_hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let master = checked_payload(super::harness::exec_words(&master_key_circuit()))
            .expect("master-key assertions hold");
        assert_eq!(to_hex(&master.u8), EXPECTED_MASTER);
        let child = checked_payload(super::harness::exec_words(&hardened_child_circuit()))
            .expect("hardened-child assertions hold");
        assert_eq!(to_hex(&child.u8), EXPECTED_HARDENED_CC);
        let priv_be: Vec<u8> =
            child.u64.iter().rev().flat_map(|l| l.to_be_bytes()).collect();
        assert_eq!(to_hex(&priv_be), EXPECTED_HARDENED_PRIV);
    }
}
