// SPDX-License-Identifier: LGPL-3.0-or-later

//! The ProofofSeed statements as ZKBoo circuits, each paired with a canonical test
//! vector, and the verifier-side constructors that rebuild them from public parameters.

#![no_std]
extern crate alloc;

pub mod comb;
pub mod hasher;
pub mod ranged;
pub mod request;

use alloc::vec::Vec;
use core::marker::PhantomData;

use zeroize::Zeroize;

use comb::{CombTableSource, ComputedComb};
use zkboo::backend::{Backend, Frontend};
use zkboo::circuit::{Assertions, Circuit};
use zkboo::word::{CompositeWord, Words};
use zkboo_bip32::{
    be_bytes_to_word, bip39_seed_with_salt_words, ethereum_address_with_tables,
    hardened_child_key, master_key, normal_child_key_with_tables,
    public_key_affine_with_tables, slip10_ed25519_child, slip10_ed25519_master,
    HARDENED_OFFSET,
};
use zkboo_modular::montgomery::MontgomeryFrontendIO;

/// Statement identifiers (the `P1` byte on the wire).
pub const MASTER_KEY: u8 = 0;
pub const HARDENED_CHILD: u8 = 1;
pub const BIP39_SEED: u8 = 2;
pub const PUBLIC_KEY: u8 = 3;
pub const NORMAL_CHILD: u8 = 4;
pub const ETH_ADDRESS: u8 = 5;

/// Whether a statement needs secp256k1 scalar multiplication.
pub fn is_elephant(statement: u8) -> bool {
    matches!(statement, PUBLIC_KEY | NORMAL_CHILD | ETH_ADDRESS)
}

/// Serialises a circuit's public output for transport to the host, as
/// `u8_len(2) ‖ u8 bytes ‖ u32_len(2) ‖ u32 words (LE) ‖ u64_len(2) ‖ u64 words (LE)`
/// with big-endian lengths.
pub fn serialize_words(w: &Words) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(w.u8.len() as u16).to_be_bytes());
    out.extend_from_slice(&w.u8);
    out.extend_from_slice(&(w.u32.len() as u16).to_be_bytes());
    for &x in &w.u32 {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.extend_from_slice(&(w.u64.len() as u16).to_be_bytes());
    for &x in &w.u64 {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

/// The value the assertion word carries when every in-circuit assertion held.
pub const ASSERTION_TRUE: u8 = 1;

/// Removes a circuit's trailing assertion word, returning the payload only when every
/// assertion held.
///
/// 🚨 The only correct way to read a circuit's outputs as values; see
/// `knowledge/assertion-word.md`.
pub fn checked_payload(mut words: Words) -> Option<Words> {
    let assertion = words.u8.pop()?;
    (assertion == ASSERTION_TRUE).then_some(words)
}

// ---------------------------------------------------------------------------
// Test vectors (BIP-32 vector 1, BIP-39 Trezor vector).
// ---------------------------------------------------------------------------

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f";
const MASTER_PRIV_HEX: &str = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
const MASTER_CC_HEX: &str = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
const M0H_CC_HEX: &str = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141";
const M0H_PRIV_HEX: &str = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea";
const MNEMONIC: &[u8] =
    b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BIP39_SALT: &[u8] = b"mnemonicTREZOR";

// SLIP-0010 ed25519 test vector 1 (its seed is the same hex as BIP-32 vector 1's):
// the master node and the hardened child m/0'.
const SLIP10_MASTER_PRIV_HEX: &str =
    "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7";
const SLIP10_MASTER_CC_HEX: &str =
    "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb";

/// secp256k1 private key `n`, 32 big-endian bytes.
fn private_key(n: u8) -> Vec<u8> {
    let mut k = alloc::vec![0u8; 32];
    k[31] = n;
    k
}

/// The scalar a 32-byte big-endian private key denotes.
fn scalar_of(private_key: &[u8]) -> CompositeWord<u64, 4> {
    assert_eq!(private_key.len(), PRIV_KEY_BYTES, "private key must be 32 bytes");
    CompositeWord::from_be_bytes(core::array::from_fn(|i| {
        core::array::from_fn(|j| private_key[8 * i + j])
    }))
}

/// Emits the trailing assertion word of a circuit that asserts nothing.
pub fn assert_nothing<B: Backend>(frontend: &Frontend<B>) {
    Assertions::scope(frontend, |_| {});
}

// ---------------------------------------------------------------------------
// Circuits (each mirrors its zkboo-bip32 test wrapper).
// ---------------------------------------------------------------------------

/// Volatile-zeroes each named secret field when the circuit is dropped.
macro_rules! zeroize_on_drop {
    ($circuit:ident: $($secret:ident),+) => {
        impl Drop for $circuit {
            fn drop(&mut self) {
                $(self.$secret.zeroize();)+
            }
        }
    };
    // The elliptic-curve circuits carry a comb-table source parameter.
    (<$g:ident> $circuit:ident: $($secret:ident),+) => {
        impl<$g: $crate::comb::CombTableSource> Drop for $circuit<$g> {
            fn drop(&mut self) {
                $(self.$secret.zeroize();)+
            }
        }
    };
}

/// BIP-32 master private key and chain code from a seed. Output: 64 u8 (IL ‖ IR).
pub struct MasterKeyCircuit {
    pub seed: Vec<u8>,
}
zeroize_on_drop!(MasterKeyCircuit: seed);

impl Circuit for MasterKeyCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let seed = self.seed.iter().map(|&b| frontend.input(b)).collect::<Vec<_>>();
        let (il, ir) = master_key(frontend.allocator(), seed);
        il.into_iter().for_each(|w| frontend.output(w));
        ir.into_iter().for_each(|w| frontend.output(w));
        assert_nothing(frontend);
    }
}

/// BIP-32 hardened child key. Output: 4 u64 (child key) + 32 u8 (chain code).
pub struct HardenedChildCircuit {
    pub chain_code: Vec<u8>,
    pub parent_priv: Vec<u8>,
    pub index: u32,
}
zeroize_on_drop!(HardenedChildCircuit: parent_priv);

impl Circuit for HardenedChildCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let chain_code = self
            .chain_code
            .iter()
            .map(|&b| frontend.alloc(b))
            .collect::<Vec<_>>();
        let parent_priv = self
            .parent_priv
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let (child_priv, child_chain_code) =
            hardened_child_key(frontend.allocator(), chain_code, parent_priv, self.index);
        frontend.output(child_priv);
        child_chain_code.into_iter().for_each(|w| frontend.output(w));
        assert_nothing(frontend);
    }
}

/// BIP-32 normal (non-hardened) child key, generic over the comb's table source.
/// Output: 4 u64 (child key) + 32 u8 (chain code).
pub struct NormalChildCircuit<T: CombTableSource = ComputedComb> {
    pub chain_code: Vec<u8>,
    pub parent_priv: Vec<u8>,
    pub index: u32,
    mirror_scalar: bool,
    tables: PhantomData<T>,
}
zeroize_on_drop!(<T> NormalChildCircuit: parent_priv);

impl<T: CombTableSource> NormalChildCircuit<T> {
    /// The prover's circuit: the comb follows the parent key.
    pub fn new(chain_code: Vec<u8>, parent_priv: Vec<u8>, index: u32) -> Self {
        Self { chain_code, parent_priv, index, mirror_scalar: true, tables: PhantomData }
    }

    /// The verifier's circuit: the comb has no scalar to follow.
    pub fn shaped(chain_code: Vec<u8>, parent_priv: Vec<u8>, index: u32) -> Self {
        Self { chain_code, parent_priv, index, mirror_scalar: false, tables: PhantomData }
    }

    /// The scalar the comb mirrors on the host, absent when verifying.
    fn scalar(&self) -> Option<CompositeWord<u64, 4>> {
        self.mirror_scalar.then(|| scalar_of(&self.parent_priv))
    }
}

impl<T: CombTableSource> Circuit for NormalChildCircuit<T> {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        Assertions::scope(frontend, |assertions| {
            let chain_code = self
                .chain_code
                .iter()
                .map(|&b| frontend.alloc(b))
                .collect::<Vec<_>>();
            let parent_priv = self
                .parent_priv
                .iter()
                .map(|&b| frontend.input(b))
                .collect::<Vec<_>>();
            let mut tables = T::make();
            let (child_priv, child_chain_code) = normal_child_key_with_tables(
                frontend,
                chain_code,
                parent_priv,
                self.scalar(),
                self.index,
                &mut tables,
                assertions,
            );
            frontend.output(child_priv);
            child_chain_code.into_iter().for_each(|w| frontend.output(w));
        });
    }
}

/// BIP-39 seed via PBKDF2-HMAC-SHA512, with the salt as witness rather than a public
/// parameter. Output: 64 u8.
pub struct SeedCircuit {
    pub mnemonic: Vec<u8>,
    pub salt: Vec<u8>,
    pub rounds: usize,
}
zeroize_on_drop!(SeedCircuit: mnemonic, salt);

impl Circuit for SeedCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let mnemonic = self
            .mnemonic
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let salt = self.salt.iter().map(|&b| frontend.input(b)).collect::<Vec<_>>();
        let seed =
            bip39_seed_with_salt_words(frontend.allocator(), mnemonic, salt, self.rounds);
        seed.into_iter().for_each(|w| frontend.output(w));
        assert_nothing(frontend);
    }
}

/// secp256k1 public key `d·G`, generic over the comb's table source.
/// Output: 8 u64 (affine x ‖ y, 4 limbs each).
pub struct PubKeyCircuit<T: CombTableSource = ComputedComb> {
    pub private_key: Vec<u8>,
    mirror_scalar: bool,
    tables: PhantomData<T>,
}
zeroize_on_drop!(<T> PubKeyCircuit: private_key);

impl<T: CombTableSource> PubKeyCircuit<T> {
    /// The prover's circuit: the comb follows the key.
    pub fn new(private_key: Vec<u8>) -> Self {
        Self { private_key, mirror_scalar: true, tables: PhantomData }
    }

    /// The verifier's circuit: the comb has no scalar to follow.
    pub fn shaped(private_key: Vec<u8>) -> Self {
        Self { private_key, mirror_scalar: false, tables: PhantomData }
    }

    /// The scalar the comb mirrors on the host, absent when verifying.
    fn scalar(&self) -> Option<CompositeWord<u64, 4>> {
        self.mirror_scalar.then(|| scalar_of(&self.private_key))
    }
}

impl<T: CombTableSource> Circuit for PubKeyCircuit<T> {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        Assertions::scope(frontend, |assertions| {
            let bytes = self
                .private_key
                .iter()
                .map(|&b| frontend.input(b))
                .collect::<Vec<_>>();
            let scalar = be_bytes_to_word(&bytes);
            let mut tables = T::make();
            let (x, y) = public_key_affine_with_tables(
                frontend,
                scalar,
                self.scalar(),
                &mut tables,
                assertions,
            );
            frontend.montgomery_output(x);
            frontend.montgomery_output(y);
        });
    }
}

/// SLIP-10 ed25519 master key and chain code from a seed. Output: 64 u8 (IL ‖ IR).
pub struct Slip10MasterCircuit {
    pub seed: Vec<u8>,
}
zeroize_on_drop!(Slip10MasterCircuit: seed);

impl Circuit for Slip10MasterCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let seed = self.seed.iter().map(|&b| frontend.input(b)).collect::<Vec<_>>();
        let (il, ir) = slip10_ed25519_master(frontend.allocator(), seed);
        il.into_iter().for_each(|w| frontend.output(w));
        ir.into_iter().for_each(|w| frontend.output(w));
        assert_nothing(frontend);
    }
}

/// SLIP-10 ed25519 hardened child key, whose `index` is the wire value and must carry
/// the hardened bit. Output: 64 u8 (child key ‖ chain code).
pub struct Slip10ChildCircuit {
    pub chain_code: Vec<u8>,
    pub parent_priv: Vec<u8>,
    pub index: u32,
}
zeroize_on_drop!(Slip10ChildCircuit: parent_priv);

impl Circuit for Slip10ChildCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        assert!(self.index & HARDENED_OFFSET != 0, "SLIP-10 ed25519 children are hardened-only");
        assert_eq!(self.chain_code.len(), 32, "chain code length");
        assert_eq!(self.parent_priv.len(), 32, "parent key length");
        let chain_code: [_; 32] = core::array::from_fn(|i| frontend.alloc(self.chain_code[i]));
        let parent_priv: [_; 32] = core::array::from_fn(|i| frontend.input(self.parent_priv[i]));
        let (child_priv, child_chain_code) = slip10_ed25519_child(
            frontend.allocator(),
            &parent_priv,
            &chain_code,
            self.index & !HARDENED_OFFSET,
        );
        child_priv.into_iter().for_each(|w| frontend.output(w));
        child_chain_code.into_iter().for_each(|w| frontend.output(w));
        assert_nothing(frontend);
    }
}

/// Ethereum address `Keccak256(d·G)[12:]`, generic over the comb's table source.
/// Output: 20 u8.
pub struct AddressCircuit<T: CombTableSource = ComputedComb> {
    pub private_key: Vec<u8>,
    mirror_scalar: bool,
    tables: PhantomData<T>,
}
zeroize_on_drop!(<T> AddressCircuit: private_key);

impl<T: CombTableSource> AddressCircuit<T> {
    /// The prover's circuit: the comb follows the key.
    pub fn new(private_key: Vec<u8>) -> Self {
        Self { private_key, mirror_scalar: true, tables: PhantomData }
    }

    /// The verifier's circuit: the comb has no scalar to follow.
    pub fn shaped(private_key: Vec<u8>) -> Self {
        Self { private_key, mirror_scalar: false, tables: PhantomData }
    }

    /// The scalar the comb mirrors on the host, absent when verifying.
    fn scalar(&self) -> Option<CompositeWord<u64, 4>> {
        self.mirror_scalar.then(|| scalar_of(&self.private_key))
    }
}

impl<T: CombTableSource> Circuit for AddressCircuit<T> {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        Assertions::scope(frontend, |assertions| {
            let bytes = self
                .private_key
                .iter()
                .map(|&b| frontend.input(b))
                .collect::<Vec<_>>();
            let scalar = be_bytes_to_word(&bytes);
            let mut tables = T::make();
            let address = ethereum_address_with_tables(
                frontend,
                scalar,
                self.scalar(),
                &mut tables,
                assertions,
            );
            address.into_iter().for_each(|w| frontend.output(w));
        });
    }
}

// ---------------------------------------------------------------------------
// Constructors with the canonical test vectors (shared by prover and verifier).
// ---------------------------------------------------------------------------

pub fn master_key_circuit() -> MasterKeyCircuit {
    MasterKeyCircuit { seed: from_hex(SEED_HEX) }
}

pub fn hardened_child_circuit() -> HardenedChildCircuit {
    HardenedChildCircuit {
        chain_code: from_hex(MASTER_CC_HEX),
        parent_priv: from_hex(MASTER_PRIV_HEX),
        index: HARDENED_OFFSET,
    }
}

pub fn normal_child_circuit() -> NormalChildCircuit {
    NormalChildCircuit::new(from_hex(M0H_CC_HEX), from_hex(M0H_PRIV_HEX), 1)
}

pub fn bip39_seed_circuit(rounds: usize) -> SeedCircuit {
    SeedCircuit {
        mnemonic: MNEMONIC.to_vec(),
        salt: BIP39_SALT.to_vec(),
        rounds,
    }
}

pub fn slip10_master_circuit() -> Slip10MasterCircuit {
    Slip10MasterCircuit { seed: from_hex(SEED_HEX) }
}

pub fn slip10_child_circuit() -> Slip10ChildCircuit {
    Slip10ChildCircuit {
        chain_code: from_hex(SLIP10_MASTER_CC_HEX),
        parent_priv: from_hex(SLIP10_MASTER_PRIV_HEX),
        index: HARDENED_OFFSET,
    }
}

pub fn public_key_circuit() -> PubKeyCircuit {
    PubKeyCircuit::new(private_key(1))
}

pub fn ethereum_address_circuit() -> AddressCircuit {
    AddressCircuit::new(private_key(1))
}

// ---------------------------------------------------------------------------
// Verifier-side constructors. See knowledge/verifier-circuits.md.
// ---------------------------------------------------------------------------

/// The secp256k1 private-key witness length in bytes.
pub const PRIV_KEY_BYTES: usize = 32;

fn placeholder_priv() -> Vec<u8> {
    alloc::vec![0u8; PRIV_KEY_BYTES]
}

/// Master-key verifier circuit for a witness of the given byte length.
pub fn master_key_verify_circuit(seed_len: usize) -> MasterKeyCircuit {
    MasterKeyCircuit { seed: alloc::vec![0u8; seed_len] }
}

/// SLIP-10 master-key verifier circuit for a witness of the given byte length.
pub fn slip10_master_verify_circuit(seed_len: usize) -> Slip10MasterCircuit {
    Slip10MasterCircuit { seed: alloc::vec![0u8; seed_len] }
}

/// BIP-39 seed verifier circuit for a mnemonic and a salt of the given byte lengths.
pub fn bip39_seed_verify_circuit(
    mnemonic_len: usize,
    salt_len: usize,
    rounds: usize,
) -> SeedCircuit {
    SeedCircuit {
        mnemonic: alloc::vec![0u8; mnemonic_len],
        salt: alloc::vec![0u8; salt_len],
        rounds,
    }
}

/// The BIP-39 PBKDF2 salt for a passphrase: the constant `"mnemonic"` followed by it.
pub fn bip39_salt_for(passphrase: &[u8]) -> Vec<u8> {
    let mut salt = alloc::vec![b'm', b'n', b'e', b'm', b'o', b'n', b'i', b'c'];
    salt[..8].copy_from_slice(b"mnemonic");
    salt.extend_from_slice(passphrase);
    salt
}

/// Hardened-child verifier circuit for an asserted chain code and index.
pub fn hardened_child_verify_circuit(chain_code: Vec<u8>, index: u32) -> HardenedChildCircuit {
    HardenedChildCircuit { chain_code, parent_priv: placeholder_priv(), index }
}

/// Normal (non-hardened) child verifier circuit.
pub fn normal_child_verify_circuit(chain_code: Vec<u8>, index: u32) -> NormalChildCircuit {
    NormalChildCircuit::shaped(chain_code, placeholder_priv(), index)
}

/// SLIP-10 ed25519 child verifier circuit for an asserted chain code and index.
pub fn slip10_child_verify_circuit(chain_code: Vec<u8>, index: u32) -> Slip10ChildCircuit {
    Slip10ChildCircuit { chain_code, parent_priv: placeholder_priv(), index }
}

/// Public-key verifier circuit.
pub fn public_key_verify_circuit() -> PubKeyCircuit {
    PubKeyCircuit::shaped(placeholder_priv())
}

/// Ethereum-address verifier circuit.
pub fn ethereum_address_verify_circuit() -> AddressCircuit {
    AddressCircuit::shaped(placeholder_priv())
}

/// The structural fingerprint of the circuit a prover would run for a family and
/// statement, or `None` for a pair no prover implements.
///
/// ⚠️ The pass services no io and its cost is linear in the gate count, so a caller on
/// a device with a watchdog must use [statement_fingerprint_hooked]. See
/// `knowledge/circuit-fingerprints.md`.
pub fn statement_fingerprint<T: CombTableSource>(
    family: request::Family,
    statement: u8,
    rounds: usize,
    chain_code: Option<&[u8]>,
    index: Option<u32>,
) -> Option<[u8; 32]> {
    return statement_fingerprint_hooked::<T, zkboo::backend::NoHook>(
        family, statement, rounds, chain_code, index, (),
    );
}

/// [statement_fingerprint] with a [zkboo::backend::BackendHook] wrapping the pass.
pub fn statement_fingerprint_hooked<T: CombTableSource, BH: zkboo::backend::BackendHook>(
    family: request::Family,
    statement: u8,
    rounds: usize,
    chain_code: Option<&[u8]>,
    index: Option<u32>,
    hook_init_arg: BH::InitArg,
) -> Option<[u8; 32]> {
    use request::Family::{Bip32Secp256k1 as B32, Slip10Ed25519 as S10};
    fn fp<BH: zkboo::backend::BackendHook, C: Circuit>(
        arg: BH::InitArg,
        c: &C,
    ) -> Option<[u8; 32]> {
        Some(ranged::circuit_fingerprint_hooked::<C, BH>(c, arg))
    }
    // The canonical test-vector parameters stand in when the request omits them,
    // exactly as the prover dispatch does.
    let cc = |d: &str| chain_code.map(<[u8]>::to_vec).unwrap_or_else(|| from_hex(d));
    match (family, statement) {
        (B32, MASTER_KEY) => fp::<BH, _>(hook_init_arg, &master_key_circuit()),
        (B32, HARDENED_CHILD) => fp::<BH, _>(hook_init_arg, &hardened_child_verify_circuit(
            cc(MASTER_CC_HEX),
            index.unwrap_or(HARDENED_OFFSET),
        )),
        (B32, BIP39_SEED) => fp::<BH, _>(hook_init_arg, &bip39_seed_circuit(rounds)),
        (B32, PUBLIC_KEY) => {
            fp::<BH, _>(hook_init_arg, &PubKeyCircuit::<T>::shaped(placeholder_priv()))
        }
        (B32, NORMAL_CHILD) => fp::<BH, _>(hook_init_arg, &NormalChildCircuit::<T>::shaped(
            cc(M0H_CC_HEX),
            placeholder_priv(),
            index.unwrap_or(1),
        )),
        (B32, ETH_ADDRESS) => {
            fp::<BH, _>(hook_init_arg, &AddressCircuit::<T>::shaped(placeholder_priv()))
        }
        (S10, MASTER_KEY) => fp::<BH, _>(hook_init_arg, &slip10_master_circuit()),
        (S10, HARDENED_CHILD) => fp::<BH, _>(hook_init_arg, &slip10_child_verify_circuit(
            cc(SLIP10_MASTER_CC_HEX),
            index.unwrap_or(HARDENED_OFFSET),
        )),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Expected public outputs (for off-device validation), big-endian hex.
// ---------------------------------------------------------------------------

/// master_key: IL ‖ IR.
pub const EXPECTED_MASTER: &str = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
/// hardened child m/0H: child private key (big-endian).
pub const EXPECTED_HARDENED_PRIV: &str =
    "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea";
pub const EXPECTED_HARDENED_CC: &str =
    "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141";
/// BIP-39 seed (Trezor vector, full 2048 rounds).
pub const EXPECTED_BIP39_SEED: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
/// public key of private key 1 (= generator G): x ‖ y.
pub const EXPECTED_PUBKEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
/// normal child m/0H/1: child private key (big-endian).
pub const EXPECTED_NORMAL_PRIV: &str =
    "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368";
pub const EXPECTED_NORMAL_CC: &str =
    "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19";
/// Ethereum address of private key 1.
pub const EXPECTED_ETH_ADDRESS: &str = "7e5f4552091a69125d5dfcb7b8c2659029395bdf";
/// SLIP-10 ed25519 master (SLIP-0010 vector 1): IL ‖ IR.
pub const EXPECTED_SLIP10_MASTER: &str = "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e790046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb";
/// SLIP-10 ed25519 hardened child m/0' (SLIP-0010 vector 1): child key ‖ chain code.
pub const EXPECTED_SLIP10_CHILD: &str = "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a38b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69";
