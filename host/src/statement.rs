// SPDX-License-Identifier: LGPL-3.0-or-later

//! The single place that resolves a request into a provable circuit, shared by every
//! host frontend and mirroring what the device app does for the same request.

use crate::{derive, harness};
use proofofseed_circuits::ranged::{
    WitnessMaterial, deterministic_seed_entropy, ranged_request_digest,
};
use proofofseed_circuits::request::{Family, ProofRequest};
use proofofseed_circuits::{
    AddressCircuit, BIP39_SEED, ETH_ADDRESS, HARDENED_CHILD, HardenedChildCircuit, MASTER_KEY,
    MasterKeyCircuit, NORMAL_CHILD, NormalChildCircuit, PUBLIC_KEY, PubKeyCircuit, SeedCircuit,
    Slip10ChildCircuit, Slip10MasterCircuit, bip39_seed_circuit, ethereum_address_circuit,
    hardened_child_circuit, master_key_circuit, normal_child_circuit, public_key_circuit,
    slip10_child_circuit, slip10_master_circuit,
};
use zeroize::Zeroizing;
use zkboo_profiling::{ProfilingData, profile};

const HARDENED: u32 = 0x8000_0000;

/// A proof-of-seed statement, family-agnostic.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Statement {
    /// Seed to BIP-32 master key and chain code.
    MasterKey,
    /// Parent key to hardened child key and chain code.
    HardenedChild,
    /// Mnemonic to BIP-39 seed via PBKDF2.
    Bip39Seed,
    /// Private key to secp256k1 public key.
    PublicKey,
    /// Parent key to normal (non-hardened) child.
    NormalChild,
    /// Private key to Ethereum address.
    EthereumAddress,
}

impl Statement {
    pub const ALL: [Statement; 6] = [
        Statement::MasterKey,
        Statement::HardenedChild,
        Statement::Bip39Seed,
        Statement::PublicKey,
        Statement::NormalChild,
        Statement::EthereumAddress,
    ];

    pub fn id(self) -> u8 {
        match self {
            Statement::MasterKey => MASTER_KEY,
            Statement::HardenedChild => HARDENED_CHILD,
            Statement::Bip39Seed => BIP39_SEED,
            Statement::PublicKey => PUBLIC_KEY,
            Statement::NormalChild => NORMAL_CHILD,
            Statement::EthereumAddress => ETH_ADDRESS,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Statement::MasterKey => "master-key",
            Statement::HardenedChild => "hardened-child",
            Statement::Bip39Seed => "bip39-seed",
            Statement::PublicKey => "public-key",
            Statement::NormalChild => "normal-child",
            Statement::EthereumAddress => "ethereum-address",
        }
    }

    pub fn from_name(name: &str) -> Option<Statement> {
        Statement::ALL.into_iter().find(|s| s.name() == name)
    }

    /// Whether the statement's public output is itself secret key material.
    pub fn output_is_secret(self) -> bool {
        !matches!(self, Statement::PublicKey | Statement::EthereumAddress)
    }
}

/// The wire name of a derivation family.
pub fn family_name(family: Family) -> &'static str {
    match family {
        Family::Bip32Secp256k1 => "bip32-secp256k1",
        Family::Slip10Ed25519 => "slip10-ed25519",
    }
}

pub fn family_from_name(name: &str) -> Option<Family> {
    match name {
        "bip32-secp256k1" => Some(Family::Bip32Secp256k1),
        "slip10-ed25519" => Some(Family::Slip10Ed25519),
        _ => None,
    }
}

/// Whether a family carries a statement.
pub fn check_family(statement: Statement, family: Family) -> Result<(), String> {
    if family == Family::Slip10Ed25519
        && !matches!(statement, Statement::MasterKey | Statement::HardenedChild)
    {
        return Err(format!(
            "family slip10-ed25519 carries only the recovery statements (master-key, \
             hardened-child), not {}",
            statement.name()
        ));
    }
    Ok(())
}

/// A statement circuit with its witness inside, dispatchable without generics.
pub enum AnyCircuit {
    Master(MasterKeyCircuit),
    Seed(SeedCircuit),
    HardenedChild(HardenedChildCircuit),
    NormalChild(NormalChildCircuit),
    PubKey(PubKeyCircuit),
    Address(AddressCircuit),
    Slip10Master(Slip10MasterCircuit),
    Slip10Child(Slip10ChildCircuit),
}

macro_rules! with_circuit {
    ($self:expr, $c:ident => $body:expr) => {
        match $self {
            AnyCircuit::Master($c) => $body,
            AnyCircuit::Seed($c) => $body,
            AnyCircuit::HardenedChild($c) => $body,
            AnyCircuit::NormalChild($c) => $body,
            AnyCircuit::PubKey($c) => $body,
            AnyCircuit::Address($c) => $body,
            AnyCircuit::Slip10Master($c) => $body,
            AnyCircuit::Slip10Child($c) => $body,
        }
    };
}

impl AnyCircuit {
    /// The serialised public output.
    pub fn output(&self) -> Vec<u8> {
        with_circuit!(self, c => harness::output_of(c))
    }

    pub fn profile(&self) -> ProfilingData {
        with_circuit!(self, c => profile(c))
    }

    pub fn entropy_for(&self, digest: &Zeroizing<[u8; 32]>) -> Zeroizing<[u8; 32]> {
        with_circuit!(self, c => deterministic_seed_entropy(c, digest))
    }

    /// Streams a half-open range of an `n`-response proof to a writer.
    pub fn prove_to<W: std::io::Write>(
        &self,
        n: usize,
        range: (usize, usize),
        seed_entropy: &[u8],
        binding: &[u8],
        writer: W,
    ) -> std::io::Result<u64> {
        with_circuit!(self, c => harness::gen_stream_range_to(c, n, range, seed_entropy, binding, writer))
    }

    pub fn gen_stream(&self, n: usize, seed_entropy: &[u8], binding: &[u8]) -> Vec<u8> {
        with_circuit!(self, c => harness::gen_stream(c, n, seed_entropy, binding))
    }
}

/// The canonical test-vector circuit for a statement, for profiling and planning.
pub fn dummy_circuit(
    statement: Statement,
    family: Family,
    rounds: usize,
) -> Result<AnyCircuit, String> {
    check_family(statement, family)?;
    use Family::{Bip32Secp256k1 as B32, Slip10Ed25519 as S10};
    Ok(match (family, statement) {
        (B32, Statement::MasterKey) => AnyCircuit::Master(master_key_circuit()),
        (S10, Statement::MasterKey) => AnyCircuit::Slip10Master(slip10_master_circuit()),
        (B32, Statement::Bip39Seed) => AnyCircuit::Seed(bip39_seed_circuit(rounds)),
        (B32, Statement::HardenedChild) => AnyCircuit::HardenedChild(hardened_child_circuit()),
        (S10, Statement::HardenedChild) => AnyCircuit::Slip10Child(slip10_child_circuit()),
        (B32, Statement::NormalChild) => AnyCircuit::NormalChild(normal_child_circuit()),
        (B32, Statement::PublicKey) => AnyCircuit::PubKey(public_key_circuit()),
        (B32, Statement::EthereumAddress) => AnyCircuit::Address(ethereum_address_circuit()),
        _ => unreachable!("family checked above"),
    })
}

/// Everything a prove or derive run needs, resolved from the seed.
pub struct Resolved {
    pub circuit: AnyCircuit,
    pub request: ProofRequest,
    pub digest: Option<Zeroizing<[u8; 32]>>,
    /// The witness shape of the seed statements: the witness byte length, and the
    /// BIP-39 salt's byte length where there is one.
    pub witness_shape: Option<(usize, Option<usize>)>,
}

/// Inputs to [resolve].
pub struct ResolveParams<'a> {
    pub statement: Statement,
    pub family: Family,
    pub path: Option<Vec<u32>>,
    pub index: Option<u32>,
    pub num_iters: usize,
    pub rounds: usize,
    pub binding: Vec<u8>,
    pub range: Option<(u16, u16)>,
    pub mnemonic: &'a [u8],
    pub passphrase: &'a [u8],
}

/// Derives the witness from the mnemonic and builds the circuit and request.
pub fn resolve(p: ResolveParams<'_>) -> Result<Resolved, String> {
    check_family(p.statement, p.family)?;
    let mut salt = Zeroizing::new(b"mnemonic".to_vec());
    salt.extend_from_slice(p.passphrase);
    let seed = derive::bip39_seed(p.mnemonic, p.passphrase);
    let statement = p.statement;
    let needs_path = !matches!(statement, Statement::MasterKey | Statement::Bip39Seed);
    if !needs_path && (p.path.is_some() || p.index.is_some()) {
        return Err(format!("{} takes no path/index", statement.name()));
    }
    // The key statements take the full key path but no child index: a stray index is
    // absorbed into the deterministic entropy while being ignored by the circuit and
    // the verifier, so two co-provers disagreeing on it would fail to assemble.
    if matches!(statement, Statement::PublicKey | Statement::EthereumAddress) && p.index.is_some() {
        return Err(format!("{} takes a path (the full key path) but no index", statement.name()));
    }
    if p.rounds > u16::MAX as usize {
        return Err(format!("rounds must be at most {} (the wire field is 16-bit)", u16::MAX));
    }
    let mut request = ProofRequest {
        num_iters: p.num_iters,
        rounds: p.rounds,
        family: p.family,
        path: p.path.clone(),
        index: p.index,
        chain_code: None,
        binding: p.binding,
        range: p.range,
    };
    use Family::{Bip32Secp256k1 as B32, Slip10Ed25519 as S10};
    let (circuit, resolved_path, material_owner): (AnyCircuit, Vec<u32>, MaterialOwner) =
        match statement {
            Statement::MasterKey => {
                let circuit = match p.family {
                    B32 => AnyCircuit::Master(MasterKeyCircuit { seed: seed.to_vec() }),
                    S10 => AnyCircuit::Slip10Master(Slip10MasterCircuit { seed: seed.to_vec() }),
                };
                (circuit, Vec::new(), MaterialOwner::Seed { seed: seed.to_vec().into() })
            }
            Statement::Bip39Seed => {
                let circuit = AnyCircuit::Seed(SeedCircuit {
                    mnemonic: p.mnemonic.to_vec(),
                    salt: salt.to_vec(),
                    rounds: p.rounds,
                });
                (
                    circuit,
                    Vec::new(),
                    MaterialOwner::Mnemonic {
                        mnemonic: Zeroizing::new(p.mnemonic.to_vec()),
                        salt: salt.clone(),
                    },
                )
            }
            Statement::HardenedChild | Statement::NormalChild => {
                let parent_path = p.path.clone().ok_or("path (the PARENT path) is required")?;
                let index = p.index.ok_or("index (the child index) is required")?;
                let hardened_stmt = statement == Statement::HardenedChild;
                if (index & HARDENED != 0) != hardened_stmt {
                    return Err(format!(
                        "{} requires a {} child index",
                        statement.name(),
                        if hardened_stmt { "hardened" } else { "non-hardened" }
                    ));
                }
                let node = match p.family {
                    B32 => derive::bip32_node(&seed, &parent_path),
                    S10 => derive::slip10_node(&seed, &parent_path)
                        .ok_or("slip10 paths must be fully hardened")?,
                };
                request.chain_code = Some(node.chain_code);
                let circuit = match (p.family, hardened_stmt) {
                    (B32, true) => AnyCircuit::HardenedChild(HardenedChildCircuit {
                        chain_code: node.chain_code.to_vec(),
                        parent_priv: node.private_key.to_vec(),
                        index,
                    }),
                    (B32, false) => AnyCircuit::NormalChild(NormalChildCircuit::new(
                        node.chain_code.to_vec(),
                        node.private_key.to_vec(),
                        index,
                    )),
                    (S10, true) => AnyCircuit::Slip10Child(Slip10ChildCircuit {
                        chain_code: node.chain_code.to_vec(),
                        parent_priv: node.private_key.to_vec(),
                        index,
                    }),
                    (S10, false) => unreachable!("hardness checked above"),
                };
                (
                    circuit,
                    parent_path,
                    MaterialOwner::Child {
                        parent_priv: node.private_key.to_vec().into(),
                        chain_code: node.chain_code,
                        index,
                    },
                )
            }
            Statement::PublicKey | Statement::EthereumAddress => {
                let full_path = p.path.clone().ok_or("path (the full key path) is required")?;
                let node = derive::bip32_node(&seed, &full_path);
                let circuit = if statement == Statement::PublicKey {
                    AnyCircuit::PubKey(PubKeyCircuit::new(node.private_key.to_vec()))
                } else {
                    AnyCircuit::Address(AddressCircuit::new(node.private_key.to_vec()))
                };
                (
                    circuit,
                    full_path,
                    MaterialOwner::Priv { private_key: node.private_key.to_vec().into() },
                )
            }
        };
    let digest = request.range.map(|_| {
        let material = material_owner.borrow();
        ranged_request_digest(statement.id(), &request, &resolved_path, material)
    });
    // The seed statements allocate one circuit input per witness byte, so their shape
    // travels to the verifier with the proof; see knowledge/verifier-circuits.md.
    let witness_shape = match &material_owner {
        MaterialOwner::Seed { seed } => Some((seed.len(), None)),
        MaterialOwner::Mnemonic { mnemonic, salt } => Some((mnemonic.len(), Some(salt.len()))),
        _ => None,
    };
    Ok(Resolved { circuit, request, digest, witness_shape })
}

/// Owned witness material, zeroized on drop.
enum MaterialOwner {
    Seed { seed: Zeroizing<Vec<u8>> },
    Mnemonic { mnemonic: Zeroizing<Vec<u8>>, salt: Zeroizing<Vec<u8>> },
    Child { parent_priv: Zeroizing<Vec<u8>>, chain_code: [u8; 32], index: u32 },
    Priv { private_key: Zeroizing<Vec<u8>> },
}

impl MaterialOwner {
    fn borrow(&self) -> WitnessMaterial<'_> {
        match self {
            MaterialOwner::Seed { seed } => WitnessMaterial::Seed { seed },
            MaterialOwner::Mnemonic { mnemonic, salt } => {
                WitnessMaterial::Mnemonic { mnemonic, salt }
            }
            MaterialOwner::Child { parent_priv, chain_code, index } => WitnessMaterial::Child {
                parent_priv,
                chain_code,
                index: *index,
            },
            MaterialOwner::Priv { private_key } => WitnessMaterial::Priv { private_key },
        }
    }
}

/// Fresh 32-byte prover entropy from the operating system.
pub fn fresh_entropy() -> Result<Zeroizing<[u8; 32]>, String> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *entropy).map_err(|e| format!("OS randomness failed: {e}"))?;
    Ok(entropy)
}
