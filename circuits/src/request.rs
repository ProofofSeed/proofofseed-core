// SPDX-License-Identifier: LGPL-3.0-or-later

//! The proof/exec request wire format, shared by the on-device parser and the host
//! tests — the same code parses on both sides, so the format cannot drift and the
//! strict-parse behaviour is testable without a device.

use alloc::vec::Vec;

/// Default BIP-39 PBKDF2 rounds when the host does not specify one.
pub const DEFAULT_BIP39_ROUNDS: usize = 2048;

/// Bounds on the host-requested repetition count.
pub const MIN_ITERS: u16 = 1;
pub const MAX_ITERS: u16 = 512;

/// Flag bits announcing which optional fields follow the request prefix. Bit 3 is
/// reserved (claimed by the parked mnemonic-entry ceremony line) and rejected here.
pub const REQ_FLAG_PATH: u8 = 1 << 0;
pub const REQ_FLAG_INDEX_CC: u8 = 1 << 1;
pub const REQ_FLAG_BINDING: u8 = 1 << 2;
pub const REQ_FLAG_FAMILY: u8 = 1 << 4;
pub const REQ_FLAG_RANGE: u8 = 1 << 5;

/// The derivation family a request selects: which master/child derivation the
/// statement ids refer to. The statement semantics (master key, hardened child, …)
/// are identical across families — only the derivation constants and curve differ.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum Family {
    /// BIP-32 over secp256k1 (`"Bitcoin seed"` master constant): Bitcoin, Ethereum
    /// and all EVM chains, and the wider BIP-44 ecosystem. The default.
    #[default]
    Bip32Secp256k1 = 0,
    /// SLIP-10 over ed25519 (`"ed25519 seed"` master constant, hardened-only,
    /// child = `I_L` directly): Solana, TON, NEAR, and others.
    Slip10Ed25519 = 1,
}

impl Family {
    /// Decodes the wire byte; `None` for an unknown family.
    pub fn from_wire(byte: u8) -> Option<Family> {
        match byte {
            0 => Some(Family::Bip32Secp256k1),
            1 => Some(Family::Slip10Ed25519),
            _ => None,
        }
    }
}

/// A proof/exec request: how many responses, BIP-39 rounds, the derivation family,
/// the optional request-anchored derivation parameters (witness path, and for the
/// child statements the asserted child index and parent chain code), the proof
/// binding, and the optional response range. Absent fields fall back to the
/// per-statement defaults (and an empty binding, the BIP-32/secp256k1 family, and
/// the full response sequence).
#[derive(Default)]
pub struct ProofRequest {
    pub num_iters: usize,
    pub rounds: usize,
    pub family: Family,
    pub path: Option<Vec<u32>>,
    pub index: Option<u32>,
    pub chain_code: Option<[u8; 32]>,
    pub binding: Vec<u8>,
    /// The half-open range `[start, end)` of response indices to emit, out of the
    /// full `num_iters`-response sequence the Fiat-Shamir challenge is computed
    /// over. `None` (no [REQ_FLAG_RANGE]) emits the full sequence with fresh TRNG
    /// prover entropy; `Some` — including the explicit full range — switches the
    /// prover to the deterministic entropy of [crate::ranged], so ranges produced
    /// by separate runs or devices assemble into one verifying proof.
    pub range: Option<(u16, u16)>,
}

/// Reads a big-endian u16 at `off` from `data`, if present.
fn be_u16(data: &[u8], off: usize) -> Option<u16> {
    if data.len() >= off + 2 {
        Some(((data[off] as u16) << 8) | data[off + 1] as u16)
    } else {
        None
    }
}

/// Parses the request data (all integers big-endian): `num_iters(2)` (present in every
/// request; Exec ignores it), then optionally `rounds(2)`, then optionally a `flags(1)`
/// byte announcing the optional fields. [REQ_FLAG_FAMILY] announces a derivation
/// `family(1)` byte that follows the flags byte immediately (it selects how the other
/// fields are interpreted, so it precedes them); the remaining fields follow in flag-bit
/// order: [REQ_FLAG_PATH] a witness path (`u8` count, then that many `u32` components),
/// [REQ_FLAG_INDEX_CC] an asserted child `index(4)` and parent `chain_code(32)`,
/// [REQ_FLAG_BINDING] the proof binding (`u8` length, then that many bytes),
/// [REQ_FLAG_RANGE] the response range `start(2)` and `end(2)` (half-open, and
/// `start < end <= num_iters` — checked against the clamped count on proof requests;
/// Exec ignores `num_iters` and the range alike, so only `start < end` is checked
/// there). An empty
/// buffer or a prefix alone yields the defaults; a buffer that declares more than it
/// carries, sets unknown flag bits, carries an unknown family byte, carries an
/// out-of-order or overlong range, or carries
/// undeclared trailing bytes is malformed and rejected (`None`) — a request-anchored
/// proof must never silently fall back to defaults on a field the host thought it sent.
pub fn parse_proof_request(data: &[u8], with_num_iters: bool) -> Option<ProofRequest> {
    let num_iters = if with_num_iters {
        be_u16(data, 0).unwrap_or(8).clamp(MIN_ITERS, MAX_ITERS) as usize
    } else {
        0
    };
    let rounds = be_u16(data, 2).map_or(DEFAULT_BIP39_ROUNDS, |r| r as usize);
    let mut req = ProofRequest { num_iters, rounds, ..Default::default() };
    match data.len() {
        0 | 2 | 4 => return Some(req),
        1 | 3 => return None,
        _ => {}
    }
    let flags = data[4];
    let known =
        REQ_FLAG_PATH | REQ_FLAG_INDEX_CC | REQ_FLAG_BINDING | REQ_FLAG_FAMILY | REQ_FLAG_RANGE;
    if flags & !known != 0 {
        return None;
    }
    let mut off = 5;
    if flags & REQ_FLAG_FAMILY != 0 {
        req.family = Family::from_wire(*data.get(off)?)?;
        off += 1;
    }
    if flags & REQ_FLAG_PATH != 0 {
        let count = *data.get(off)? as usize;
        off += 1;
        let mut path = Vec::with_capacity(count);
        for _ in 0..count {
            path.push(u32::from_be_bytes(data.get(off..off + 4)?.try_into().ok()?));
            off += 4;
        }
        req.path = Some(path);
    }
    if flags & REQ_FLAG_INDEX_CC != 0 {
        req.index = Some(u32::from_be_bytes(data.get(off..off + 4)?.try_into().ok()?));
        off += 4;
        req.chain_code = Some(data.get(off..off + 32)?.try_into().ok()?);
        off += 32;
    }
    if flags & REQ_FLAG_BINDING != 0 {
        let len = *data.get(off)? as usize;
        off += 1;
        req.binding = data.get(off..off + len)?.to_vec();
        off += len;
    }
    if flags & REQ_FLAG_RANGE != 0 {
        let start = be_u16(data, off)?;
        let end = be_u16(data, off + 2)?;
        off += 4;
        if start >= end || (with_num_iters && end as usize > num_iters) {
            return None;
        }
        req.range = Some((start, end));
    }
    if off != data.len() {
        return None;
    }
    Some(req)
}
