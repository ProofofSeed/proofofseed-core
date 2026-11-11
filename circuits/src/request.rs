// SPDX-License-Identifier: LGPL-3.0-or-later

//! The proof and exec request wire format, shared by the on-device parser and the
//! host tests. See `knowledge/request-format.md`.

use alloc::vec::Vec;

/// Default BIP-39 PBKDF2 rounds when the host does not specify one.
pub const DEFAULT_BIP39_ROUNDS: usize = 2048;

/// Bounds on the host-requested repetition count.
pub const MIN_ITERS: u16 = 1;
pub const MAX_ITERS: u16 = 512;

/// Flag bits announcing which optional fields follow the request prefix.
pub const REQ_FLAG_PATH: u8 = 1 << 0;
pub const REQ_FLAG_INDEX_CC: u8 = 1 << 1;
pub const REQ_FLAG_BINDING: u8 = 1 << 2;
pub const REQ_FLAG_FAMILY: u8 = 1 << 4;
pub const REQ_FLAG_RANGE: u8 = 1 << 5;

/// The derivation family a request selects.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum Family {
    /// BIP-32 over secp256k1, the default.
    #[default]
    Bip32Secp256k1 = 0,
    /// SLIP-10 over ed25519.
    Slip10Ed25519 = 1,
}

impl Family {
    /// Decodes the wire byte.
    pub fn from_wire(byte: u8) -> Option<Family> {
        match byte {
            0 => Some(Family::Bip32Secp256k1),
            1 => Some(Family::Slip10Ed25519),
            _ => None,
        }
    }
}

/// A proof or exec request.
#[derive(Default)]
pub struct ProofRequest {
    pub num_iters: usize,
    pub rounds: usize,
    pub family: Family,
    pub path: Option<Vec<u32>>,
    pub index: Option<u32>,
    pub chain_code: Option<[u8; 32]>,
    pub binding: Vec<u8>,
    /// The half-open range of response indices to emit, which also selects the
    /// prover's entropy mode.
    pub range: Option<(u16, u16)>,
}

/// Reads a big-endian u16 at an offset, if present.
fn be_u16(data: &[u8], off: usize) -> Option<u16> {
    if data.len() >= off + 2 {
        Some(((data[off] as u16) << 8) | data[off + 1] as u16)
    } else {
        None
    }
}

/// Parses the request data, returning `None` for a malformed buffer.
///
/// A request-anchored proof must never silently fall back to a default on a field the
/// host thought it sent; the layout and the refusal rules are in
/// `knowledge/request-format.md`.
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
