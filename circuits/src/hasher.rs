// SPDX-License-Identifier: LGPL-3.0-or-later

//! The proof hash shared by every ProofofSeed prover and verifier.
//!
//! Keccak-256 — Ethereum's `keccak256`, the original Keccak padding byte `0x01` rather than
//! NIST SHA3-256's `0x06`. It fixes the Fiat-Shamir transcript, the view commitments and the
//! pseudo-random generator, so a device, a CLI and a Python package that pick it produce
//! identical proof bytes, and one that picks anything else produces proofs none of the others
//! will verify.
//!
//! `zkboo` defines the [Hasher] trait and ships no concrete hash, leaving the choice to the
//! consumer; this module is where the ecosystem makes it, once.

use core::fmt::{self, Debug};

use tiny_keccak::{Hasher as _, Keccak};
use zeroize::Zeroize;

use zkboo::crypto::Hasher;

/// A [Hasher] backed by Keccak-256, producing 32-byte digests.
pub struct Keccak256Hasher {
    inner: Keccak,
}

impl Debug for Keccak256Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keccak256Hasher")
    }
}

impl Hasher for Keccak256Hasher {
    type Digest = [u8; 32];
    const DIGEST_SIZE: usize = 32;

    fn new() -> Self {
        Self { inner: Keccak::v256() }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize_into(&mut self, out: &mut Self::Digest) {
        // `Keccak::finalize` consumes the sponge; swap in a fresh state so the hasher stays
        // reusable after finalization, as the `Hasher` contract requires.
        let inner = core::mem::replace(&mut self.inner, Keccak::v256());
        inner.finalize(out);
    }
}

impl Zeroize for Keccak256Hasher {
    fn zeroize(&mut self) {
        self.inner = Keccak::v256();
    }
}
