// SPDX-License-Identifier: LGPL-3.0-or-later

//! Where a fixed-base comb gets its secp256k1 window tables.
//!
//! The comb's per-window tables are a public function of the base point `G` and are
//! identical on every pass, so they can either be recomputed with native point
//! arithmetic ([ComputedComb]) or read from a precomputed table ([FlashComb], behind
//! the `flash-comb` feature). On a secure element the recomputation is the dominant
//! cost and a watchdog hazard, so the device reads them; on a host, recomputing is
//! cheaper than carrying 80 KB of constants.
//!
//! **This is a table source, not a circuit variant.** Both sources feed the *same*
//! circuit through [crate::PubKeyCircuit] and friends, which are generic over
//! [CombTableSource]. That is deliberate: the device and the host used to carry
//! separate copies of each elliptic-curve circuit body, differing only in this one
//! call, and a copy that is only ever compared against a third copy in a test is a
//! drift waiting to happen. There is now one body.
//!
//! What the choice of source *can* still change is the circuit's structure, because
//! the number of entries in a window sets how many gates the constant-time select
//! emits. A table generated for a comb that stores all multiples has twice the
//! entries of one that stores only the odd ones, and the consumer asserts the length
//! it is handed rather than trusting it. `tests/flash_tables.rs` pins both halves:
//! the reconstructed values against the computed ones, and the fingerprint of the
//! flash-sourced circuit against the computed-sourced one.

use zkboo_ecc::weierstrass::{ComputedWindowTables, Curve, WindowTables, DEFAULT_COMB_WINDOW_BITS};
use zkboo_ecc::secp256k1::Secp256k1PM;

/// A source of secp256k1 fixed-base comb window tables.
///
/// The tables are built inside `Circuit::exec`, which takes `&self`, so a source is a
/// zero-sized type with a factory rather than a value held by the circuit.
pub trait CombTableSource {
    /// The reader this source produces.
    type Tables: WindowTables<u64, 4, Secp256k1PM>;
    /// Build a reader. Called once per circuit pass.
    fn make() -> Self::Tables;
}

/// Recompute the tables with native point arithmetic — the host default.
///
/// This reproduces exactly what `zkboo_bip32::public_key` does internally, so a
/// circuit parameterised by this source is structurally identical to the
/// non-parameterised form it replaced.
pub struct ComputedComb;

impl CombTableSource for ComputedComb {
    type Tables = ComputedWindowTables<u64, 4, Secp256k1PM>;
    fn make() -> Self::Tables {
        ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS)
    }
}

#[cfg(feature = "flash-comb")]
mod flash {
    use alloc::vec::Vec;

    use zkboo::word::CompositeWord;
    use zkboo_ecc::weierstrass::WindowTables;
    use zkboo_ecc::secp256k1::{Secp256k1FieldPM, Secp256k1PM};
    use zkboo_modular::montgomery::MontgomeryWord;

    use super::CombTableSource;

    // COMB_TABLE: &[[[u64; 4]; 3]], COMB_WINDOW_OFFSETS: &[usize], COMB_WINDOW_BITS: usize.
    include!("comb_table.rs");

    type Field = Secp256k1FieldPM;
    type Coords = [MontgomeryWord<u64, 4, Field>; 3];

    /// Rebuild one table entry's three Montgomery coordinates from its stored limbs.
    fn reconstruct(limbs: &[[u64; 4]; 3]) -> Coords {
        core::array::from_fn(|c| {
            let bytes: [[u8; 8]; 4] = core::array::from_fn(|i| limbs[c][i].to_le_bytes());
            MontgomeryWord::from_inner(CompositeWord::from_le_bytes(bytes), Secp256k1FieldPM)
        })
    }

    /// A [WindowTables] backed by the precomputed [COMB_TABLE]. Reconstructs each
    /// window's points from stored Montgomery limbs — no field arithmetic — so the
    /// comb does no native point arithmetic at all. One reused buffer holds the
    /// current window.
    pub struct FlashWindowTables {
        buf: Vec<Coords>,
    }

    impl FlashWindowTables {
        pub fn new() -> Self {
            // Sized from the generated layout, not from a stride computed here: how
            // many entries a window holds is a property of the comb the table was
            // generated for, and a reader that assumes it mis-slices silently when
            // that changes.
            let widest = COMB_WINDOW_OFFSETS
                .windows(2)
                .map(|w| w[1] - w[0])
                .max()
                .unwrap_or(0);
            Self { buf: Vec::with_capacity(widest) }
        }
    }

    impl Default for FlashWindowTables {
        fn default() -> Self {
            Self::new()
        }
    }

    impl WindowTables<u64, 4, Secp256k1PM> for FlashWindowTables {
        fn window_bits(&self) -> usize {
            COMB_WINDOW_BITS
        }
        fn window(&mut self, k: usize) -> &[Coords] {
            self.buf.clear();
            for entry in &COMB_TABLE[COMB_WINDOW_OFFSETS[k]..COMB_WINDOW_OFFSETS[k + 1]] {
                self.buf.push(reconstruct(entry));
            }
            &self.buf
        }
    }

    /// Read the tables from the precomputed [COMB_TABLE] — the device source.
    pub struct FlashComb;

    impl CombTableSource for FlashComb {
        type Tables = FlashWindowTables;
        fn make() -> Self::Tables {
            FlashWindowTables::new()
        }
    }

    /// The generated table's layout, exposed so tests can check it against the comb
    /// the circuits actually run: window bits, per-window offsets, total entries.
    pub fn layout() -> (usize, &'static [usize], usize) {
        (COMB_WINDOW_BITS, COMB_WINDOW_OFFSETS, COMB_TABLE.len())
    }

    /// One entry's reconstructed coordinates, for the value-parity test.
    pub fn entry(i: usize) -> Coords {
        reconstruct(&COMB_TABLE[i])
    }
}

#[cfg(feature = "flash-comb")]
pub use flash::{entry, layout, FlashComb, FlashWindowTables};
