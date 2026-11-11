// SPDX-License-Identifier: LGPL-3.0-or-later

//! Where a fixed-base comb gets its secp256k1 window tables.
//!
//! A table source is not a circuit variant: both sources feed the same circuit. See
//! `knowledge/comb-tables.md`.

use zkboo_ecc::weierstrass::{ComputedWindowTables, Curve, WindowTables, DEFAULT_COMB_WINDOW_BITS};
use zkboo_ecc::secp256k1::Secp256k1PM;

/// A source of secp256k1 fixed-base comb window tables.
pub trait CombTableSource {
    /// The reader this source produces.
    type Tables: WindowTables<u64, 4, Secp256k1PM>;
    /// Builds a reader, once per circuit pass.
    fn make() -> Self::Tables;
}

/// Recomputes the tables with native point arithmetic.
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
    use zkboo_modular::montgomery::{Montgomery, MontgomeryWord};

    use super::CombTableSource;

    // COMB_TABLE: &[[[u64; 4]; 3]], COMB_WINDOW_OFFSETS: &[usize], COMB_WINDOW_BITS: usize.
    include!("comb_table.rs");

    type Field = Secp256k1FieldPM;
    type Coords = [MontgomeryWord<u64, 4, Field>; 3];

    /// Rebuilds one table entry's three Montgomery coordinates from its stored limbs.
    ///
    /// The limbs are the stored representation, and nothing in the generated file
    /// records that but this line; see `knowledge/comb-tables.md`.
    fn reconstruct(limbs: &[[u64; 4]; 3]) -> Coords {
        core::array::from_fn(|c| {
            let bytes: [[u8; 8]; 4] = core::array::from_fn(|i| limbs[c][i].to_le_bytes());
            let stored = Montgomery::from_raw(CompositeWord::from_le_bytes(bytes));
            MontgomeryWord::from_inner(stored, Secp256k1FieldPM)
        })
    }

    /// A [WindowTables] backed by the precomputed [COMB_TABLE].
    pub struct FlashWindowTables {
        buf: Vec<Coords>,
    }

    impl FlashWindowTables {
        pub fn new() -> Self {
            // Sized from the generated layout, never from a stride computed here:
            // see knowledge/comb-tables.md.
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

    /// Reads the tables from the precomputed [COMB_TABLE].
    pub struct FlashComb;

    impl CombTableSource for FlashComb {
        type Tables = FlashWindowTables;
        fn make() -> Self::Tables {
            FlashWindowTables::new()
        }
    }

    /// The generated table's layout: window bits, per-window offsets, total entries.
    pub fn layout() -> (usize, &'static [usize], usize) {
        (COMB_WINDOW_BITS, COMB_WINDOW_OFFSETS, COMB_TABLE.len())
    }

    /// One entry's reconstructed coordinates.
    pub fn entry(i: usize) -> Coords {
        reconstruct(&COMB_TABLE[i])
    }
}

#[cfg(feature = "flash-comb")]
pub use flash::{entry, layout, FlashComb, FlashWindowTables};
