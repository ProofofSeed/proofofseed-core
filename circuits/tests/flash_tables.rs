// SPDX-License-Identifier: LGPL-3.0-or-later

//! The precomputed comb table, against the comb the circuits actually run.
//!
//! Two independent things can go wrong with a precomputed table, and each has its
//! own test here.
//!
//! **Values.** The table must reconstruct to exactly what `ComputedWindowTables`
//! produces, or the proofs it generates verify against nothing.
//!
//! **Shape.** The number of entries per window sets how many gates the constant-time
//! select emits, so a table generated for a different comb changes the *circuit*, not
//! just its constants. This is not hypothetical: the table once carried
//! pre-optimisation windowing (all multiples, 32 per window) while the comb had moved
//! to storing only the odd ones (16), and every elliptic-curve proof would have
//! panicked on the consumer's length assertion. What made that reachable was a check
//! that lived as a hand-run example, so nobody ran it.
//!
//! Both circuits under test are now the *same* circuit — `PubKeyCircuit<T>` — with
//! the table source swapped, rather than two hand-kept copies of one body. The
//! fingerprint comparison is therefore about the tables alone.

use proofofseed_circuits::comb::{CombTableSource, ComputedComb, FlashComb, entry, layout};
use proofofseed_circuits::{
    AddressCircuit, NormalChildCircuit, PubKeyCircuit, ethereum_address_circuit,
    normal_child_circuit, public_key_circuit,
};
use proofofseed_circuits::hasher::Keccak256Hasher;
use zkboo::circuit::Circuit;
use zkboo_circuit_hash::hash_circuit;
use zkboo_ecc::weierstrass::{ComputedWindowTables, Curve, DEFAULT_COMB_WINDOW_BITS, WindowTables};
use zkboo_ecc::secp256k1::Secp256k1PM;

/// Scalar width in bits (256 = u64 × 4).
const WIDTH: usize = 64 * 4;

fn fingerprint<C: Circuit>(c: &C) -> [u8; 32] {
    hash_circuit::<C, Keccak256Hasher>(c)
}

#[test]
fn the_flash_table_reconstructs_to_the_computed_one() {
    let (bits, offsets, total) = layout();
    assert_eq!(bits, DEFAULT_COMB_WINDOW_BITS, "window width the comb was generated for");
    let mut computed = ComputedWindowTables::new(Secp256k1PM.g(), bits);
    assert_eq!(offsets.len(), WIDTH.div_ceil(bits) + 1, "window count");
    let mut seen = 0usize;
    for k in 0..WIDTH.div_ceil(bits) {
        let base = offsets[k];
        let want = computed.window(k);
        assert_eq!(
            want.len(),
            offsets[k + 1] - base,
            "window {k}: the generated layout must match what the comb asks for",
        );
        for (j, coords) in want.iter().enumerate() {
            let got = entry(base + j);
            for c in 0..3 {
                assert_eq!(*coords[c].inner(), *got[c].inner(), "window {k} entry {j} coord {c}");
            }
            seen += 1;
        }
    }
    assert_eq!(seen, total, "every stored entry belongs to a window");
}

#[test]
fn the_flash_sourced_circuits_fingerprint_as_the_computed_ones() {
    // One body per statement, two table sources. A difference here is the tables.
    assert_eq!(
        fingerprint(&PubKeyCircuit::<FlashComb>::new(public_key_circuit().private_key.clone())),
        fingerprint(&public_key_circuit()),
        "public key",
    );
    assert_eq!(
        fingerprint(&AddressCircuit::<FlashComb>::new(
            ethereum_address_circuit().private_key.clone()
        )),
        fingerprint(&ethereum_address_circuit()),
        "ethereum address",
    );
    let nc = normal_child_circuit();
    assert_eq!(
        fingerprint(&NormalChildCircuit::<FlashComb>::new(
            nc.chain_code.clone(),
            nc.parent_priv.clone(),
            nc.index,
        )),
        fingerprint(&nc),
        "normal child",
    );
}

/// A source whose windows are a different width — the failure the shape test exists
/// for, in the smallest form that produces one.
///
/// One *wider*, not one narrower. The affine comb requires a window width that does not
/// divide the 256-bit scalar (its top window is fail-closed and must be partial), so the
/// obvious `- 1` gives 4, which divides 256 and now panics inside the comb before the
/// fingerprints are ever compared. Six is the nearest width that is both valid and
/// different from the default.
struct WrongWidth;

impl CombTableSource for WrongWidth {
    type Tables = ComputedWindowTables<u64, 4, Secp256k1PM>;
    fn make() -> Self::Tables {
        ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS + 1)
    }
}

#[test]
fn the_fingerprint_comparison_can_go_red() {
    // Without this, the test above would pass just as happily if `hash_circuit` were
    // blind to the window layout — which is exactly the property the shape check
    // depends on. A narrower window means more windows and a different number of
    // select gates, so the fingerprint must move.
    let priv_key = public_key_circuit().private_key.clone();
    assert_ne!(
        fingerprint(&PubKeyCircuit::<WrongWidth>::new(priv_key.clone())),
        fingerprint(&PubKeyCircuit::<ComputedComb>::new(priv_key)),
        "circuit fingerprints must be sensitive to the comb's window layout",
    );
}

/// The historical failure exactly: a table whose windows hold twice as many entries
/// as the comb asks for — what the generated table carried before it was regenerated
/// for the odd-multiples-only comb.
struct DoubledWindows;

/// Wraps the real reader and hands back each window duplicated.
struct Doubling {
    inner: proofofseed_circuits::comb::FlashWindowTables,
    buf: Vec<[zkboo_modular::montgomery::MontgomeryWord<u64, 4, zkboo_ecc::secp256k1::Secp256k1FieldPM>; 3]>,
}

impl WindowTables<u64, 4, Secp256k1PM> for Doubling {
    fn window_bits(&self) -> usize {
        self.inner.window_bits()
    }
    fn window(
        &mut self,
        k: usize,
    ) -> &[[zkboo_modular::montgomery::MontgomeryWord<u64, 4, zkboo_ecc::secp256k1::Secp256k1FieldPM>; 3]]
    {
        self.buf.clear();
        let w = self.inner.window(k);
        self.buf.extend_from_slice(w);
        self.buf.extend_from_slice(w);
        &self.buf
    }
}

impl CombTableSource for DoubledWindows {
    type Tables = Doubling;
    fn make() -> Self::Tables {
        Doubling {
            inner: proofofseed_circuits::comb::FlashWindowTables::new(),
            buf: Vec::new(),
        }
    }
}

#[test]
#[should_panic(expected = "assertion")]
fn a_mis_sized_table_is_refused_rather_than_silently_muxed() {
    // The consumer asserts the length it is handed instead of trusting it, so this
    // panics where a trusting implementation would mux the wrong constant and emit a
    // proof of the wrong statement. Removing that assertion is what would make the
    // shape test above unable to protect anything.
    let _ = fingerprint(&PubKeyCircuit::<DoubledWindows>::new(
        public_key_circuit().private_key.clone(),
    ));
}
