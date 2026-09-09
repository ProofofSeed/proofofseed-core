# Comb table sources, the mirrored scalar, and stored field values

## Table sources

A fixed-base comb's per-window tables are a public function of the base point `G` and are identical on every pass, so they can either be recomputed with native point arithmetic (`ComputedComb`) or read from a precomputed table (`FlashComb`, behind the `flash-comb` feature).
On a secure element the recomputation is the dominant cost and a watchdog hazard, so the device reads them; on a host, recomputing is cheaper than carrying 80 KB of constants.

A table source is not a circuit variant.
Both sources feed the same circuit through `PubKeyCircuit` and its siblings, which are generic over `CombTableSource`.
The device and the host used to carry separate copies of each elliptic-curve circuit body, differing only in this one call, and a copy that is only ever compared against a third copy in a test is a drift waiting to happen.
There is now one body.

The tables are built inside `Circuit::exec`, which takes `&self`, so a source is a zero-sized type with a factory rather than a value held by the circuit.

What the choice of source can still change is the circuit's structure, because the number of entries in a window sets how many gates the constant-time select emits.
A table generated for a comb that stores all multiples has twice the entries of one that stores only the odd ones, and the consumer asserts the length it is handed rather than trusting it.
The reader is sized from the generated layout rather than from a stride computed at the reading site, because how many entries a window holds is a property of the comb the table was generated for, and a reader that assumes it mis-slices silently when that changes.

`circuits/tests/flash_tables.rs` pins both halves: the reconstructed values against the computed ones, and the fingerprint of the flash-sourced circuit against the computed-sourced one.

## The mirrored scalar

The curve circuits used to carry a precomputed table of comb slopes as a circuit input.
The comb now takes the scalar it multiplies by, as an optional host value, and mirrors it internally one window at a time inside `exec`, under whatever backend hook the caller already has.

`Some` when proving or executing, `None` when replaying a view, fingerprinting or profiling; the circuits hold a `mirror_scalar` flag that `new` sets and `shaped` clears.
Nothing key-equivalent is held for the duration of a proof any more, and the arithmetic no longer runs in a constructor outside any hook's reach.

The mirror is a private local holding the recoding residual and the running accumulator: 128 bytes of witness-derived material, erased when the comb returns.
Its stack footprint is 224 bytes, the balance being loop counters and `Option` discriminants.
On a device where a stack shortfall wipes rather than reboots, 224 is the number to budget against and 128 is the number that has to be erased; and a frame-size figure is not a stack-budget figure, because a marginal frame adds to the high-water only if it sits on the deepest call path.

## Stored field values against canonical residues

`zkboo_modular::montgomery::Montgomery<W, N>` wraps a field element's value in the representation its modulus stores it in.
`MontgomeryWord::canonical` returns the canonical residue; `Montgomery::from_raw` and `into_raw` are the escape hatches for reading a word back out of a cleartext pass's output limbs, where nothing but the author knows which form it is in.

Both forms are a `CompositeWord` in `[0, p)`, and under a pseudo-Mersenne modulus — which is what secp256k1 uses here — they are the same word.
Passing one where the other is meant is therefore invisible on secp256k1 and makes every assertion silently false on Ed25519.
There is no error and no panic: the assertion flag simply comes out zero.

The one place in this repository that reconstructs a stored form is `FlashComb`'s table reader, whose limbs came out of `MontgomeryWord::inner` in `gen_comb_table`.
Nothing in the generated file records which form they are, so `from_raw` at that site is load-bearing and its correctness is not observable on this field.
