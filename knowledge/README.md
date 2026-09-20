# Knowledge

Design records for the shared proof-of-seed library.

- [`plan.md`](plan.md) — the plan of record: architecture, milestones and their acceptance tests.
- [`assertion-word.md`](assertion-word.md) — the trailing assertion word, `checked_payload`, and why uniform output shape is this suite's discipline.
- [`verifier-circuits.md`](verifier-circuits.md) — what a verifier must know to rebuild a circuit: public parameters, witness shape, the BIP-39 salt, and why a wrong circuit is refused by soundness rather than by structure.
- [`ranged-entropy.md`](ranged-entropy.md) — ranged proving, the deterministic entropy derivation, and the invariant it rests on.
- [`circuit-fingerprints.md`](circuit-fingerprints.md) — what a fingerprint commits to, why it leaks nothing, and the watchdog constraint.
- [`comb-tables.md`](comb-tables.md) — comb table sources, the mirrored scalar, and stored field values against canonical residues.
- [`proof-stream.md`](proof-stream.md) — the wire encoding, what the verifier refuses, size bimodality, and the soundness parameter.
- [`request-format.md`](request-format.md) — the request wire format and its strict parse.
- [`proof-byte-pins.md`](proof-byte-pins.md) — what the golden fixture asserts, and its re-anchoring history.
- [`zkboo-port-record.md`](zkboo-port-record.md) — what each upstream release required here, and what was measured.
- [`dependencies.md`](dependencies.md) — the zkboo crates, the patch table, and the proof hash.
- `host-benchmarks-2026-09-06.txt` — host example output, recorded as taken.
