# Plan of record: the shared proof-of-seed library and the standalone provers

Ratified 2026-08-20 (Stefano).
Goal: a standalone Rust program, installable and runnable on any host, that creates and verifies proofs of seed for software wallets — plus a pip-installable Python package — with **no duplication** of the statement, protocol, or prover/verifier code already serving the Ledger app.
Method: **extraction, not mirroring** — promote the already-shared layers out of `ledger-app` into this library repo, and put thin frontends on them.

## Ratified decisions

- **Topology**: a dedicated library repo (this one, `proofofseed-core/`), consumed by `ledger-app`, the standalone Rust app, and the Python package. Chosen over a workspace-in-rust-app for long-run maintainability and reusability.
- **Naming**: crates are `proofofseed-*`. This repo is a Cargo workspace with `proofofseed-circuits` (the moved `pos-circuits`, `no_std + alloc`) and `proofofseed-host` (the host prover/verifier library split out of `psverify`). The CLI crate is `proofofseed-cli` with binary `proofofseed`; the pip package is `proofofseed`. App repo folders stay as proposed: `rust-app/`, `python-app/` (under `<proofofseed>/`, each its own git repo per project convention).
- **Soundness default: 438 responses (PQ-128), everywhere.** The response count stays a runtime parameter, but every default, example, headline number and document in the new repos uses 438. The classical-128 figure (219, `n_eps(128)` — ratified 2026-08-19 for the SNARK-lifter track only) must not appear in these repos unless explicitly requested.
- **CLI scope**: `prove`, `verify`, `derive` (public outputs for verifier-side pinning), `assemble` (concatenate + verify range files), `profile` (the zkboo-profiling numbers for a statement), and **dry-run planning** (`prove --dry-run` or a `plan` command): proof size, prover/verifier memory, and a time estimate for the exact requested parameters, before any witness is touched.

## Architecture

```
zkboo crates (<zkboo>, upstream author's)      layer 0, unchanged
        ↑
proofofseed-circuits  (this repo)                  layer 1: the statements (both
  no_std+alloc; was ledger-app's pos-circuits        families), request transcript,
        ↑                                            ranged/deterministic entropy,
proofofseed-host      (this repo)                    WitnessMaterial, serialization,
  streaming verifier, host prover                    canonical vectors
  (gen_stream/gen_stream_range), executor-based
  witness derivation, n_eps, device-suite aliases
        ↑
  ┌─────┴──────────────┬─────────────────────┐
ledger-app          rust-app              python-app
  device app +        proofofseed-cli       Maturin/PyO3 package
  thin psverify       (binary:              `proofofseed`
  PyO3 shim +         `proofofseed`)
  APDU driver
```

De-duplication principles:

- **Witness derivation reuses the circuits.** The standalone app derives BIP-39 seeds and walks BIP-32/SLIP-10 trees by executing the *same statement circuits* through zkboo's plain executor (the pattern `psverify`'s tests already use). No third-party wallet crate in the trust path, no second implementation of the derivations, consistency with the proved circuits by construction.
- **The request transcript is the proof identity.** `ProofRequest` (and the ranged deterministic-entropy derivation keyed on it) is shared unchanged; the CLI's arguments map onto the same struct the device parses from APDUs. This is what makes a Ledger and the CLI, holding the same seed, produce byte-identical ranged output — they can co-prove one proof.
- **The device keeps only device code**: NBGL UI, APDU handling, syscall witness derivation, flash comb tables, stack probe, stream keepalive, the APDU Python driver, bench tooling. The Flash-vs-Computed comb-table split already covers the one real device/host divergence.
- **Nothing is mirrored.** Any future feature (new statement, new family, protocol change) lands once, in this repo.

## Milestone 1 — extraction (this repo becomes real)

Move `ledger-app/circuits` here as `proofofseed-circuits` (crate renamed; `pos_circuits::` imports updated mechanically). Split `ledger-app/host/psverify` into `proofofseed-host` here (pure Rust: verifier, harness prover, witness derivation, `n_eps`, suite aliases) and a thin PyO3 shim left in `ledger-app` so all existing device tooling keeps working unchanged. Re-path `ledger-app`'s `[patch.crates-io]` tables.

Amendment (2026-08-20, ratified same day): split into two halves so the library work can proceed while the hardware gate waits. **M1a — stand up the library from a copy** (may run immediately): golden stream fixtures are recorded from the untouched ledger-app source tree first, then the code is copied here, renamed, PyO3-stripped, and brought to a green battery that reproduces those fixtures; the ledger-app tree is not modified at all, and the source commit the copy was taken from is recorded below. **M1a executed 2026-08-20: the copy was taken from ledger-app commit `86a4656` (branch `bitcoin-and-solana-recovery-statements`, clean tree); the golden fixtures in `host/tests/golden_streams.txt` were generated from that untouched tree; every copied file was verified identical to its source modulo the crate rename, lib.rs additionally minus the PyO3 module (which stays in ledger-app), and the two device-coupled comb-table examples were left behind.** **M1b — the consumer switch** (only after the hardware gate and the branch's merge): reconcile any gate-era changes to the copied files (a diff against the recorded source commit), re-path ledger-app to consume this repo, reduce psverify to the PyO3 shim, delete the moved code.

Acceptance (all binary, all off-device — items 1 and 5 gate M1b, the rest gate M1a):

1. The entire existing ledger-app battery is green with **zero test edits** (imports aside), and both app feature sets build. (M1b)
2. **Proof-byte neutrality**: a golden fixture of harness streams (hash statements of both families, an elephant, a ranged partition, both entropy modes) recorded from the pre-copy ledger-app code is reproduced byte-identically by this repo's crates. The extraction must not move a single proof byte — the deterministic-entropy transcript tags, the circuit fingerprints, and `DETERMINISTIC_ENTROPY_VERSION` are all untouched by renaming. (M1a)
3. No public API change beyond the crate rename; no new dependency. (M1a)
4. The number 219 is introduced nowhere. (M1a)
5. The M1b reconciliation diff against the recorded source commit is empty or every difference is deliberately carried over. (M1b)

## Milestone 2 design rulings (2026-08-20, Stefano)

- **Proof file = the raw device-identical stream** (interop-clean), with a **JSON sidecar** (`<file>.json`) carrying the request transcript, range, entropy mode, versions (crates + `DETERMINISTIC_ENTROPY_VERSION`), stream length and Keccak-256. The sidecar is metadata, never load-bearing for soundness.
- **Sidecar secrecy rule** (design consequence, applied conservatively): statements whose public output is itself secret material (master key, hardened/normal child, BIP-39 seed) get only an `output_keccak256` commitment in the sidecar — the verifier supplies the expected output out of band and the commitment cross-checks it; the genuinely public outputs (public key, Ethereum address) are stored plainly.
- **`assemble` is sidecar-driven**: all inputs must share one request transcript and version set; coverage of `[0, N)` is checked (gaps and overlaps refuse); concatenation is verified before the assembled artifact is written.
- **Seed input channels**: interactive hidden prompt (default), `--seed-file` (plus the existing `PROOFOFSEED_SEED_FILE` convention — the env var names a file, never the secret), and piped stdin (refused on a TTY). Never argv, never the secret in an env var. BIP-39 checksum validated against the embedded English wordlist (checksum SHA-256 computed by executing the zkboo-sha2 circuit — no new hash dependency), with an explicit override flag for non-BIP-39 phrases.
- **Argument parsing: clap 4 (derive), pinned** — the Rust security-tooling mainstream (sq, cargo-audit, bdk-cli); the parser is off the secret dataflow by construction.
- Response count: default 438, bounded to the wire format's `[1, 512]` so every CLI request stays device-compatible; `prove --dry-run` plans size/memory before touching a witness, with an optional calibration that times a single response and extrapolates.
- Library additions to `proofofseed-host` in support (additive only; the neutrality fixture keeps gating): a `Write`-backed streaming sink with `gen_stream_to`/`gen_stream_range_to` (proofs larger than RAM stream to disk), and a `derive` module walking BIP-39/BIP-32/SLIP-10 by executing the statement circuits (no wallet crates in the trust path).

## Milestone 2 — rust-app (`proofofseed-cli`)

The standalone prover. Mnemonic via file or interactive prompt only (never argv, never env), optional passphrase; family, statement, path/index, binding, response count (default 438), rounds, `--range`; streamed output to file at constant memory; `derive`, `assemble`, `profile`, and dry-run planning as ratified. Statements newly reachable relative to a stock Ledger: master key and full-rounds BIP-39 (the seed itself is a witness here); elephants at host speed. OS RNG replaces the SE TRNG on the rangeless path; ranged requests use the shared deterministic entropy unchanged.

Acceptance:

1. Published-vector anchors pass through the CLI end to end (the BIP-84/86, SLIP-0010 and wallet-core suites already used by `proofofseed-host` tests), and refusal negatives are red with the named refuser, each with a passing twin.
2. **CLI ≡ harness byte-equality**: in deterministic (ranged) mode, the CLI's stream for a request equals `gen_stream_range`'s output byte for byte.
3. Dry-run numbers match `zkboo-profiling` for every statement.
4. Witness hygiene demonstrated: mnemonic and derived secrets zeroized; no secret ever appears in argv, env, logs, or error output (test the failure paths).
5. Documentation states the threat model plainly: the host holds the raw seed — a categorically higher-stakes witness than the device's derived keys; air-gapped use recommended; no swap/coredump guarantees are claimed that aren't implemented.

## Milestone 3 — python-app (`proofofseed` on pip)

Maturin + PyO3 over `proofofseed-host` (the precedent is psverify's existing binding). Typed, mypy-strict Python API: `prove`, `verify`, `derive`, `assemble`, profiling/planning, progress callbacks; abi3 wheels.

Acceptance:

1. `maturin develop` installs locally; the Python test suite passes under mypy strict + black.
2. **Python ≡ CLI byte-parity**: proofs produced through the Python API equal the CLI's for the same request.
3. The package embeds and reports the exact crate versions it was built from (ranged fleets must pin one build — the `DETERMINISTIC_ENTROPY_VERSION` discipline).

## Milestone 4 — cross-prover interop (hardware, folds into the range-proving acceptance)

A device range and a CLI range of one request (same seed) assemble into one verifying proof. Given milestone 2's byte-equality and the pre-registered device↔host equality step in `ledger-app/docs/range-proving.md`, this is confirmation, not discovery.

## Sequencing and publication

- Extraction starts only **after** the ledger-app hardware gate (multi-chain milestone 4 + range-proving acceptance) and that branch's merge to main: extraction is pure churn to run through a gate, and the gate's baseline should be the tree its milestones were built on.
- **Publication to crates.io / PyPI is blocked on zkboo 0.2.0 reaching crates.io** (the same unblocking event recorded in `ledger-app/docs/dependencies.md`; several zkboo crates are ahead of their remotes or have none). Until then: local installs with `[patch.crates-io]` path overrides and `maturin develop`. Name reservations on crates.io/PyPI are the author's call at that point.

## Deferred to milestone design (not yet decided)

- Exact CLI argument surface and output-file format/naming conventions (including how `assemble` discovers and orders range files, and resumption ergonomics).
- Whether the proof file gets a small self-describing header (request transcript + version pins) vs. staying the raw device-identical stream — a raw stream is what interop needs; a sidecar metadata file may serve both.
- Optional hardening (mlock/madvise, guarded memory) — nice-to-have, must not be claimed until implemented.
- Whether `psverify`'s PyO3 shim eventually re-exports the `proofofseed` package instead of carrying its own binding (convergence, not urgency).
