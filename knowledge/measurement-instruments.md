# The host measurement examples, and what each is good for

`host/examples/` holds the off-device instruments.
Every one of them measures a host, and the device is a 32-bit secure element, so what each reading transfers to the device is stated here rather than assumed at the call site.

Run them as `cargo run --release -p proofofseed-host --example <name>`.

## Heap

`device_heap` reports peak prover heap per statement in the device's configuration, for both comb table sources, and at realistic witness lengths for the seed statements.
The flash table source previously lived only inside the app where no host allocator could see it; it is now the same circuit with a different source, so it can be measured here.

`validate_statements` reports the same peak through a tracking global allocator, which is why it is an example and not a test: the counter is process-wide, so tests running in parallel would read each other's allocations.
It also prints the output checks that `circuits/tests/statement_outputs.rs` asserts, and exits non-zero when one mismatches.

`measure_prove_heap` reports peak heap of the streaming master-key prover at increasing response counts, to distinguish a constant per-response budget from growth.

`device_arena` charges a prove against a heap of the device's exact size using the device's exact allocator, `linked_list_allocator` over a fixed array, so that the per-allocation header, the alignment padding and first-fit fragmentation are all visible — none of which a byte-counting allocator can see.

**Read `device_arena` in one direction only.**
The host is 64-bit and the device 32-bit, so a hole header costs 16 B here and 8 B there, and minimum alignment is 8 B here and 4 B there.
This arena is therefore more wasteful than the device's: fitting here proves fitting there, and failing here does not prove failing there.

**`device_arena` is withdrawn as a source of device figures (2026-08-24).**
Its bisection put the minimum served arena for a master-key proof at 19,200 B, while the device runs that proof inside a 13,312 B arena, peaking at 11,747 B with 1,548 B still free.
It demanded more than the device's whole arena for a proof the device serves comfortably.

The tool's documentation used to add that allocation *sizes* are pointer-width independent, on the grounds that the prover holds no `Vec<usize>`.
The device's own measurement falsifies that: the same proof peaks at 11,747 B there against 16,932 B here with the allocation counts agreeing.
The one-way reading above is the only thing this tool ever established.
The device measures its own heap now, through the telemetry instruction driven by `ledger-app/host/bench_matrix.py`.

## Stack

`stack_profile` samples the stack pointer around every backend operation, through both phases the app runs, and reports the deepest excursion below the frame that started the run.
It exists because the device's own probe paints its stack and reads the high-water after a command returns, which cannot happen for a command that never returns — so the one path that matters most, a prover run that kills the device, is the one the device cannot report on.

**Do not infer the device's ordering from it.**
That is what these numbers were originally claimed to be good for, and the device falsified it on 2026-08-23: the table ranks BIP-39 as the shallowest of the three statements, 5.5% below the hardened child, while the device measured it as much the deepest, 19,320 B against a master key's 17,192 B. The ranking inverts.
Host codegen, calling convention and inlining all differ from Thumb-2 on the secure element, and they differ per circuit rather than by a common factor.

What it is still good for is the questions inside one row: whether a statement's depth grows with a parameter, which it does not with the BIP-39 round count either here or on the device, and whether a change to the circuits moved the depth at all.
For any cross-statement comparison, and for any absolute figure, ask the device.

## Size and gate counts

`proof_size` generates the streamed proof for each statement and reports bytes per response, then predicts the device's streaming time.
It predicts the streaming phase only: the byte-silent challenge phase is a further 44% of device work on the curve statements and 30–45% on the others, so a figure here is a floor on the device's total rather than an estimate of it.

The rate to divide by is a property of the statement, not of the device.
Re-measured on 2026-09-09 over 42 verified rows, the rate is flat in witness size, response count and proof size but not in statement: the hash statements run at 3,171–3,367 B/s and the curve statements at 3,527–3,547 B/s, with no overlap.
The single mean that preceded this belonged to neither population, and a projection using it was about 8% optimistic on a curve statement.
The earlier figure of ~1.9 KB/s is retracted outright: its timer spanned the consent prompt, so it measured the operator as much as the device.

`profile_extra` profiles the statements beyond the app's six — the per-chain address bindings and the BIP-39 seed derivation across round counts — with `zkboo-profiling`, whose `response_size` matches the streamed byte count exactly.
`profile_seed_statements` and `profile_slip10` report gate counts, refcount widths, per-response size and the estimated prover working set at the device's refcount width.
`statement_fingerprints` prints the circuit fingerprint of every implemented statement, for the table in `ledger-app/knowledge/benchmarks.md`.

## Watchdog silence

The on-device watchdog keepalive fires on `push_and_msgs`, once per AND gate.
A stretch of circuit with no AND messages emits no keepalive, so if it runs longer than the watchdog window the device reboots.

`and_timeline` measures, off-device, the fraction of one challenge-phase pass that precedes the first AND message and the largest gap between two of them, which locates the keepalive-silent regions.
The secp256k1 fixed-base comb's precompute on the public base point is one: it involves no secret AND gates.

`op_timeline` runs the same pass through a hook that timestamps every backend operation, so a long maximum gap between two operations localises native compute the hook cannot service — the comb building each window's point table with native arithmetic being the case it was written for.

## Generation

`gen_comb_table` writes the secp256k1 fixed-base comb table to `circuits/src/comb_table.rs` as flash-resident constant data, computing the same per-window multiples that `ComputedWindowTables` builds at run time, in Montgomery limbs.
Re-run it if the curve or the default window width changes.

`profile_mem` reports the streaming prover's profiled heap and stack footprint per statement at the device's refcount width.
It is a circuit-profile figure: the reductions it predicted in the 2026-08 optimisation round did not appear on the device, so it ranks statements and sizes nothing.

## Cost of specific decisions

`fingerprint_cost` reports what the fingerprinting pass costs in heap and time as a function of the BIP-39 round count, the one public parameter that scales it.
The two failure modes are told apart by that measurement: heap growing with the round count would make a large fingerprint a memory problem, and hence memory-corruption-class on the device, while a flat heap and growing time makes it a watchdog problem, which is recoverable by feeding the watchdog.

`salt_secrecy_cost` measures what it costs to stop publishing the BIP-39 passphrase, by moving the salt bytes from `alloc` to `input`.
The salt appears only in the message of the first HMAC — the key is the mnemonic, already secret — so the example isolates exactly that one HMAC.
Measuring the whole statement instead would swamp the difference under 2048 rounds of HMAC over secret data.

`multi_response_soak` runs repeated multi-response proofs, each drawing fresh entropy so the challenge differs between trials as it does on the device, catching a panic rather than aborting the run because the panic is the observation.
It was written when a two-response master-key proof on the Flex succeeded about a third of the time and otherwise died with the SDK's panic status word at the same point in each run, with polling, heap and stack all ruled out.
One in three is the number of ZKBoo challenge values, which is what made the prover path worth testing directly: the proofs the command-line tool and the Python package produce come from the same path.
