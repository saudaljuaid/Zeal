# Research validation

Run `make test`. The command uses bounded subprocess timeouts, fails if any
layer fails, preserves emulator serial traces, and writes a machine-readable
summary under `build/research/results.json`. GitHub Actions runs the same
`make test` target and retains the complete test transcript, emulator logs,
results, and the boot image on both success and failure.

## Host checks

Rust tests exercise lifecycle transitions and capability grant, delegation,
attenuation, revocation, ancestry, stale handles, restart reconstruction,
table pressure, slot reuse, and cross-language structure sizes. The lifecycle
policy is also compared with an independent model over 299,593 bounded trace
nodes and 65,536 deterministic adversarial steps. These checks are bounded,
not a proof over all executions.

Production C IPC, finite waits, allocation, checked-copy, manifest validation,
queue compaction, and cleanup paths run under AddressSanitizer and
UndefinedBehaviorSanitizer. Tests cover exact memory budgets, exhaustion without partial claims,
page reuse, 1,000 cold clears, independent cell backing, readable images,
unwritable images, and guards. Capability tests cover allowed and forbidden
operations, delegation without permission, rights amplification, ancestor
revocation, stale endpoint generations, table pressure, stale slot reuse, and
messages queued before revocation while preserving unrelated queue entries.
The broker test also compares 50,000 deterministic generated queue/capability
operations using seed `0x6d2b79f5` against a separate bounded queue model.

Wait tests exercise immediate delivery, zero durations, exact deadline
boundaries, arithmetic overflow, arrivals around wait publication, expiry
versus arrival ordering, queued-message revocation, deferred destination
failures without consuming messages, stale generations, fault/restart
cancellation, unrelated-state preservation, round-robin runnable selection,
and idle followed by later wakeup. Another 50,000 deterministic generated
operations, using seed `0x5a17e39b`, compare production C wait and scheduling
paths with a separate bounded model.

The manifest validator tests header truncation, unsupported versions,
count/size boundaries, every cell and grant field, duplicate identities and
grants, name encoding, image catalogs, entries, lifecycle settings, rights,
and page rounding. Build-compiler tests independently reject malformed source
records and overlarge images. C and Zig emit their ABI layouts for direct
comparison; Rust validates its policy FFI layouts. Zig protocol tests check
message authentication, malformed lengths, backpressure, rebinding, and
deterministic storage-chain recovery. Artifact tests reject malformed boot
sectors, corrupt ELF headers, writable cell segments, and out-of-bounds images.

## Emulator checks

The test runner boots the raw disk under QEMU TCG and validates structured
serial records plus the emulator exit status. It does not accept the
`RESEARCH_PASS` marker alone. It checks manifest acceptance, cell identities,
ABI and entry data, event ordering, endpoint generations, operation rights,
delegation, forbidden-operation denial, revocation, stale-handle rejection,
rebind, resumed verified reads, restart delays, quarantine, and unchanged
application memory. The demo restarts both the RAM block service and the
filesystem while the application remains in its original generation.

Scenario 19 verifies that an empty-queue receiver suspends while another cell
completes a verified file read, then wakes for an application message with the
expected sender and payload. It checks a two-tick receive timeout, a three-tick
sleep, and cancellation of a pending service receive before dependency restart.
A standalone wait probe proves idle entry and later PIT wakeup when its only
cell is waiting. The oracle pairs each traced wait with its original identity,
generation, kind, and deadline, verifies wake reasons and signed results,
rejects early or stale completions, and requires the expected emulator exit.

Fault scenarios cover invalid instructions, supervisor memory writes,
immutable code writes, NX stack execution, interrupt masking, port I/O,
non-cooperating loops, invalid syscall addresses, forged endpoints, null and
guard accesses, disabled x87/SSE instructions, direction-flag preservation,
noncanonical return stacks, disabled SYSCALL/SYSENTER paths, and a trusted
kernel fault. The suite tests CPU models with 32–128 MiB RAM, boot images for
each standalone service/application/probe, no-runnable-cell scheduling,
unsupported CPU failures, and an Intel SYSENTER control. Most scenarios run
twice by default; `RESEARCH_REPEAT` may be set from 1 to 20.

The oracle's unit tests reject marker-only traces, missing boot and recovery
events, forged generations, altered rights, missing app reads, counterfeit
recovery, incorrect emulator exits, missing or counterfeit wakeups, altered
deadlines, early timeout/sleep completion, stale-generation delivery, missing
wait cancellation, counterfeit application progress, and missing or forged
idle timer wakes. Emulator logs and `results.json` remain available under
`build/research/`.

These tests do not establish real-hardware correctness, DMA containment,
NVMe reset safety, SMP correctness, persistent-data integrity, extended CPU
state preservation, or side-channel isolation.
