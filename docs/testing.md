# Research validation

Run `make test`. The command uses bounded subprocess timeouts, fails if any
layer fails, preserves emulator serial traces, and writes a machine-readable
summary under `build/research/results.json`. GitHub Actions runs the same
`make test` target and retains logs and the boot image on failure.

## Host checks

Rust tests exercise lifecycle transitions and capability grant, delegation,
attenuation, revocation, ancestry, stale handles, restart reconstruction,
table pressure, slot reuse, and cross-language structure sizes. The lifecycle
policy is also compared with an independent model over 299,593 bounded trace
nodes and 65,536 deterministic adversarial steps. These checks are bounded,
not a proof over all executions.

Production C IPC, allocation, checked-copy, manifest validation, queue
compaction, and cleanup paths run under AddressSanitizer and UndefinedBehavior
Sanitizer. Tests cover exact memory budgets, exhaustion without partial claims,
page reuse, 1,000 cold clears, independent cell backing, readable images,
unwritable images, and guards. Capability tests cover allowed and forbidden
operations, delegation without permission, rights amplification, ancestor
revocation, stale endpoint generations, table pressure, stale slot reuse, and
messages queued before revocation while preserving unrelated queue entries.
The broker test also compares 50,000 deterministic generated queue/capability
operations using seed `0x6d2b79f5` against a separate bounded queue model.

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
recovery, and incorrect emulator exits. Emulator logs and `results.json` remain
available under `build/research/`.

These tests do not establish real-hardware correctness, DMA containment,
NVMe reset safety, SMP correctness, persistent-data integrity, extended CPU
state preservation, or side-channel isolation.
