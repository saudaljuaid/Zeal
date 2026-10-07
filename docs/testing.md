# Validation

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
deterministic storage-chain recovery. Direct Zig tests exercise the production
storage, handle, and wire core: empty files, EOF, exact limits, overwrite,
contiguous growth, unsupported gaps, unrelated-file preservation, malformed
requests, arithmetic overflow, file/handle/storage exhaustion, owner and
endpoint generations, forged/closed/stale handles, slot reuse, terminal
counter exhaustion, full 128-byte multi-chunk close/reopen readback, and
filesystem/block reset behavior. Two independent deterministic models each
run 4,096 generated operations: one models bytes and lengths, the other owners,
handle slots, serials, closes, and dependency changes.

Seven direct tests for the shared production transport state cover bounded
FIFO inbox preservation, four-attempt enqueue backpressure, no retransmission
after enqueue, lost replies, fresh request identities after timeout, interrupted
requests, dependency rebind, unrelated-traffic receive exhaustion, strict
handle/offset/count reply matching, and terminal identity exhaustion. Storage
rights and revocation also exercise the affected production C IPC and deferred
receive paths under the existing sanitizers. Artifact tests reject malformed
boot sectors, corrupt ELF headers, writable cell segments, and out-of-bounds
images.

## Runtime hierarchy checks

The production creation engine in `kernel/hosting.c` runs through injectable
architecture/copy callbacks under ASan and UBSan. The fixtures use the actual
private-page allocator, broker, queues, waits and Rust policy; there is no
separate test spawn implementation. Tests cover unpublished rollback, every
copy/allocation/frame boundary, parent and ancestor retirement, exact rounded
credits and physical ownership, typed authority, table/counter pressure,
terminal retention, subtree cancellation, sibling FIFO/deadline preservation,
restart/rebind, and slot reuse. Both the Rust tree model and the independent C
orchestration model compare invariants after every generated operation. Seeds,
operation counts and reproducible failing step information are printed in the
complete test transcript. See [hosting policy](hosting-policy.md).

The hosting Zig tests exercise production packet, dispatcher, worker admission,
bootstrap and resource-selection logic. They reject malformed, late and
unsolicited traffic, preserve interleaved replies and deferred parent requests,
bound pending/inbox pressure and retries, and enforce request exhaustion.
Compiled C, Rust and Zig tests verify management structures, field offsets,
alignments, object tags, call numbers and rights.

## Emulator checks

The test runner boots the raw disk under QEMU TCG and validates structured
serial records plus the emulator exit status. It does not accept the
`RESEARCH_PASS` marker alone. It checks manifest acceptance, cell identities,
ABI and entry data, event ordering, endpoint generations, operation rights,
delegation, forbidden-operation denial, revocation, stale-handle rejection,
rebind, resumed verified reads, restart delays, quarantine, and unchanged
application memory. The demo restarts both the RAM block service and the
filesystem while the application remains in its original generation.

Scenario 20 verifies three writable `/note` round trips with the 26-byte
`Zeal writable RAM storage.` payload, across the initial boot, a block restart,
and a filesystem restart. Each round trip checks empty EOF, rejects a gap,
writes four bounded chunks, closes and reopens, and verifies returned bytes.
The oracle joins application requests to filesystem transfer identities,
actual block reads/writes, ordered replies, and application byte-verification
events. It requires both services' participation, matching offsets and counts,
new generation bindings, stale-handle rejection before raw storage access,
a denied write under delegated read authority, and resumed verified progress.
The expected QEMU exit status is required alongside this evidence.

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
idle timer wakes. Storage negative controls remove or counterfeit block writes,
reads, transfer links, verified bytes, offsets, outcomes, handle generations,
stale-handle rejection, recovery, and emulator exit status. Emulator logs and
`results.json` remain available under `build/research/`.

## Dedicated hosting acceptance

Scenarios 21–23 each run twice through `make test`, alongside every existing
fault, standalone, idle and storage-recovery case. Hosting uses a separate
external oracle in `tests/hosting_oracle.py`; the old oracle still requires the
original block/filesystem generation-one-to-two recovery sequence for old
scenarios. Hosting preserves all four root generations at one, and verifies
runtime cells absent from active manifest roots.

The oracle independently reads the emitted manifest, reconstructs logical
instances and ancestor reservations, verifies unique physical-page ownership,
and requires request → reserve → private initialization → publication → actual
ring-3 entry → authenticated IPC delivery → recomputed owner progress. It
checks current-generation rebinding, stale rejection, exact cleanup/refunds,
FIFO and original sleep-deadline preservation, no delayed subtree revival,
leaf restart and slot reuse. It joins `/hello`, `/alpha`, and `/beta` byte
verification to actual filesystem/block traffic before and after cleanup.
The recovery interval is supervisor fault through the first verified RPC after
explicit root-owner rebinding; at least one complete matched storage chunk must
occur inside that interval.

The live-trace negative-control runner removes or counterfeits each essential
creation, execution, generation, authority, budget, cancellation, cleanup,
recovery, reuse, denial, storage and completion element. Complete capability
epoch uniqueness, exact packet reserved fields, nonrunnable retirement phases,
physical page IDs and zeroed private backing are checked independently. Genuine
QEMU exit status is mandatory. Exhausted bounded trace budgets are failures.
Results appear in `build/research/hosting-negative-controls.json`, while hosting
case evidence is included in `build/research/results.json`. Additional hosting
platform cases use `qemu64` with 32 MiB and `max` with 128 MiB. CI retains the
same full target transcript, JSON evidence and default/storage/hosting images
on success and failure.

These tests do not establish real-hardware correctness, DMA containment,
NVMe reset safety, SMP correctness, persistent-data integrity, extended CPU
state preservation, or side-channel isolation.
